# 自动填表助手 - 一键执行服务
# 用法：
#   1. pip install ddddocr playwright
#   2. playwright install chromium
#   3. python ocr_server.py
# 默认监听 127.0.0.1:7777
#
# 接口：
#   GET  /health         健康检查
#   POST /ocr            验证码识别  {"image_base64": "..."}
#   POST /run            一键执行  {"config": {...}}  -> {"job_id": "..."}
#   GET  /progress?id=X  查询进度
#   POST /test           同步测试单个流程  {"config": {...}}  -> {"log": [...], "result": "ok/error"}

import sys
import os
import json
import time
import base64
import uuid
import threading
import queue
import socket
import sqlite3
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------- 密码加密（Fernet，对称加密） ----------
# 保护目标：数据库文件被单独偷走时，密码不可见
# 不防：代码 + 数据库一起被偷（密钥在代码里）
# 密钥来源（按优先级）：
#   1. 环境变量 AUTOFILL_DB_KEY（生产用，塞 Sealos 环境变量）
#   2. 固定 fallback（开发用，明文写在代码里，只防 DB 单独泄漏）
try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAS_FERNET = True
except ImportError:
    _HAS_FERNET = False
    InvalidToken = Exception  # 兜底

def _get_fernet():
    """获取 Fernet 实例。如果 cryptography 没装就返 None（降级明文）。"""
    if not _HAS_FERNET:
        return None
    key = os.environ.get("AUTOFILL_DB_KEY", "").strip()
    if not key:
        # fallback 密钥（开发用，生产必须设环境变量）
        # 注意：这个 key 编码了 "dev-only-do-not-use-in-prod" 字符串
        # 如果有人在生产用这个 key，密码用以下 key 解：
        fallback = b'dev-only-do-not-use-in-prod-32bytes!!'  # 占位
        import hashlib
        fallback = base64.urlsafe_b64encode(hashlib.sha256(b"ocr-autofill-dev-fallback-key").digest())
        key = fallback.decode()
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        return None

def _encrypt_password(plaintext: str) -> str:
    """加密密码。Fernet 不可用 → 降级返回明文（用 _ENC_ 前缀标识）"""
    if not plaintext:
        return plaintext
    f = _get_fernet()
    if f is None:
        # 没装 cryptography → 明文存（加前缀方便识别）
        return "PLAIN:" + plaintext
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")

def _decrypt_password(ciphertext: str) -> str:
    """解密密码。Fernet 不可用或非加密数据 → 原样返回"""
    if not ciphertext:
        return ciphertext
    if ciphertext.startswith("PLAIN:"):
        return ciphertext[6:]
    f = _get_fernet()
    if f is None:
        return ciphertext
    try:
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):
        # 解不出来（旧数据格式不对、key 换了）→ 原样返回
        return ciphertext

# ---------- 路径 ----------
# 配置和 HTML 都放在 exe 同目录（开发时就是脚本同目录；打包后是 exe 同目录）
if getattr(sys, 'frozen', False):
    # PyInstaller 打包后：exe 在 APP_DIR；资源（HTML）在 _MEIPASS 临时目录
    APP_DIR = os.path.dirname(sys.executable)
    MEIPASS = getattr(sys, '_MEIPASS', APP_DIR)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    MEIPASS = APP_DIR
CONFIG_FILE = os.path.join(APP_DIR, "autofill_config.json")
# 数据目录：环境变量 AUTOFILL_DATA_DIR 优先（容器部署时指向挂载的 volume，
# 避免 db 写进镜像/容器内、重启/重新部署就丢）。未设时回退到脚本同目录。
_DATA_DIR = os.environ.get("AUTOFILL_DATA_DIR", APP_DIR)
os.makedirs(_DATA_DIR, exist_ok=True)
DB_FILE = os.path.join(_DATA_DIR, "autofill.db")

# ---------- SQLite 数据库 ----------
def _init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_account TEXT UNIQUE NOT NULL,
        game_password TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS cdks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        used INTEGER DEFAULT 0,
        once INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )""")
    # 兼容旧库：补 once 字段
    try:
        c.execute("ALTER TABLE cdks ADD COLUMN once INTEGER DEFAULT 0")
    except Exception:
        pass
    conn.commit()
    conn.close()

def db_get_accounts(include_password=False):
    """
    获取账号列表。密码在数据库中是加密存的，读取时自动解密。
    include_password=False (默认): 只返回账号名（用于前端展示/CLI 列表）
    include_password=True: 返回账号+明文密码（用于程序内部自动登录用）
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, game_account, game_password FROM accounts ORDER BY id")
    rows = c.fetchall()
    conn.close()
    if include_password:
        return [{"id": r[0], "username": r[1], "password": _decrypt_password(r[2])} for r in rows]
    else:
        return [{"id": r[0], "username": r[1]} for r in rows]

def db_upsert_account(game_account, game_password):
    """按 game_account 去重：存在+密码不同→更新，存在+相同→跳过，不存在→新增
    密码在写入前加密存储（Fernet）。"""
    encrypted = _encrypt_password(game_password)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT game_password FROM accounts WHERE game_account = ?", (game_account,))
    row = c.fetchone()
    if row:
        # 旧库可能是明文存的（PLAIN: 前缀或裸字符串），跟新存的密文比较
        if row[0] == encrypted:
            conn.close()
            return "skip"
        c.execute("UPDATE accounts SET game_password = ? WHERE game_account = ?", (encrypted, game_account))
        conn.commit()
        conn.close()
        return "update"
    c.execute("INSERT INTO accounts (game_account, game_password) VALUES (?, ?)", (game_account, encrypted))
    conn.commit()
    conn.close()
    return "insert"

def db_delete_account(aid):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM accounts WHERE id = ?", (aid,))
    conn.commit()
    conn.close()

def db_get_cdks():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, code, used, once FROM cdks ORDER BY id")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "code": r[1], "used": bool(r[2]), "once": bool(r[3])} for r in rows]

def db_add_cdk(code, once=0):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO cdks (code, once) VALUES (?, ?)", (code, once))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def db_delete_cdk(cid):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM cdks WHERE id = ?", (cid,))
    conn.commit()
    conn.close()

def db_delete_cdk_by_code(code):
    """按 code 删（CLI 用）"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM cdks WHERE code = ?", (code,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted

def db_delete_once_cdks():
    """删所有一次性 CDK（跑完一轮后调）"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM cdks WHERE once = 1")
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted

def db_reset_cdk(code):
    """重置某 CDK 为未用（每日 CDK 想重跑时）"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE cdks SET used = 0 WHERE code = ?", (code,))
    updated = c.rowcount
    conn.commit()
    conn.close()
    return updated

def db_mark_cdk_used(code):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE cdks SET used = 1 WHERE code = ?", (code,))
    conn.commit()
    conn.close()

# 容器化部署（如 Sealos/Docker）支持：启动时从环境变量读 config 写回本地文件
# 用法：docker run -e AUTOFILL_CONFIG_JSON='{"accounts":[...]}' ...
def _load_config_from_env():
    raw = os.environ.get("AUTOFILL_CONFIG_JSON", "").strip()
    if not raw:
        return False
    try:
        cfg = json.loads(raw)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"[boot] 从环境变量 AUTOFILL_CONFIG_JSON 写入 config（{len(raw)} 字符）", flush=True)
        # 同步到 LAST_CONFIG（定时任务用）
        global LAST_CONFIG
        LAST_CONFIG = cfg
        return True
    except Exception as e:
        print(f"[boot] 解析 AUTOFILL_CONFIG_JSON 失败: {e}", flush=True)
        return False
_load_config_from_env()
# HTML 优先从同目录找（开发模式 或 用户自己放），找不到再从 _MEIPASS 找（打包内置）
PANEL_HTML_CANDIDATES = [
    os.path.join(APP_DIR, "autofill-panel.html"),
    os.path.join(MEIPASS, "autofill-panel.html"),
]
def get_panel_html_path():
    for p in PANEL_HTML_CANDIDATES:
        if os.path.exists(p): return p
    return PANEL_HTML_CANDIDATES[0]  # 不存在也返回第一个，_serve_panel 会处理

# ---------- OCR ----------
ocr = None
try:
    import ddddocr
    # beta=True 启用新模型，对部分复杂验证码识别率更高
    ocr = ddddocr.DdddOcr(show_ad=False, beta=True)
except ImportError:
    print("[WARN] ddddocr 未安装，OCR 不可用")
    print("       pip install ddddocr")

# ---------- Playwright ----------
playwright = None
sync_playwright = None
try:
    from playwright.sync_api import sync_playwright as _sp
    sync_playwright = _sp
    playwright = _sp  # 标记为可用
except ImportError:
    print("[WARN] playwright 未安装，一键执行不可用")
    print("       pip install playwright")

# ---------- 任务管理 ----------
# JOBS[jid] = {
#   "status": "running|done|error",
#   "log": [{"time":..., "msg":..., "level":...}, ...],
#   "result": "...",
#   "updatedConfig": {...},   # 一次性 CDK 标记 used 后的回写
#   "cond": threading.Condition(),
#   "last_index": 0,          # SSE 客户端已读到的日志序号
#   "subscribers": int,       # 当前 SSE 订阅数
# }
JOBS = {}
JOBS_LOCK = threading.Lock()
# 简单过期清理：30 分钟前完成的 job 删掉
JOB_TTL = 30 * 60

# ---------- 验证码识别优化（ABCDF 方案） ----------
# 验证码字符长度（按你的网站，4-5 位字母数字）
CAPTCHA_MIN_LEN = 4
CAPTCHA_MAX_LEN = 5
# 错误关键词：只重试"验证码错误"这类，不要被"已使用/上限"业务错误触发
CAPTCHA_RETRY_KEYWORDS = ["验证码错误", "验证码不正确", "请重新输入验证码", "wrong captcha", "captcha error", "invalid captcha"]
# 账密错误关键词：出现即判定账密错，不入库，不进下一轮
# 注意：不含"登录失败"（登录失败可能是验证码/网络等其他原因）
WRONG_PWD_KEYWORDS = ["账号或密码错误", "密码错误", "密码不正确", "账号不存在", "账号未注册", "用户不存在", "请检查账号和密码"]
# 重试控制：错了刷图重 OCR，最多 3 次
MAX_CAPTCHA_RETRY = 3
# 验证码上下文：OCR 时设置，click 时检查并清空
captcha_ctx = {
    "active": False,        # 当前是否有等待检查的 captcha
    "image_sel": "",        # 验证码图片选择器
    "input_sel": "",        # 验证码输入框选择器
    "attempts": 0,          # 已重试次数
    "last_result": None,    # "success" / "failure" / "wrong_pwd" / None —— 给外层轮次循环判断用
}

def preprocess_captcha_image(img_bytes):
    """B. 二值化预处理：转灰度 + 阈值去噪。需要 Pillow，没有就返回 None。"""
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(img_bytes)).convert("L")
        img = img.point(lambda x: 255 if x > 128 else 0)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return None  # PIL 没装就不预处理

def is_valid_captcha_text(text):
    """F. 长度+字符校验：4-5 位字母数字"""
    if not text:
        return False
    if len(text) < CAPTCHA_MIN_LEN or len(text) > CAPTCHA_MAX_LEN:
        return False
    return all(c.isalnum() for c in text)

def do_ocr_once(img_bytes, emit=None):
    """单次 OCR 识别（带 try/except 保护）"""
    try:
        b64 = base64.b64encode(img_bytes).decode()
        text = ocr.classification(b64).strip()
        return text
    except Exception as e:
        if emit:
            emit(f"  [OCR] 识别失败: {e}", "warn")
        return None

def is_captcha_error_text(page_text):
    """判断页面文字是否含验证码错误（不是"已使用/上限"这类业务错误）"""
    text_lower = page_text.lower()
    for kw in CAPTCHA_RETRY_KEYWORDS:
        if kw.lower() in text_lower:
            return True
    return False

def is_wrong_pwd_text(page_text):
    """判断页面文字是否含"账号密码错误"（账密错）。
    命中：直接判定账密错，不入库，不进下一轮重试。"""
    for kw in WRONG_PWD_KEYWORDS:
        if kw in page_text:
            return kw
    return None

def refresh_captcha_image(page, image_sel, emit):
    """点击验证码图本身换新图（D. 智能延时：换图后等 800ms）
    加了 src 变化检测：有些网站 click 后 src 不变，OCR 截的还是旧图"""
    # 先关掉可能挡住验证码图的错误弹窗（Bootstrap modal）
    close_captcha_modal(page, emit)
    # 记录 click 前的 src，用于判断是否真的换图
    try:
        prev_src = page.eval_on_selector(image_sel, "el => el.getAttribute('src') || ''") or ""
    except Exception:
        prev_src = ""
    # 第一次点击换图
    try:
        page.click(image_sel)
    except Exception as e:
        if emit:
            emit(f"  ⚠ 刷新验证码图失败: {e}", "warn")
        return False
    # 等 src 变化：先 1.5s（正常情况），超时延 1s 再等 2s（用户要求"没刷新出来延长一秒"）
    try:
        page.wait_for_function(
            "([sel, prev]) => { const el = document.querySelector(sel); "
            "if (!el) return false; const cur = el.getAttribute('src') || ''; "
            "return cur !== prev; }",
            arg=[image_sel, prev_src],
            timeout=1500,
        )
    except Exception:
        # 1.5s 内 src 未变——延 1s 再等
        time.sleep(1.0)
        try:
            page.wait_for_function(
                "([sel, prev]) => { const el = document.querySelector(sel); "
                "if (!el) return false; const cur = el.getAttribute('src') || ''; "
                "return cur !== prev; }",
                arg=[image_sel, prev_src],
                timeout=2000,
            )
        except Exception:
            # 延 1s 后还是没变——再点一次兜底
            if emit:
                emit(f"  [换图] 延 1s 后 src 仍未变化，再点一次")
            try:
                page.click(image_sel)
                time.sleep(0.5)
            except Exception as e:
                if emit:
                    emit(f"  ⚠ 重试点击换图失败: {e}", "warn")
                return False
    # 等新图加载（D）
    time.sleep(0.5)
    # 显式等 naturalWidth > 0（多一层保险）
    try:
        page.wait_for_function(
            "sel => { const el = document.querySelector(sel); return el && el.complete && el.naturalWidth > 0; }",
            arg=image_sel,
            timeout=5000,
        )
    except Exception:
        pass
    return True

def close_captcha_modal(page, emit):
    """关闭挡住验证码的错误弹窗（Bootstrap 风格 modal）
    关键：必须走 Bootstrap 正常关闭流程（模拟点击 close button），不能直接 m.remove()
    原因：m.remove() 跳过 Bootstrap 内部状态机，会破坏网站后续操作（人工 modal 走正常流程就没事）
    backdrop 单独清理（不影响 Bootstrap 状态）"""
    try:
        result = page.evaluate("""() => {
            let clickedClose = 0;
            // 1. 优先模拟点击 Bootstrap close button —— 走正常关闭流程，状态机正确流转
            const closeBtn = document.querySelector(
                '.modal.show .close, .modal.show [data-dismiss="modal"], .modal.show [data-bs-dismiss="modal"]'
            );
            if (closeBtn) {
                closeBtn.click();
                clickedClose = 1;
            } else {
                // 2. 没找到 close button 才用 remove 兜底（很少见）
                document.querySelectorAll('.modal.show').forEach(m => m.remove());
            }
            // 3. backdrop 单独清理（不管 .show 状态）—— 残留的 z-index:1050 会拦截点击
            let backdropCount = 0;
            document.querySelectorAll('.modal-backdrop').forEach(m => { m.remove(); backdropCount++; });
            // 4. body 锁
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
            return { clicked: clickedClose, backdrop: backdropCount };
        }""")
        if result and (result.get("clicked") or result.get("backdrop")):
            msg = []
            if result.get("clicked"):
                msg.append("模拟点击 close button")
            if result.get("backdrop"):
                msg.append(f"清 backdrop × {result['backdrop']}")
            if emit:
                emit(f"  [重试] 关闭弹窗（{', '.join(msg)}）")
            time.sleep(0.3)  # 让 Bootstrap 完成 fade-out 动画
    except Exception as e:
        if emit:
            emit(f"  ⚠ 关弹窗异常: {e}", "warn")

def ocr_with_preprocess_and_pick_best(page, image_sel, emit):
    """C. 多结果选最优：原图 + 二值化各 OCR 一次，挑 4-5 位字母数字
    返回 (text, method)，没合适就返回第一个结果（标记为 suspect）
    验证码图加载：3 次循环（5s 等）→ 不行就点击换图 → 再 3 次循环——实在不行才放弃"""
    # 等图片加载（关键：超时不能静默吞——否则截图到空白/损坏图会 OCR 出乱码）
    loaded = False
    total_waits = 0  # 累计 wait 次数，超过 3 次就点图换
    click_retry = 0  # 已点图换的次数
    MAX_CLICK_RETRY = 3  # 最多点图换 3 次
    while total_waits < 3 and click_retry <= MAX_CLICK_RETRY:
        try:
            page.wait_for_function(
                "sel => { const el = document.querySelector(sel); return el && el.complete && el.naturalWidth > 0; }",
                arg=image_sel,
                timeout=5000,
            )
            loaded = True
            break
        except Exception as e:
            total_waits += 1
            if total_waits < 3:
                emit(f"  ⚠ 验证码图未加载完成（naturalWidth=0），延 1s 再等（第 {total_waits}/3 次）", "warn")
                time.sleep(1.0)
            else:
                # 3 次 wait 都未加载——点击验证图刷新
                if click_retry < MAX_CLICK_RETRY:
                    click_retry += 1
                    emit(f"  ⚠ 验证码图 3 次 wait 未加载，点击图刷新（第 {click_retry}/{MAX_CLICK_RETRY} 次）", "warn")
                    try:
                        page.click(image_sel)
                    except Exception as ce:
                        emit(f"  ✗ 点击图刷新失败: {ce}", "error")
                        break
                    # 等 1-2.5s（先 1.5s，不行延 1s 再等 1s）
                    time.sleep(1.5)
                    total_waits = 0  # 重置 wait 计数，开始下一轮 3 次
                else:
                    emit(f"  ✗ 验证码图点击刷新 {MAX_CLICK_RETRY} 次仍未加载，放弃本次 OCR: {type(e).__name__}", "error")
    if not loaded:
        return None, None
    # 截图
    try:
        img_bytes = page.locator(image_sel).screenshot()
    except Exception as e:
        emit(f"  ✗ 截验证码失败: {e}", "error")
        return None, None
    # 两个候选
    candidates = []  # [(text, method)]
    text_orig = do_ocr_once(img_bytes)
    if text_orig is not None:
        candidates.append((text_orig, "原图"))
    bin_bytes = preprocess_captcha_image(img_bytes)
    if bin_bytes is not None:
        text_bin = do_ocr_once(bin_bytes)
        if text_bin is not None:
            candidates.append((text_bin, "二值化"))
    if not candidates:
        emit("  ✗ OCR 全部失败", "error")
        return None, None
    # 选最优（4-5 位字母数字）
    good = [(t, m) for t, m in candidates if is_valid_captcha_text(t)]
    if good:
        text, method = good[0]
        emit(f"  ✓ OCR 识别 ({method}): {text}")
        return text, method
    # 没有 4-5 位的——按用户要求：刷图重试，最多 3 次
    text_bad, method_bad = candidates[0]
    emit(f"  ⚠ OCR 识别 ({method_bad}) 长度异常: {text_bad}（期望 {CAPTCHA_MIN_LEN}-{CAPTCHA_MAX_LEN} 位），刷图重试", "warn")
    for retry_n in range(1, 4):  # 3 次刷图重试
        if not refresh_captcha_image(page, image_sel, emit):
            continue
        # 截图重 OCR
        try:
            img_bytes2 = page.locator(image_sel).screenshot()
        except Exception as e:
            emit(f"  ✗ 截验证码失败: {e}", "error")
            continue
        cands2 = []
        t_orig2 = do_ocr_once(img_bytes2)
        if t_orig2 is not None:
            cands2.append((t_orig2, "原图"))
        bin2 = preprocess_captcha_image(img_bytes2)
        if bin2 is not None:
            t_bin2 = do_ocr_once(bin2)
            if t_bin2 is not None:
                cands2.append((t_bin2, "二值化"))
        if not cands2:
            continue
        good2 = [(t, m) for t, m in cands2 if is_valid_captcha_text(t)]
        if good2:
            text, method = good2[0]
            emit(f"  ✓ OCR 识别 ({method}): {text}（刷图 {retry_n} 次后成功）")
            return text, method
        text_bad, method_bad = cands2[0]
        emit(f"  ⚠ 第 {retry_n} 次刷图后仍异常: {text_bad}（期望 {CAPTCHA_MIN_LEN}-{CAPTCHA_MAX_LEN} 位）", "warn")
    # 3 次都失败 —— 放弃本次，不让外层瞎填
    emit(f"  ✗ OCR 多次刷图后仍异常（{text_bad}），放弃本次", "error")
    return None, "invalid"

def retry_captcha_after_click(page, submit_selector, emit):
    """A. 重试机制：点完 submit 之后，如果检测到验证码错误，就刷图 + 重 OCR + 重填 + 重 submit
    最多 MAX_CAPTCHA_RETRY 次
    在 captcha_ctx["last_result"] 写 "success" / "failure" / "wrong_pwd"，给外层轮次循环用"""
    if not captcha_ctx["active"]:
        return
    # 等弹窗出现
    time.sleep(1.5)
    # 抓页面文字
    try:
        page_text = page.evaluate("() => document.body.innerText || ''") or ""
    except Exception:
        page_text = ""
    # 优先级 0：账密错误（出现就判定，不再试验证码）—— 用户要求：账密错不入库，不进下一轮
    wrong_pwd_kw = is_wrong_pwd_text(page_text)
    if wrong_pwd_kw:
        emit(f"  ✗ 检测到账密错误（关键词「{wrong_pwd_kw}」），停止重试，不入库、不进下一轮", "error")
        captcha_ctx["active"] = False
        captcha_ctx["last_result"] = "wrong_pwd"
        return
    # 优先级 1：含成功关键词（"上限"/"领取成功"/"失败:0"）→ 已成功，不再试错
    # 单独解析"失败: N 个"——N=0 视为成功；N>=1 视为业务失败（验证码已通过，不进下一轮）
    for m in _FAIL_COUNT_RE.finditer(page_text):
        n = int(m.group(1))
        if n == 0:
            emit(f"  ✓ 失败计数 0：验证码验证成功（页面含「{m.group(0)}」）")
            captcha_ctx["active"] = False
            captcha_ctx["last_result"] = "success"
            time.sleep(2.5)
            return
        # N>=1 → 业务失败，验证码已通过，不进下一轮（用户要求"业务失败不算验证码失败"）
        emit(f"  ⚠ 页面提示含「{m.group(0)}」：业务失败，验证码已通过，不再试错", "warn")
        captcha_ctx["active"] = False
        captcha_ctx["last_result"] = "success"
        time.sleep(2.5)
        return
    for kw in _SUCCESS_KEYWORDS:
        if kw in page_text:
            emit(f"  ✓ 检测到成功关键词「{kw}」，验证码验证成功，不再试错")
            captcha_ctx["active"] = False
            captcha_ctx["last_result"] = "success"
            time.sleep(2.5)
            return
    # 优先级 2：判断是否验证码错误：innerText 关键词 + body 是否有 modal-open（双保险）
    if not is_captcha_error_text(page_text) and not _has_error_modal(page):
        # 不是验证码错误（可能是业务错误如"已使用"），仅记日志不重试
        captcha_ctx["active"] = False
        captcha_ctx["last_result"] = "success"
        # A. 验证码成功后，强制等 2.5s 让页面跳转/稳定（解决 claim 页 #giftServer 偶发超时）
        time.sleep(2.5)
        return
    # 重试循环
    while captcha_ctx["attempts"] < MAX_CAPTCHA_RETRY:
        captcha_ctx["attempts"] += 1
        emit(f"  ⚠ 检测到验证码错误，重试 ({captcha_ctx['attempts']}/{MAX_CAPTCHA_RETRY})")
        # 刷图
        if not refresh_captcha_image(page, captcha_ctx["image_sel"], emit):
            continue
        # 重 OCR
        new_text, new_method = ocr_with_preprocess_and_pick_best(page, captcha_ctx["image_sel"], emit)
        if not new_text:
            continue
        # 重填
        if captcha_ctx["input_sel"]:
            try:
                page.fill(captcha_ctx["input_sel"], new_text)
            except Exception as e:
                emit(f"  ⚠ 重试填验证码失败: {e}", "warn")
                continue
        # 重 submit
        try:
            page.click(submit_selector)
        except Exception as e:
            emit(f"  ⚠ 重试点提交失败: {e}", "warn")
            continue
        # 等弹窗 + 检查
        time.sleep(1.5)
        try:
            new_text_check = page.evaluate("() => document.body.innerText || ''") or ""
        except Exception:
            new_text_check = ""
        # 优先级 1：含成功关键词 → 已成功，不再试错
        # "失败: N 个"——N=0 视为成功；N>=1 视为业务失败（验证码已通过，不进下一轮）
        for m in _FAIL_COUNT_RE.finditer(new_text_check):
            n = int(m.group(1))
            if n == 0:
                emit(f"  ✓ 失败计数 0：验证码验证成功（页面含「{m.group(0)}」）")
                captcha_ctx["active"] = False
                captcha_ctx["last_result"] = "success"
                time.sleep(2.5)
                return
            # N>=1 → 业务失败，验证码已通过，不再试错
            emit(f"  ⚠ 页面提示含「{m.group(0)}」：业务失败，验证码已通过，不再试错", "warn")
            captcha_ctx["active"] = False
            captcha_ctx["last_result"] = "success"
            time.sleep(2.5)
            return
        for kw in _SUCCESS_KEYWORDS:
            if kw in new_text_check:
                emit(f"  ✓ 检测到成功关键词「{kw}」: 验证码验证成功，不再试错")
                captcha_ctx["active"] = False
                captcha_ctx["last_result"] = "success"
                time.sleep(2.5)
                return
        # 优先级 2：关键检查：页面真的跳走了吗？看 captcha 输入框是否还可见
        # 如果还可见 → 第二次 submit 没生效，强制当成失败继续重试
        try:
            input_still_visible = page.locator(captcha_ctx["input_sel"]).is_visible(timeout=1500)
        except Exception:
            input_still_visible = False  # 找不到元素 = 跳走了 = 当成成功
        # 加强：除了 input 可见 + innerText，还要看是否真有错误弹窗（modal-open）
        if input_still_visible and not is_captcha_error_text(new_text_check) and not _has_error_modal(page):
            # 还在登录页 + 没有错误提示 = submit 被无视
            emit(f"  ⚠ 提交后页面无变化（captcha 输入框仍可见），不当作成功")
            continue
        if not is_captcha_error_text(new_text_check) and not _has_error_modal(page):
            emit(f"  ✓ 重试成功: {new_text}")
            captcha_ctx["active"] = False
            captcha_ctx["last_result"] = "success"
            # A. 重试成功后也等 2.5s 让页面跳转/稳定
            time.sleep(2.5)
            return
    emit("  ✗ 验证码重试次数用尽", "error")
    captcha_ctx["active"] = False
    captcha_ctx["last_result"] = "failure"


def _has_error_modal(page):
    """检查页面是否有错误弹窗（Bootstrap 风格）
    通过 body.modal-open class + .modal.show 元素判断——close modal 会被移除，
    新弹窗出现时会重新加上。抓住"弹窗刚出现但 innerText 还没渲染"的真空期"""
    try:
        return page.evaluate("""() => {
            if (document.body.classList.contains('modal-open')) return true;
            return !!document.querySelector('.modal.show, .modal[style*="display: block"]');
        }""")
    except Exception:
        return False

# ---------- 配置持久化 ----------
# 配置文件就放在 exe 同目录：autofill_config.json
# 主要存一次性 CDK 的 used 状态 + 多设备共享的配置
def load_persisted_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[WARN] 读配置文件失败: {e}")
    return {}

def save_persisted_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[WARN] 写配置文件失败: {e}")
        return False

def merge_used_flags(new_cfg):
    """把持久化里的一次性 CDK used 状态合并到新 config"""
    old = load_persisted_config()
    old_cdks = old.get("cdkList", []) or []
    new_cdks = new_cfg.get("cdkList", []) or []
    old_map = {c.get("value"): c for c in old_cdks if c.get("value")}
    for nc in new_cdks:
        v = nc.get("value")
        if v and v in old_map and old_map[v].get("used"):
            nc["used"] = True
    return new_cfg

def persist_used_flags(cfg):
    """任务跑完后，把 cdks 里 used=true 的写回配置文件"""
    cdks = cfg.get("cdkList", []) or []
    if not cdks:
        return
    used_only = [c for c in cdks if c.get("used")]
    if not used_only:
        return
    old = load_persisted_config()
    old_cdks = old.get("cdkList", []) or []
    old_map = {c.get("value"): c for c in old_cdks if c.get("value")}
    for c in used_only:
        old_map[c["value"]] = c
    old["cdkList"] = list(old_map.values())
    save_persisted_config(old)


# ---------- 点选器（独立 Picker 浏览器，非 headless） ----------
PICKER_LOCK = threading.Lock()
PICKER_STATE = {
    "running": False,        # 是否有点选浏览器在跑
    "browser": None,         # sync_playwright 浏览器实例
    "playwright": None,      # sync_playwright 上下文
    "page": None,            # 当前页
    "context": None,         # browser context
    "pending": None,         # 当前正在填的位置 {actionIdx, field}
    "cond": threading.Condition(PICKER_LOCK),  # 选完通知前端用
    "last_result": None,     # 最近一次选中的 selector + 目标位置
    "start_event": threading.Event(),  # picker 启动完成（成功/失败）时 set，让 /picker/start 同步返回
}

# 浏览器内 JS：把数据塞 window.__afPickBuffer，后端 100ms 轮询拉
# 极简：无顶层守门（每次 nav 都重跑），boot 内部按 DOM 元素防重
PICKER_INJECT_JS = r"""
(function() {
  function send(action, extra) {
    try {
      window.__afPickBuffer = window.__afPickBuffer || [];
      window.__afPickBuffer.push(Object.assign({ action: action }, extra || {}));
    } catch (e) {}
  }

  function boot() {
    if (document.getElementById('__afPickerBar')) return;  // 已初始化过

    // 等 body
    if (!document.body) { setTimeout(boot, 30); return; }

    try {
      const box = document.createElement('div');
      box.id = '__afPickerBox';
      box.style.cssText = 'position:fixed;pointer-events:none;border:2px solid #ff5722;background:rgba(255,87,34,0.12);z-index:2147483647;transition:all 80ms ease;display:none;border-radius:2px';
      document.body.appendChild(box);

      const tip = document.createElement('div');
      tip.id = '__afPickerTip';
      tip.style.cssText = 'position:fixed;pointer-events:none;background:#1976d2;color:#fff;padding:4px 8px;border-radius:3px;font:12px monospace;z-index:2147483647;display:none;box-shadow:0 2px 6px rgba(0,0,0,0.3);max-width:600px;word-break:break-all';
      document.body.appendChild(tip);

      const bar = document.createElement('div');
      bar.id = '__afPickerBar';
      bar.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#1976d2;color:#fff;padding:8px 12px;font:14px sans-serif;z-index:2147483647;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,0.2)';
      bar.innerHTML = '🎯 <b>点选模式</b> · 鼠标移到元素上看选择器，点击即选中 · 按 <b>ESC</b> 退出';
      document.body.appendChild(bar);
      document.body.style.paddingTop = '40px';

      let lastEl = null;
      function highlight(el) {
        try {
          if (el === lastEl) return;
          if (lastEl) { lastEl.style.outline = ''; lastEl.style.outlineOffset = ''; }
          if (el && el !== document.body && el !== document.documentElement) {
            el.style.outline = '2px solid #ff5722';
            el.style.outlineOffset = '1px';
          }
          lastEl = el;
        } catch (e) {}
      }

      function getSelector(el) {
        try {
          if (!el || el.nodeType !== 1) return '';
          if (el === document.body) return 'body';
          if (el.id && /^[a-zA-Z][\w-]*$/.test(el.id)) return '#' + el.id;
          const parts = [];
          let cur = el;
          let depth = 0;
          while (cur && cur.nodeType === 1 && cur !== document.body && depth < 8) {
            let part = cur.tagName.toLowerCase();
            const cls = (typeof cur.className === 'string') ? cur.className.trim() : '';
            if (cls) {
              const tokens = cls.split(/\s+/).filter(c => c && !/^(ng-|v-|is-|js-|form-control|form-select|input-)/.test(c));
              if (tokens.length) part += '.' + tokens[0];
            }
            const parent = cur.parentElement;
            if (parent) {
              const sibs = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
              if (sibs.length > 1) {
                const idx = sibs.indexOf(cur) + 1;
                part += `:nth-of-type(${idx})`;
              }
            }
            parts.unshift(part);
            cur = cur.parentElement;
            depth++;
          }
          return parts.join(' > ');
        } catch (e) { return ''; }
      }

      document.addEventListener('mousemove', (e) => {
        try {
          const el = e.target;
          if (!el || el === box || el === tip || el === bar) return;
          const r = el.getBoundingClientRect();
          box.style.left = r.left + 'px';
          box.style.top = r.top + 'px';
          box.style.width = r.width + 'px';
          box.style.height = r.height + 'px';
          box.style.display = 'block';
          const sel = getSelector(el);
          tip.textContent = sel.length > 80 ? sel.slice(0, 80) + '…' : sel;
          tip.style.left = (r.left + 4) + 'px';
          tip.style.top = (r.bottom + 4) + 'px';
          tip.style.display = 'block';
          highlight(el);
        } catch (err) {}
      }, true);

      document.addEventListener('click', (e) => {
        try {
          const el = e.target;
          if (!el || el === box || el === tip || el === bar) return;
          e.preventDefault();
          e.stopPropagation();
          if (e.stopImmediatePropagation) e.stopImmediatePropagation();
          const sel = getSelector(el);
          try { box.style.background = 'rgba(76,175,80,0.25)'; box.style.borderColor = '#4caf50'; } catch (e) {}
          try { bar.innerHTML = '✓ 已选中 ' + (sel.length > 60 ? sel.slice(0,60)+'…' : sel) + ' · 等待后端...'; } catch (e) {}
          // 优先用 expose_function 直接调 Python（无竞态，结果+关浏览器原子完成）
          if (typeof window.__afPickSelect === 'function') {
            try {
              window.__afPickSelect(sel, el.tagName, location.href);
              return;  // 已调 expose，不再入 buffer，避免双处理
            } catch (e) {
              // expose 调用失败（如 Playwright 内部异常），fallback 到 buffer
              send('select', { sel: sel, tag: el.tagName, url: location.href });
            }
          } else {
            // 没暴露（兜底路径），走 buffer
            send('select', { sel: sel, tag: el.tagName, url: location.href });
          }
        } catch (err) {}
      }, true);

      document.addEventListener('keydown', (e) => {
        try {
          if (e.key === 'Escape') {
            e.preventDefault();
            try { bar.innerHTML = '↩ 已退出'; } catch (e) {}
            // 优先 expose，fallback buffer
            if (typeof window.__afPickStop === 'function') {
              try { window.__afPickStop(); return; } catch (e) {}
            }
            send('stop');
          }
        } catch (err) {}
      }, true);

      send('ready', { exposeOk: typeof window.__afPickSelect === 'function' });
    } catch (err) {
      send('err', { msg: String(err && err.message || err) });
    }
  }

  // 入口
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
"""


# 启动一个常驻 picker 线程（所有 page 操作只能在这一个线程里）
PICKER_COMMAND_QUEUE = queue.Queue()  # HTTP handler 投递命令
PICKER_RESULT_QUEUE = queue.Queue()  # picker 线程投递结果（可选，目前主要靠 PICKER_STATE）

def _picker_loop():
    """常驻线程：处理 start/stop 命令 + 100ms 轮询 page.evaluate 拉数据"""
    import time as _t
    while True:
        # 1) 处理命令（非阻塞）
        try:
            while True:
                cmd = PICKER_COMMAND_QUEUE.get_nowait()
                action = cmd.get("action")
                if action == "start":
                    _open_picker(cmd["url"], cmd["action_idx"], cmd["field"])
                elif action == "stop":
                    _close_picker()
        except queue.Empty:
            pass

        # 2) 轮询拉数据（如果 picker 在跑）
        with PICKER_STATE["cond"]:
            running = PICKER_STATE.get("running")
            page = PICKER_STATE.get("page")
        if running and page:
            try:
                data = page.evaluate("() => { const r = window.__afPickBuffer || []; window.__afPickBuffer = []; return r; }")
                for item in (data or []):
                    act = item.get("action")
                    if act == "ready":
                        print(f"[PICKER] 浏览器就绪 (expose_function: {item.get('exposeOk')})", flush=True)
                    elif act == "select":
                        on_pick_select(item.get("sel", ""), item.get("tag", ""), item.get("url", ""))
                    elif act == "stop":
                        on_pick_stop()
                    elif act == "err":
                        print(f"[PICKER] 浏览器 JS 错误: {item.get('msg')}", flush=True)
            except Exception as e:
                print(f"[PICKER] poll err: {e}", flush=True)
            _t.sleep(0.1)
        else:
            _t.sleep(0.05)

STEALTH_INIT = r"""
// 反检测：抹掉 Playwright/headless 标志，让 Cloudflare 以为是正常浏览器
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
delete navigator.__proto__.webdriver;
window.navigator.chrome = { runtime: {}, csi: function(){}, loadTimes: function(){} };
window.navigator.languages = ['zh-CN', 'zh', 'en'];
Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
const _origQuery = window.navigator.permissions && window.navigator.permissions.query;
if (_origQuery) {
    window.navigator.permissions.query = (p) => p.name === 'notifications' ? Promise.resolve({state: Notification.permission}) : _origQuery(p);
}
"""


def _open_picker(url, action_idx, field):
    """在 picker 线程内启 Playwright 浏览器"""
    # 新一轮：清掉 start_event，确保 start_picker 同步等的是这一轮
    PICKER_STATE["start_event"].clear()
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            channel="msedge",
            headless=False,
            args=["--no-sandbox", "--disable-blink-features=AutomationControlled", "--disable-features=IsolateOrigins,site-per-process"],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
        )
        page = context.new_page()
        # 关键：用 expose_function 让 JS 点击直接调 Python（原子操作，避开 buffer 100ms 轮询竞态）
        # 注意：这两个回调会在 Playwright 内部线程跑，**只**做线程安全的事（cond 锁、queue.put），
        #       **绝不**调 page.close/goto 等 sync Playwright API（那些留给 picker 线程的 _close_picker）
        page.expose_function("__afPickSelect", _js_pick_callback)
        page.expose_function("__afPickStop", _js_stop_callback)
        # 反检测必须在 picker 注入之前（picker 用 webdriver 检测会受影响）
        page.add_init_script(STEALTH_INIT)
        page.add_init_script(PICKER_INJECT_JS)
        # goto 失败重试 1 次（ERR_ABORTED 常见）
        last_err = None
        for attempt in range(2):
            try:
                page.goto(url, timeout=20000, wait_until="load")
                last_err = None
                break
            except Exception as e:
                last_err = e
                print(f"[PICKER] goto 第 {attempt+1} 次失败: {e}", flush=True)
                if attempt == 0:
                    import time as _t
                    _t.sleep(1.0)
        if last_err:
            raise last_err
        with PICKER_STATE["cond"]:
            PICKER_STATE["playwright"] = pw
            PICKER_STATE["browser"] = browser
            PICKER_STATE["context"] = context
            PICKER_STATE["page"] = page
            PICKER_STATE["running"] = True
            PICKER_STATE["cond"].notify_all()
        # 通知 /picker/start 同步等待的 HTTP 线程：启动成功
        PICKER_STATE["start_event"].set()
        print(f"[PICKER] 启动：{url} actionIdx={action_idx} field={field}", flush=True)
    except Exception as e:
        print(f"[PICKER] 启动失败：{e}", flush=True)
        with PICKER_STATE["cond"]:
            # 关键：不改 running（保护旧 picker 状态，避免被本次失败误覆盖为 False
            # 导致前端误判"已关闭"，但实际浏览器还在跑）
            PICKER_STATE["last_result"] = {"error": str(e)}
            PICKER_STATE["cond"].notify_all()
        # 失败也要 set，让 start_picker 同步等的结果出来
        PICKER_STATE["start_event"].set()

def _close_picker():
    """在 picker 线程内关 Playwright（不要清 last_result，保留 on_pick_select 设的真实 selector）"""
    with PICKER_STATE["cond"]:
        PICKER_STATE["running"] = False
        page = PICKER_STATE.get("page")
        browser = PICKER_STATE.get("browser")
        context = PICKER_STATE.get("context")
        pw = PICKER_STATE.get("playwright")
    try:
        # 还原 picker 注入的 padding（如果还在当前页）
        try:
            if page:
                page.evaluate("() => { try { document.body.style.paddingTop = ''; } catch(e){} }")
        except Exception:
            pass
        if page: page.close()
    except Exception: pass
    try:
        if context: context.close()
    except Exception: pass
    try:
        if browser: browser.close()
    except Exception: pass
    try:
        if pw: pw.stop()
    except Exception: pass
    with PICKER_STATE["cond"]:
        PICKER_STATE["page"] = None
        PICKER_STATE["browser"] = None
        PICKER_STATE["context"] = None
        PICKER_STATE["playwright"] = None
        PICKER_STATE["cond"].notify_all()
    print("[PICKER] 已停止", flush=True)

# 启动 picker 常驻线程（在 server 启动时）
PICKER_THREAD = None

def ensure_picker_thread():
    global PICKER_THREAD
    if PICKER_THREAD is None or not PICKER_THREAD.is_alive():
        PICKER_THREAD = threading.Thread(target=_picker_loop, daemon=True)
        PICKER_THREAD.start()
        print("[PICKER] 常驻线程已启动", flush=True)


def on_pick_select(selector, tag, page_url):
    """点选器 JS 选完元素后的回调（由 picker 线程在 polling 时调，buffer 兜底路径）"""
    with PICKER_STATE["cond"]:
        pending = PICKER_STATE.get("pending") or {}
        result = {
            "actionIdx": pending.get("actionIdx", ""),
            "field": pending.get("field", ""),
            "page": pending.get("page", ""),
            "selector": selector,
            "tag": tag,
            "url": page_url,
        }
        PICKER_STATE["last_result"] = result
        # 关键：存一份 snapshot，防止并发 wait 抢到清空的 last_result 时还能拿到
        PICKER_STATE["last_result_snapshot"] = result
        PICKER_STATE["cond"].notify_all()
    print(f"[PICKER] 选中: {selector} ({tag}) | actionIdx={result['actionIdx']} field={result['field']}", flush=True)
    # 投递 stop 命令给 picker 线程关浏览器
    PICKER_COMMAND_QUEUE.put({"action": "stop"})


def _js_pick_callback(selector, tag, page_url):
    """通过 page.expose_function 让 JS 直接调用的选中回调（主路径，无竞态）

    ⚠️ 此函数在 Playwright 内部线程跑，**只**做线程安全的事：
       - cond 锁内的状态写入
       - queue.put 投递 stop 命令（实际关浏览器留给 picker 线程的 _close_picker）
       - print 日志
       **绝不**调 page.close / page.goto 等 sync Playwright API，否则跨线程会死锁/报错
    """
    try:
        with PICKER_STATE["cond"]:
            pending = PICKER_STATE.get("pending") or {}
            result = {
                "actionIdx": pending.get("actionIdx", ""),
                "field": pending.get("field", ""),
                "page": pending.get("page", ""),
                "selector": selector,
                "tag": tag,
                "url": page_url,
            }
            PICKER_STATE["last_result"] = result
            PICKER_STATE["last_result_snapshot"] = result
            PICKER_STATE["cond"].notify_all()
        print(f"[PICKER] ✓ JS 直接回调选中: {selector} ({tag}) | actionIdx={result['actionIdx']} field={result['field']}", flush=True)
        # 投递 stop 给 picker 线程，由它统一调 _close_picker 关浏览器
        PICKER_COMMAND_QUEUE.put({"action": "stop"})
    except Exception as e:
        print(f"[PICKER] _js_pick_callback 异常: {e}", flush=True)


def _js_stop_callback():
    """通过 page.expose_function 让 JS 直接调用的 ESC 回调（主路径）

    同上：只 queue.put，不调 Playwright API。
    """
    try:
        print("[PICKER] JS 直接回调 ESC 退出", flush=True)
        PICKER_COMMAND_QUEUE.put({"action": "stop"})
    except Exception as e:
        print(f"[PICKER] _js_stop_callback 异常: {e}", flush=True)


def on_pick_stop():
    """点选器 JS 按 ESC 时的回调（由 picker 线程在 polling 时调，buffer 兜底路径）"""
    print("[PICKER] 用户按 ESC 退出", flush=True)
    PICKER_COMMAND_QUEUE.put({"action": "stop"})


def start_picker(action_idx, field, page_name, url, callback_url=None):
    """启动点选浏览器：投递 start 命令给 picker 线程 + 同步等启动结果"""
    ensure_picker_thread()

    # 关键修复：如果旧 picker 在跑，先 stop 掉（避免新 _open_picker 启动时
    # sync_playwright 资源冲突；同时避免失败时误改 running 覆盖旧 picker 状态）
    with PICKER_STATE["cond"]:
        if PICKER_STATE.get("running"):
            PICKER_COMMAND_QUEUE.put({"action": "stop"})
            # 等旧 picker 关完（最多 5s：关 page/browser 通常 1-2s）
            PICKER_STATE["cond"].wait_for(
                lambda: not PICKER_STATE.get("running"),
                timeout=5
            )

    # 重置 event，等本轮启动完成
    PICKER_STATE["start_event"].clear()
    with PICKER_STATE["cond"]:
        PICKER_STATE["pending"] = {"actionIdx": action_idx, "field": field, "page": page_name}
        PICKER_STATE["last_result"] = None
        PICKER_STATE["last_result_snapshot"] = None  # 清掉上次的 snapshot

    if not sync_playwright:
        return {"ok": False, "error": "playwright 未安装"}

    PICKER_COMMAND_QUEUE.put({"action": "start", "url": url, "action_idx": action_idx, "field": field})

    # 同步等启动结果：成功（running=True）or 失败（last_result.error）
    # 25s 足够 Playwright 启动 + Cloudflare 校验 + goto
    if not PICKER_STATE["start_event"].wait(timeout=25):
        return {"ok": False, "error": "点选窗口启动超时（25s）"}

    with PICKER_STATE["cond"]:
        # 优先看本次启动的错误（即使旧 picker 还在跑，新启动失败也要报出来）
        last = PICKER_STATE.get("last_result") or {}
        if last.get("error"):
            return {"ok": False, "error": last["error"]}
        if not PICKER_STATE.get("running"):
            return {"ok": False, "error": "启动失败"}

    return {"ok": True, "msg": "点选窗口启动中..."}


def stop_picker():
    """投递 stop 命令给 picker 线程关浏览器"""
    PICKER_COMMAND_QUEUE.put({"action": "stop"})
    return {"ok": True}

# ---------- 获取本机局域网 IP（手机访问用） ----------
def get_lan_ip():
    """通过连一下外网 IP 拿到本机出口 IP（不开真发包）"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))  # 阿里 DNS，连一下不真发数据
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# 调度判断：今天是否该执行某个 CDK
def cdk_active_today(cdk):
    if cdk.get("used") and cdk.get("schedule") == "once":
        return False
    schedule = cdk.get("schedule", "daily")
    start = cdk.get("startDate", "")
    if not start:
        return schedule != "once"  # 无起始日期的 daily/weekly/monthly 都跑
    try:
        from datetime import date
        s = date.fromisoformat(start)
        t = date.today()
        diff = (t - s).days
        if diff < 0:
            return False
        if schedule == "daily":
            return True
        if schedule == "weekly":
            return diff % 7 == 0
        if schedule == "monthly":
            return diff % 30 == 0
        if schedule == "once":
            return not cdk.get("used", False)
    except Exception:
        return True
    return False


# ---------- 检查页面错误提示 ----------
# 抓 HTML 模态框 / 错误文字（JS 原生弹窗由 page.on("dialog") 抓）
# 成功关键词：任一命中 → 视为成功（如"领取成功" / "领取次数已达上限"）
_SUCCESS_KEYWORDS = ["上限", "领取成功"]
# 错误关键词：任一命中 → 视为失败
_ERROR_KEYWORDS = ["错误", "失败", "无效", "已使用", "已兑换", "失效", "限兑", "校验码", "captcha", "incorrect"]
# 注意：成功关键词里"上限"必须在错误关键词列表中**排除**——因为含"上限"是成功
# B. "失败: N 个" 这种格式的解析正则
import re as _re
_FAIL_COUNT_RE = _re.compile(r"失败[::\s]*([0-9]+)\s*个")

def _check_page_error(page, emit):
    """点击后等 2.5s，扫页面找成功/失败关键词
    返回 (status, detail)：
      status: "success" / "failure" / "unknown"
      detail: 命中的具体内容（用于日志）
    """
    try:
        time.sleep(2.5)
        # 只查可见文字（documentElement.innerText），不查 HTML 源码——
        # 否则验证码图片 src="/index/captcha" 这种会被误判
        text = page.evaluate("document.documentElement ? (document.documentElement.innerText || '') : ''")
        if not text or not text.strip():
            emit("  [check] 页面文字为空（可能跳转中/页面被关闭）", "info")
            return ("unknown", "页面文字为空")
        # 1. 解析"失败: N 个"——N=0 视为成功，N>0 视为失败（用户指定逻辑）
        for m in _FAIL_COUNT_RE.finditer(text):
            n = int(m.group(1))
            if n == 0:
                emit(f"  ✓ 失败计数 0：本次提交成功（页面文字含「{m.group(0)}」）")
                return ("success", m.group(0))
            else:
                emit(f"  ⚠ 页面提示含「失败: {n} 个」：{n} 个失败（≥1）", "warn")
                return ("failure", m.group(0))
        # 2. 找成功关键词
        for kw in _SUCCESS_KEYWORDS:
            if kw in text:
                lines = [l.strip() for l in text.split("\n") if kw in l and l.strip()]
                snippet = " | ".join(lines[:3]) if lines else kw
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."
                emit(f"  ✓ 页面提示含成功关键词「{kw}」: {snippet}")
                return ("success", snippet)
        # 3. 找错误关键词
        for kw in _ERROR_KEYWORDS:
            if kw in text:
                lines = [l.strip() for l in text.split("\n") if kw in l and l.strip()]
                snippet = " | ".join(lines[:3]) if lines else kw
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."
                emit(f"  ⚠ 页面提示含错误关键词「{kw}」: {snippet}", "warn")
                return ("failure", snippet)
        # 4. 都没命中 —— 按用户要求"否则视为失败"
        snippet = text.strip().replace("\n", " | ")[:200]
        emit(f"  ⚠ 页面提示未命中任何关键词，按否则视为失败处理: {snippet}", "warn")
        return ("failure", "未命中关键词")
    except Exception as e:
        # 不再静默：把异常告诉用户，方便排查
        try:
            emit(f"  [check] 错误检查异常: {type(e).__name__}: {e}", "warn")
        except Exception:
            pass
        return ("unknown", f"异常: {e}")


# ---------- 执行单个操作 ----------
def do_op(page, op, account, cdk, emit):
    # 前端存的字段叫 "type"，但历史代码读 "action"——同时认两个，type 优先
    action = op.get("type") or op.get("action", "fill")
    # 前端叫 "captcha"，后端历史叫 "ocr"——映射一下
    if action == "captcha":
        action = "ocr"
    selector = op.get("selector", "").strip()
    value = op.get("value", "")
    input_selector = op.get("inputSelector", "").strip()
    capture_group = op.get("captureGroup", "1")

    # 解析 value 中的变量
    value = resolve_value(value, account, cdk, page)

    if not selector:
        return

    if action == "fill":
        page.wait_for_selector(selector, timeout=10000)
        page.fill(selector, value)
        emit(f"  ✓ 填: {selector} = {value[:30]}{'...' if len(value)>30 else ''}")

    elif action == "click":
        page.wait_for_selector(selector, timeout=10000)
        page.click(selector)
        emit(f"  ✓ 点击: {selector}")
        # A. 如果是 captcha 后的 click，自动检查验证码错误并重试（最多 3 次）
        if captcha_ctx["active"]:
            retry_captcha_after_click(page, selector, emit)
        # 通用错误检查（已使用/上限等业务错误，已被排除在 captcha 重试外）
        _check_page_error(page, emit)

    elif action == "select":
        page.wait_for_selector(selector, timeout=10000)
        sel = selector
        val = value.strip()
        # 选项经常是异步加载的（点 #getRoleList 之后要 3-5s 才出真选项），
        # 等最多 10s 直到出现"真"选项（>1 个，因为占位符占 1 个）
        try:
            # 等下拉框 options 加载：先 1.5s（绝大多数情况够用），比之前 10s 节省 8.5s
            page.wait_for_function(
                "sel => { const el = document.querySelector(sel); return el && el.options && el.options.length > 1; }",
                arg=sel,
                timeout=1500,
            )
        except Exception:
            # 1.5s 还没好 —— 延长 1s 再试（最多再等 2s，总计 3.5s，比之前 10s 仍快很多）
            time.sleep(1.0)
            try:
                page.wait_for_function(
                    "sel => { const el = document.querySelector(sel); return el && el.options && el.options.length > 1; }",
                    arg=sel,
                    timeout=2000,
                )
            except Exception:
                # 真没好就用现在的 options 继续（可能真的只有 0~1 个）
                pass
        opts = page.eval_on_selector(sel, "el => Array.from(el.options).map(o => ({v: o.value, t: o.textContent}))")
        chosen = None
        if val.startswith("#"):
            idx = int(val[1:]) - 1
            if 0 <= idx < len(opts):
                chosen = opts[idx]["v"]
        elif val.isdigit():
            idx = int(val) - 1
            if 0 <= idx < len(opts):
                chosen = opts[idx]["v"]
        else:
            for o in opts:
                if val in o["t"] or val in o["v"]:
                    chosen = o["v"]
                    break
        if chosen is not None:
            page.select_option(sel, chosen)
            emit(f"  ✓ 下拉: {sel} -> {chosen}（{len(opts)} 个选项）")
        else:
            # 把所有可选值列出来，方便用户对照自己的 value 写错了什么
            sample = " | ".join([f"[{o['v']}]{o['t']}" for o in opts[:8]])
            more = f" ...（共 {len(opts)} 个）" if len(opts) > 8 else ""
            emit(f"  ✗ 下拉: 没找到 {val}。可选: {sample}{more}", "warn")

    elif action == "ocr":
        if not ocr:
            emit("  ✗ OCR 未安装", "error")
            return
        # 注意：前端"图片选择器"存到 selector，"输入框"存到 inputSelector
        if not selector:
            emit("  ✗ OCR 缺验证码图片选择器", "error")
            return
        # 调试日志：打印图片元素状态（方便排查「截到 alt 文字」类问题）
        try:
            info = page.evaluate("""(sel) => {
                const el = document.querySelector(sel);
                if (!el) return {found: false, selector: sel};
                return {
                    found: true,
                    tag: el.tagName,
                    src: (el.getAttribute('src') || '').slice(0, 80),
                    alt: el.getAttribute('alt') || '',
                    complete: !!el.complete,
                    naturalWidth: el.naturalWidth || 0,
                    offsetW: el.offsetWidth,
                    offsetH: el.offsetHeight,
                };
            }""", selector)
            emit(f"  [OCR-debug] {json.dumps(info, ensure_ascii=False)}")
        except Exception:
            pass
        # 调 OCR（自动应用 B/C/F：原图 + 二值化，挑 4-5 位字母数字）
        result, method = ocr_with_preprocess_and_pick_best(page, selector, emit)
        if not result:
            return
        # 填到验证码框
        if input_selector:
            try:
                page.fill(input_selector, result)
                emit(f"  ✓ 填验证码: {input_selector} = {result}")
            except Exception as e:
                emit(f"  ✗ 填验证码失败: {e}", "error")
                return
        else:
            emit("  ⚠ 未配置验证码输入框，跳过填入", "warn")
        # 设置 captcha_ctx，让紧随其后的 click 自动检查 + 重试
        captcha_ctx["active"] = True
        captcha_ctx["image_sel"] = selector
        captcha_ctx["input_sel"] = input_selector
        captcha_ctx["attempts"] = 0

    elif action == "wait":
        ms = int(value) if value.isdigit() else 1000
        time.sleep(ms / 1000)
        emit(f"  ✓ 等待 {ms}ms")

    elif action == "waitForUrl":
        page.wait_for_url(value, timeout=15000)
        emit(f"  ✓ 跳转到: {value}")

    elif action == "waitForSelector":
        page.wait_for_selector(value, timeout=15000)
        emit(f"  ✓ 元素出现: {value}")


def resolve_value(value, account, cdk, page):
    if not isinstance(value, str):
        return value
    # 字段映射：前端用什么字段名 → 真实值
    # 之前只有"整字符串等于"才替换，且字段名跟前端不一致
    repls = {}
    if account:
        repls["{username}"] = str(account.get("username", ""))   # 前端用 {username}
        repls["{account}"] = str(account.get("username", ""))    # 旧名字也兼容
        repls["{password}"] = str(account.get("password", ""))
    if cdk:
        repls["{cdk}"] = str(cdk.get("value", "") or cdk.get("code", ""))  # 前端存的是 value，兼容历史 code
    if "{date}" in value:
        from datetime import date
        repls["{date}"] = date.today().isoformat()
    # 子串替换（不是只整字符串等于）
    for k, v in repls.items():
        value = value.replace(k, v)
    return value


def _check_pause(job_id, emit):
    """暂停检查：暂停时阻塞，恢复后继续；首次进入暂停态时 emit 一次"""
    paused_logged = [False]  # 用 list 包，让嵌套函数能改
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
    while True:
        with JOBS_LOCK:
            if not JOBS.get(job_id):
                return  # 任务被外部移除
            if job.get("cancel_requested"):
                return  # 取消优先级最高
            if not job.get("paused"):
                if paused_logged[0]:
                    emit("▶ 继续执行")
                    paused_logged[0] = False
                return
            # 暂停中
            if not paused_logged[0]:
                emit("⏸ 已暂停（点继续恢复）")
                paused_logged[0] = True
        time.sleep(0.3)


class _JobCancelled(Exception):
    """任务被用户取消时抛出的内部异常"""
    pass


def _check_cancel(job_id, emit):
    """取消检查：被取消时抛异常让上层 try/except 收"""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job and job.get("cancel_requested"):
        emit("⏹ 已取消任务", "warn")
        raise _JobCancelled()


# ---------- 执行任务 ----------
# 保存最近一次 /run 收到的 config（用于定时任务——复用最后一次的 config）
LAST_CONFIG = {}
# 今天的日期 + 是否已触发（避免一天触发多次）
LAST_SCHEDULE_DAY = ""
LAST_SCHEDULE_TRIGGERED = False

def run_job(job_id, config):
    JOBS[job_id] = {
        "status": "running",
        "log": [],
        "result": None,
        "started": time.time(),
        "cond": threading.Condition(),   # SSE 推送用：emit 时 notify
        "last_index": 0,                # SSE 客户端已读到的日志序号
        "subscribers": 0,               # 当前 SSE 订阅数
        "updatedConfig": None,
        "paused": False,                # /pause 设 True，/resume 设 False
        "cancel_requested": False,      # /cancel 设 True，主循环检查后跳出
        "trigger": "manual",            # "manual" / "schedule"
    }
    log_q = queue.Queue()

    def emit(msg, level="info"):
        item = {"time": time.time(), "msg": msg, "level": level}
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job: return
            job["log"].append(item)
        print(f"[{job_id[:8]}] {msg}", flush=True)
        # 唤醒 SSE 等待的客户端
        with job["cond"]:
            job["cond"].notify_all()

    def th():
        try:
            _run_job_impl(job_id, config, emit)
        except Exception as e:
            import traceback
            emit(f"✗ 异常: {e}", "error")
            emit(traceback.format_exc(), "error")
            JOBS[job_id]["status"] = "error"

    threading.Thread(target=th, daemon=True).start()


def _scheduler_loop():
    """定时任务守护线程：每 30s 检查一次，到点触发一键执行
    时间配置从 LAST_CONFIG["schedule"]["time"] 读，默认 "00:05"
    触发条件：当前时间 HH:MM == 设定时间 + 今天没触发过 + 没任务在跑"""
    global LAST_SCHEDULE_DAY, LAST_SCHEDULE_TRIGGERED
    while True:
        try:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            hhmm = now.strftime("%H:%M")
            # 跨天重置
            if today != LAST_SCHEDULE_DAY:
                LAST_SCHEDULE_DAY = today
                LAST_SCHEDULE_TRIGGERED = False
            # 读时间配置
            sched = LAST_CONFIG.get("schedule", {}) if LAST_CONFIG else {}
            if not sched.get("enabled", True):
                time.sleep(30)
                continue
            target_time = sched.get("time", "00:05")
            # 到点 + 今天没触发过 + 没任务在跑
            if hhmm == target_time and not LAST_SCHEDULE_TRIGGERED:
                with JOBS_LOCK:
                    has_running = any(j.get("status") == "running" for j in JOBS.values())
                if has_running:
                    # 有任务在跑（手动触发的）→ 跳过本次定时
                    print(f"[scheduler] {hhmm} 到点但有任务在跑，跳过本次定时", flush=True)
                    # 不标 triggered，明天还能触发
                else:
                    LAST_SCHEDULE_TRIGGERED = True
                    print(f"[scheduler] ⏰ 触发定时任务: {target_time}", flush=True)
                    jid = uuid.uuid4().hex
                    JOBS[jid] = {
                        "status": "running",
                        "log": [],
                        "result": None,
                        "started": time.time(),
                        "cond": threading.Condition(),
                        "last_index": 0,
                        "subscribers": 0,
                        "updatedConfig": None,
                        "paused": False,
                        "cancel_requested": False,
                        "trigger": "schedule",
                    }
                    cfg_to_run = json.loads(json.dumps(LAST_CONFIG)) if LAST_CONFIG else {}
                    cfg_to_run.pop("schedule", None)  # 调度信息不传给执行逻辑
                    # 定时任务从数据库读所有账号 + 全局 CDK（不依赖前端 config）
                    # 区分 once / daily：每日 CDK 只能 used=0 的才跑；一次性 CDK 不论 used 都跑
                    cfg_to_run["accounts"] = db_get_accounts(include_password=True)
                    cfg_to_run["cdkList"] = []
                    for c in db_get_cdks():
                        if c["once"]:
                            cfg_to_run["cdkList"].append({"code": c["code"], "schedule": "once", "used": False, "_db_id": c["id"]})
                        else:
                            if not c["used"]:
                                cfg_to_run["cdkList"].append({"code": c["code"], "schedule": "daily", "used": False, "_db_id": c["id"]})
                    # 单独启动线程跑这个 job
                    def _sched_th():
                        try:
                            def _emit(msg, level="info"):
                                item = {"time": time.time(), "msg": msg, "level": level}
                                with JOBS_LOCK:
                                    job = JOBS.get(jid)
                                    if not job: return
                                    job["log"].append(item)
                                print(f"[{jid[:8]}] {msg}", flush=True)
                                with job["cond"]:
                                    job["cond"].notify_all()
                            _run_job_impl(jid, cfg_to_run, _emit)
                        except Exception as e:
                            import traceback
                            print(f"[scheduler] 任务异常: {e}", flush=True)
                            print(traceback.format_exc(), flush=True)
                            JOBS[jid]["status"] = "error"
                    threading.Thread(target=_sched_th, daemon=True).start()
        except Exception as e:
            print(f"[scheduler] 异常: {e}", flush=True)
        time.sleep(30)


def _run_job_impl(job_id, config, emit):
    if not playwright:
        emit("✗ Playwright 未安装，无法执行", "error")
        JOBS[job_id]["status"] = "error"
        return

    accounts = config.get("accounts", [])
    cdk_list = config.get("cdkList", [])
    pages_cfg = config.get("pages", {})
    domain = config.get("domain", "")

    # 筛选今日活跃 CDK
    active_cdks = [c for c in cdk_list if cdk_active_today(c)]
    emit(f"📋 今日活跃 CDK: {len(active_cdks)} 个（总计 {len(cdk_list)}）")
    if active_cdks:
        for c in active_cdks:
            emit(f"  - [{c.get('schedule')}] {c.get('code', '')[:20]}...")

    if not accounts:
        emit("✗ 没有账号", "error")
        JOBS[job_id]["status"] = "error"
        return

    # 选择浏览器：优先用 config 里的，没有再读环境变量，最后默认 msedge
    browser_type = (config.get("browserType") or os.environ.get("BROWSER_TYPE") or "msedge").lower()
    launch_kwargs = {
        "headless": config.get("headless", True),  # 改回 True
        "args": ["--no-sandbox", "--disable-blink-features=AutomationControlled"],
    }
    if browser_type in ("msedge", "chrome"):
        launch_kwargs["channel"] = browser_type
    # browser_type == "chromium" 时不传 channel，用 Playwright 自带的（需先 playwright install chromium）

    emit(f"🌐 启动浏览器: {browser_type} (headless={launch_kwargs['headless']})")

    # 选择要执行的页面（前端勾选，默认两个都跑）
    run_targets = config.get("runTargets") or ["login", "cdk"]
    emit(f"🎯 执行目标: {', '.join(run_targets)}")

    # 先试启动浏览器，失败给出明确提示
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**launch_kwargs)
            try:
                context = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
                page = context.new_page()
                # 反爬：隐藏 webdriver
                page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
                # 监听 JS 弹窗：emit 日志后自动 accept，避免卡住任务
                def _on_dialog(dialog):
                    try:
                        emit(f"  ⚠ 弹窗 [{dialog.type}]: {dialog.message}", "warn")
                    except Exception:
                        pass
                    try: dialog.accept()
                    except Exception: pass
                page.on("dialog", _on_dialog)

                # 根据 run_targets 计算总步骤数
                total_steps = 0
                if "login" in run_targets: total_steps += len(accounts)
                if "claim" in run_targets: total_steps += len(accounts)
                if "cdk" in run_targets: total_steps += len(accounts) * len(active_cdks)
                done = 0

                # 多轮重试：每个轮次只跑"验证码未成功"的账号，全部成功或达轮次上限才停
                # 业务失败（"失败: 1 个"等）不算验证码失败，不会进下一轮
                MAX_CAPTCHA_ROUNDS = 5
                round_num = 1
                remaining_accounts = list(accounts)  # 复制：每轮从头遍历失败的账号

                while remaining_accounts and round_num <= MAX_CAPTCHA_ROUNDS:
                    if round_num > 1:
                        emit(f"\n===== 第 {round_num} 轮：重试 {len(remaining_accounts)} 个验证码失败的账号 =====")
                    next_remaining = []

                    for acc in remaining_accounts:
                        acc_user = acc.get("username", "?")
                        # 每账号开始前重置验证码状态
                        captcha_ctx["last_result"] = None
                        captcha_ctx["attempts"] = 0
                        captcha_ctx["active"] = False
                        _check_pause(job_id, emit)
                        _check_cancel(job_id, emit)
                        emit(f"\n=== 账号: {acc_user} ===")

                        if "login" in run_targets:
                            page_obj = pages_cfg.get("login", {})
                            if not page_obj.get("actions"):
                                emit("  (未配置登录页操作，跳过登录)", "warn")
                            else:
                                try:
                                    target = page_obj.get("urlPattern", "https://" + domain + "/player/login")
                                    if not target.startswith("http"):
                                        target = "https://" + domain + target
                                    page.goto(target, timeout=20000)
                                    emit(f"  打开: {target}")
                                    for op in page_obj.get("actions", []):
                                        _check_pause(job_id, emit)
                                        _check_cancel(job_id, emit)
                                        do_op(page, op, acc, None, emit)
                                    # 等待跳转（如果配了 waitForUrl）
                                    time.sleep(1)
                                except Exception as e:
                                    emit(f"  ✗ 登录失败: {e}", "error")
                                    captcha_ctx["last_result"] = "failure"  # 异常也算失败，加入下一轮
                                    continue
                                done += 1

                        if "claim" in run_targets:
                            # 校验：claim 必须跟 login 一起勾（用户要求强制）
                            if "login" not in run_targets:
                                emit("  ⚠ 勾了领取页但没勾登录页，跳过领取", "warn")
                            else:
                                page_obj = pages_cfg.get("claim", {})
                                if not page_obj.get("actions"):
                                    emit("  (未配置领取页操作，跳过)", "warn")
                                else:
                                    try:
                                        # claim 默认 autoGoto=False（不跳转，登录后已在那）
                                        if page_obj.get("autoGoto", False):
                                            target = page_obj.get("urlPattern", "")
                                            if target:
                                                if not target.startswith("http"):
                                                    target = "https://" + domain + target
                                                page.goto(target, timeout=20000)
                                                emit(f"  打开: {target}")
                                            else:
                                                emit("  (claim 设了 autoGoto 但没配 urlPattern，跳过 goto)", "warn")
                                        # 不管跳不跳，都跑动作
                                        for op in page_obj.get("actions", []):
                                            _check_pause(job_id, emit)
                                            _check_cancel(job_id, emit)
                                            do_op(page, op, acc, None, emit)
                                        time.sleep(0.5)
                                    except Exception as e:
                                        emit(f"  ✗ 领取失败: {e}", "error")
                                    done += 1

                        if "cdk" in run_targets:
                            # 跑 CDK
                            for cdk in active_cdks:
                                _check_pause(job_id, emit)
                                _check_cancel(job_id, emit)
                                page_obj = pages_cfg.get("cdk", {})
                                if not page_obj.get("actions"):
                                    emit("  (未配置 CDK 页操作，跳过)", "warn")
                                    continue
                                try:
                                    target = page_obj.get("urlPattern", "https://" + domain + "/index/cdk")
                                    if not target.startswith("http"):
                                        target = "https://" + domain + target
                                    page.goto(target, timeout=20000)
                                    emit(f"  打开: {target}")
                                    for op in page_obj.get("actions", []):
                                        _check_pause(job_id, emit)
                                        _check_cancel(job_id, emit)
                                        do_op(page, op, acc, cdk, emit)
                                    time.sleep(0.5)
                                    # 标记一次性 CDK 已用
                                    if cdk.get("schedule") == "once":
                                        cdk["used"] = True
                                        # 写回 config 给面板保存
                                        emit(f"  ✓ CDK[{cdk.get('code','')[:10]}] 已标记为已用")
                                except Exception as e:
                                    emit(f"  ✗ CDK 失败: {e}", "error")
                                    # 跟 login 一致：异常也算失败，加入下一轮重试
                                    captcha_ctx["last_result"] = "failure"
                                done += 1
                        # 账号处理完一轮：检查结果分类
                        # - "wrong_pwd" → 账密错，不入库，不进下一轮
                        # - "failure"    → 验证码失败，进下一轮重试
                        # - "success"    → 完成（成功或业务失败），不入 next_remaining
                        last = captcha_ctx.get("last_result")
                        if last == "wrong_pwd":
                            acc_user = acc.get("username", "?")
                            emit(f"  ✗ 账号 {acc_user} 账密错误，标记但不进下一轮、不入库", "error")
                            # 账密错：不入 next_remaining，账密也不入库（用户要求）
                        elif last == "failure":
                            acc_user = acc.get("username", "?")
                            emit(f"  ⚠ 账号 {acc_user} 验证码失败，加入下一轮重试", "warn")
                            next_remaining.append(acc)
                    # 本轮结束：更新 remaining + round
                    if not next_remaining:
                        emit("\n✅ 所有账号验证码都已通过")
                        remaining_accounts = []
                    else:
                        remaining_accounts = next_remaining
                        round_num += 1
                if remaining_accounts:
                    emit(f"\n⚠ 经过 {MAX_CAPTCHA_ROUNDS} 轮，仍有 {len(remaining_accounts)} 个账号验证码失败: {[a.get('username','?') for a in remaining_accounts]}", "warn")
            finally:
                try: browser.close()
                except: pass
    except _JobCancelled:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job: job["status"] = "cancelled"
        return  # 浏览器已在 finally 里关掉
    except Exception as e:
        hint = ""
        if "Executable doesn't exist" in str(e) or "找不到" in str(e):
            if browser_type == "msedge":
                hint = "（找不到系统 Edge。请确认你装了新版 Edge：Win10 1903+ / Win11 自带。设置里搜「Edge」看有没有）"
            elif browser_type == "chrome":
                hint = "（找不到 Chrome。请先装 Chrome，或把 browserType 改成 msedge 用系统 Edge）"
            else:
                hint = "（需要先执行：python -m playwright install chromium）"
        emit(f"✗ 浏览器启动失败: {e}", "error")
        if hint: emit(hint, "error")
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job: job["status"] = "error"
        return

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            job["status"] = "done"
            job["result"] = "completed"
    emit("\n✅ 全部完成")
    # 持久化 CDK 状态到数据库
    # - 一次性 CDK：跑完一轮全删（不管成功失败）
    # - 每日 CDK：标 used=1（明天不再跑）
    # - 不论成功失败都标 used=1（避免每天重复跑同一个 CDK）
    try:
        n = db_delete_once_cdks()
        if n:
            emit(f"  ✓ 已删除 {n} 个一次性 CDK")
        n_marked = 0
        for cdk in cdk_list:
            if cdk.get("schedule") != "once":
                if db_mark_cdk_used(cdk.get("code", "")):
                    n_marked += 1
        if n_marked:
            emit(f"  ✓ {n_marked} 个每日 CDK 已标已用（明天不会重跑）")
    except Exception as e:
        emit(f"  ⚠ 保存 CDK 状态失败: {e}", "warn")
    # 把更新后的 cdkList 写回（给面板同步）
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            job["updatedConfig"] = config


# ---------- HTTP Server ----------
class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self._cors()
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if not length: return {}
        return json.loads(self.rfile.read(length).decode('utf-8'))

    def log_message(self, format, *args):
        pass  # 静默

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        try:
            from urllib.parse import urlparse, parse_qs
            if self.path == '/favicon.ico':
                # 返回 1x1 透明 png，避免浏览器控制台 404 噪音
                body = bytes.fromhex("89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4890000000A49444154789C6300010000000500010D0A2DB40000000049454E44AE426082")
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'max-age=86400')
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == '/' or self.path == '/index.html' or self.path == '/panel':
                self._serve_panel()
            elif self.path == '/api/info':
                self._json(200, {
                    "lan_ip": get_lan_ip(),
                    "port": SERVER_PORT,
                    "ocr": ocr is not None,
                    "playwright": playwright is not None,
                })
            elif self.path == '/api/config':
                if self.command == 'POST':
                    # 前端 syncConfigToServer：保存 config 到文件 + LAST_CONFIG
                    try:
                        body = self._read_body()
                        cfg = body if isinstance(body, dict) else {}
                        ok = save_persisted_config(cfg)
                        global LAST_CONFIG
                        LAST_CONFIG = cfg
                        self._json(200, {"ok": ok})
                    except Exception as e:
                        self._json(500, {"error": str(e)})
                else:
                    self._json(200, load_persisted_config())
            elif self.path == '/api/accounts':
                if self.command == 'POST':
                    body = self._read_body()
                    ga = (body.get("username") or body.get("game_account") or "").strip()
                    gp = (body.get("password") or body.get("game_password") or "").strip()
                    if not ga or not gp:
                        return self._json(400, {"error": "账号密码不能为空"})
                    action = db_upsert_account(ga, gp)
                    self._json(200, {"ok": True, "action": action})
                elif self.command == 'DELETE':
                    body = self._read_body()
                    aid = body.get("id")
                    if aid:
                        db_delete_account(aid)
                    self._json(200, {"ok": True})
                else:
                    # GET /api/accounts 只返回账号列表（不返回密码，保护安全）
                    self._json(200, db_get_accounts(include_password=False))
            elif self.path == '/api/cdks':
                if self.command == 'POST':
                    body = self._read_body()
                    code = (body.get("code") or "").strip()
                    if not code:
                        return self._json(400, {"error": "CDK 不能为空"})
                    ok = db_add_cdk(code)
                    self._json(200, {"ok": ok})
                elif self.command == 'DELETE':
                    body = self._read_body()
                    cid = body.get("id")
                    if cid:
                        db_delete_cdk(cid)
                    self._json(200, {"ok": True})
                else:
                    self._json(200, db_get_cdks())
            elif self.path.startswith('/health'):
                self._json(200, {"ok": True, "ocr": ocr is not None, "playwright": playwright is not None})
            elif self.path.startswith('/progress'):
                qs = parse_qs(urlparse(self.path).query)
                jid = qs.get('id', [''])[0]
                job = JOBS.get(jid)
                if not job:
                    self._json(404, {"error": "job not found"})
                else:
                    with job["cond"]:
                        self._json(200, {
                            "status": job["status"],
                            "log": job["log"][job["last_index"]:],
                            "done": job["status"] in ("done", "error"),
                            "updatedConfig": job.get("updatedConfig"),
                        })
                        job["last_index"] = len(job["log"])
            elif self.path.startswith('/api/jobs'):
                # /api/jobs?job_id=xxx —— 简化版进度查询（前端测试兑换用）
                qs = parse_qs(urlparse(self.path).query)
                jid = qs.get('job_id', [''])[0]
                job = JOBS.get(jid)
                if not job:
                    self._json(404, {"error": "job not found"})
                else:
                    with JOBS_LOCK:
                        self._json(200, {
                            "status": job["status"],
                            "saved": job.get("saved"),
                            "save_reason": job.get("save_reason"),
                            "save_action": job.get("save_action"),
                            "log_count": len(job.get("log", [])),
                        })
            elif self.path.startswith('/stream'):
                # SSE：实时推送日志
                qs = parse_qs(urlparse(self.path).query)
                jid = qs.get('id', [''])[0]
                self._handle_sse(jid)
            elif self.path == '/picker/wait':
                # 前端长轮询：等点选结果（最多 120s）
                # 关键 1：必须等 start_event set（picker 启动完成）后，才检查 running/result。
                #         避免 _open_picker 还在 goto 时，前端 wait 误判 "running=False => 未选择"
                # 关键 2：优先用 last_result_snapshot，兜底用 last_result
                #         防止并发 wait 抢到清空的 last_result 时还能从 snapshot 拿到正确值
                with PICKER_STATE["cond"]:
                    PICKER_STATE["cond"].wait_for(
                        lambda: PICKER_STATE["start_event"].is_set() and (
                            PICKER_STATE.get("last_result_snapshot") is not None
                            or PICKER_STATE.get("last_result") is not None
                            or not PICKER_STATE.get("running")
                        ),
                        timeout=120
                    )
                    snapshot = PICKER_STATE.get("last_result_snapshot")
                    if snapshot:
                        # snapshot 不清空（保留给后续可能并发的 wait）
                        result = snapshot
                    else:
                        result = PICKER_STATE.get("last_result")
                        if result:
                            PICKER_STATE["last_result"] = None
                print(f"[PICKER] wait 返回: result.selector={result.get('selector') if result else None} running={PICKER_STATE.get('running')}", flush=True)
                self._json(200, {"result": result, "running": PICKER_STATE.get("running", False)})
            else:
                self._json(404, {"error": "not found"})
        except Exception as e:
            import traceback
            self._json(500, {"error": str(e), "trace": traceback.format_exc()})

    def _handle_sse(self, jid):
        job = JOBS.get(jid)
        if not job:
            self._json(404, {"error": "job not found"})
            return

        # SSE 响应头
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.send_header('X-Accel-Buffering', 'no')
        self._cors()
        self.end_headers()

        with JOBS_LOCK:
            job["subscribers"] += 1
        try:
            # 先发一次已存在的日志（断线重连也能拿到）
            with job["cond"]:
                start_idx = job["last_index"]
                # 重连时支持 ?last=N 续传
                from urllib.parse import urlparse, parse_qs as _pqs
                # 已在 do_GET 解析过，但这里拿不到 query，重新解析 path
                q = _pqs(urlparse('http://x' + self.path).query)
                try: start_idx = int(q.get('last', [start_idx])[0])
                except: pass
                for item in job["log"][start_idx:]:
                    self._sse_send({"type": "log", **item})
                job["last_index"] = len(job["log"])
                # 立即 flush
                try: self.wfile.flush()
                except: pass

            # 进入推送循环
            while True:
                with job["cond"]:
                    # 等新日志或任务结束（最多 25s 一发心跳，防代理超时）
                    while job["status"] == "running" and job["last_index"] >= len(job["log"]):
                        job["cond"].wait(timeout=25)
                        # 心跳
                        try:
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                        except Exception:
                            return

                    # 把新增日志推出去
                    for item in job["log"][job["last_index"]:]:
                        self._sse_send({"type": "log", **item})
                    job["last_index"] = len(job["log"])

                    if job["status"] in ("done", "error"):
                        self._sse_send({
                            "type": "done",
                            "ok": job["status"] == "done",
                            "msg": "全部完成" if job["status"] == "done" else "执行失败",
                            "updatedConfig": job.get("updatedConfig"),
                        })
                        try: self.wfile.flush()
                        except: pass
                        break
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with JOBS_LOCK:
                job["subscribers"] = max(0, job["subscribers"] - 1)

    def _sse_send(self, obj):
        data = json.dumps(obj, ensure_ascii=False)
        # 注意 SSE 字段必须一个占一行，行尾 \n
        for line in data.split('\n'):
            self.wfile.write(('data: ' + line + '\n').encode('utf-8'))
        self.wfile.write(b'\n')
        self.wfile.flush()

    def _serve_panel(self):
        """直接返回面板 HTML（同目录的 autofill-panel.html）"""
        panel_path = get_panel_html_path()
        if not os.path.exists(panel_path):
            # 没找到 HTML，给个简单提示
            body = (
                "<!doctype html><meta charset=utf-8>"
                "<h2>找不到 autofill-panel.html</h2>"
                f"<p>已尝试：</p><ul>{''.join(f'<li><code>{p}</code></li>' for p in PANEL_HTML_CANDIDATES)}</ul>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self._cors()
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            with open(panel_path, "rb") as f:
                body = f.read()
        except Exception as e:
            self._json(500, {"error": "read panel failed", "msg": str(e)})
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self._cors()
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            from urllib.parse import urlparse, parse_qs
            if self.path == '/api/config':
                body = self._read_body()
                ok = save_persisted_config(body)
                self._json(200, {"ok": ok, "file": CONFIG_FILE})
            elif self.path.startswith('/ocr'):
                body = self._read_body()
                img_b64 = body.get("image_base64", "")
                if not img_b64 or not ocr:
                    return self._json(400, {"error": "bad request"})
                img = base64.b64decode(img_b64)
                result = ocr.classification(img)
                self._json(200, {"result": result})
            elif self.path == '/api/run':
                body = self._read_body()
                cfg = body.get("config", {})
                jid = uuid.uuid4().hex
                # 保存最新 config 给定时任务用
                global LAST_CONFIG
                LAST_CONFIG = cfg
                run_job(jid, cfg)
                self._json(200, {"job_id": jid})
            elif self.path == '/api/test-redeem':
                # 测试兑换：用前端临时输入的账密 + 用后端 CDK 池跑一次
                # 账密错 → 不入库；成功/其他 → 入库
                body = self._read_body()
                username = (body.get("username") or "").strip()
                password = (body.get("password") or "").strip()
                if not username or not password:
                    return self._json(400, {"error": "账号密码不能为空"})
                # 用 G2 策略：所有每日 CDK 各跑一次
                active_cdks = []
                for c in db_get_cdks():
                    if c["once"]:
                        active_cdks.append({"code": c["code"], "schedule": "once", "used": False})
                    else:
                        if not c["used"]:
                            active_cdks.append({"code": c["code"], "schedule": "daily", "used": False})
                if not active_cdks:
                    return self._json(400, {"error": "后端 CDK 池为空，请先用 cdk add-daily 加"})
                # 组装 config（只跑 cdk target，但实际 _run_job_impl 会跑 login+cdk）
                cfg = {
                    "domain": LAST_CONFIG.get("domain", "newxiadan.3f8cz.com") if LAST_CONFIG else "newxiadan.3f8cz.com",
                    "pages": (LAST_CONFIG.get("pages") if LAST_CONFIG else None) or json.load(open(CONFIG_FILE, encoding="utf-8")).get("pages", {}) if os.path.exists(CONFIG_FILE) else {},
                    "accounts": [{"username": username, "password": password}],
                    "cdkList": active_cdks,
                    "runTargets": ["login", "cdk"],
                }
                jid = uuid.uuid4().hex
                JOBS[jid] = {
                    "status": "running", "log": [], "result": None, "started": time.time(),
                    "cond": threading.Condition(), "last_index": 0, "subscribers": 0,
                    "updatedConfig": None, "paused": False, "cancel_requested": False,
                    "trigger": "test-redeem", "test_account": {"username": username, "password": password},
                }
                def _test_th():
                    try:
                        def _emit(msg, level="info"):
                            with JOBS_LOCK:
                                job = JOBS.get(jid)
                                if not job: return
                                job["log"].append({"time": time.time(), "msg": msg, "level": level})
                            print(f"[{jid[:8]}] {msg}", flush=True)
                            with job["cond"]:
                                job["cond"].notify_all()
                        _run_job_impl(jid, cfg, _emit)
                        # 跑完后判断结果：查日志有没有"账密错误"关键词
                        with JOBS_LOCK:
                            job = JOBS.get(jid)
                            log = job.get("log", []) if job else []
                        wrong_pwd = any("账密错误" in item.get("msg", "") for item in log)
                        if wrong_pwd:
                            # 账密错：不入库
                            with JOBS_LOCK:
                                if job: job["saved"] = False; job["save_reason"] = "账密错"
                        else:
                            # 没账密错：入库
                            action = db_upsert_account(username, password)
                            with JOBS_LOCK:
                                if job:
                                    job["saved"] = True
                                    job["save_action"] = action
                                    job["save_reason"] = f"成功入库（{action}）"
                            print(f"[test-redeem] 账密入库: {action}", flush=True)
                    except Exception as e:
                        import traceback
                        print(f"[test-redeem] 异常: {e}", flush=True)
                        print(traceback.format_exc(), flush=True)
                        with JOBS_LOCK:
                            job = JOBS.get(jid)
                            if job: job["status"] = "error"
                threading.Thread(target=_test_th, daemon=True).start()
                self._json(200, {"job_id": jid, "cdk_count": len(active_cdks)})
            elif self.path.startswith('/picker/start'):
                qs = parse_qs(urlparse(self.path).query)
                body = self._read_body()
                action_idx = (body.get("actionIdx") if isinstance(body, dict) else None) or qs.get("actionIdx", [None])[0]
                field = (body.get("field") if isinstance(body, dict) else None) or qs.get("field", [None])[0]
                page_name = (body.get("page") if isinstance(body, dict) else None) or qs.get("page", [None])[0]
                url = (body.get("url") if isinstance(body, dict) else None) or qs.get("url", [None])[0]
                if not url:
                    return self._json(400, {"error": "缺少 url"})
                r = start_picker(action_idx, field, page_name, url)
                self._json(200, r)
            elif self.path.startswith('/picker/select'):
                qs = parse_qs(urlparse(self.path).query)
                body = self._read_body()
                sel = (body.get("selector") if isinstance(body, dict) else None) or ""
                tag = (body.get("tag") if isinstance(body, dict) else None) or ""
                action_idx = qs.get("actionIdx", [None])[0]
                field = qs.get("field", [None])[0]
                page_name = qs.get("page", [None])[0]
                with PICKER_STATE["cond"]:
                    PICKER_STATE["last_result"] = {
                        "actionIdx": action_idx, "field": field, "page": page_name,
                        "selector": sel, "tag": tag,
                    }
                    PICKER_STATE["cond"].notify_all()
                self._json(200, {"ok": True, "selector": sel})
            elif self.path.startswith('/picker/stop'):
                r = stop_picker()
                self._json(200, r)
            elif self.path.startswith('/jobs/') and self.path.endswith('/pause'):
                # /jobs/<id>/pause
                jid = self.path.split('/')[2]
                with JOBS_LOCK:
                    job = JOBS.get(jid)
                    if not job: return self._json(404, {"error": "job not found"})
                    if job.get("status") != "running":
                        return self._json(400, {"error": f"job not running (status={job.get('status')})"})
                    job["paused"] = True
                self._json(200, {"ok": True, "msg": "已请求暂停"})
            elif self.path.startswith('/jobs/') and self.path.endswith('/resume'):
                # /jobs/<id>/resume
                jid = self.path.split('/')[2]
                with JOBS_LOCK:
                    job = JOBS.get(jid)
                    if not job: return self._json(404, {"error": "job not found"})
                    job["paused"] = False
                self._json(200, {"ok": True, "msg": "已请求继续"})
            elif self.path.startswith('/jobs/') and self.path.endswith('/cancel'):
                # /jobs/<id>/cancel
                jid = self.path.split('/')[2]
                with JOBS_LOCK:
                    job = JOBS.get(jid)
                    if not job: return self._json(404, {"error": "job not found"})
                    job["cancel_requested"] = True
                    job["paused"] = False  # 取消时如果暂停中，先恢复才能让取消检查跑起来
                self._json(200, {"ok": True, "msg": "已请求取消"})
            elif self.path.startswith('/restart'):
                # 重启服务：先通知所有任务取消 → 等 Playwright 干净关闭 → 再 execv
                # 不先 cancel 就 execv 会导致 Playwright 还在往 chromium pipe 写消息 → EPIPE
                with JOBS_LOCK:
                    for jid, job in list(JOBS.items()):
                        if job.get("status") == "running":
                            job["cancel_requested"] = True
                            job["paused"] = False
                os.environ["OCR_NO_BROWSER"] = "1"
                self._json(200, {"ok": True, "msg": "🔄 服务重启中..."})
                print(f"[{threading.current_thread().name}] 收到 /restart 请求，准备替换进程...", flush=True)
                def _do_restart():
                    time.sleep(2.5)  # 等 cancel 检查 + browser.close 走完 finally
                    try:
                        os.execv(sys.executable, [sys.executable] + sys.argv)
                    except Exception as e:
                        print(f"[FATAL] 重启失败: {e}", flush=True)
                threading.Thread(target=_do_restart, daemon=True).start()
            else:
                self._json(404, {"error": "not found"})
        except Exception as e:
            import traceback
            self._json(500, {"error": str(e), "trace": traceback.format_exc()})


def main():
    global SERVER_PORT
    SERVER_PORT = 7777
    if len(sys.argv) > 1:
        try: SERVER_PORT = int(sys.argv[1])
        except: pass
    lan_ip = get_lan_ip()
    print("=" * 50)
    print(f"自动填表助手 - 一键执行服务")
    print(f"OCR:       {'✓' if ocr else '✗ 未安装'}")
    print(f"Playwright:{'✓' if playwright else '✗ 未安装'}  (默认用系统 Edge，不用下 Chromium)")
    print(f"本机访问:   http://127.0.0.1:{SERVER_PORT}/")
    print(f"局域网访问: http://{lan_ip}:{SERVER_PORT}/  ← 手机扫码/输入这个")
    print(f"配置目录:   {APP_DIR}")
    print(f"健康检查:   http://127.0.0.1:{SERVER_PORT}/api/info")
    print(f"一键执行:   POST http://127.0.0.1:{SERVER_PORT}/run")
    print(f"进度查询:   GET  http://127.0.0.1:{SERVER_PORT}/progress?id=<job_id>")
    print(f"实时日志:   GET  http://127.0.0.1:{SERVER_PORT}/stream?id=<job_id>  (SSE)")
    print("按 Ctrl+C 停止")
    print("=" * 50)
    # 初始化数据库
    _init_db()
    print(f"数据库:     {DB_FILE}")
    # 启动后自动开浏览器（通过 /restart 重启时跳过，避免弹新窗口）
    def _open_browser():
        if os.environ.get("OCR_NO_BROWSER") == "1":
            print("[INFO] OCR_NO_BROWSER=1，跳过自动开浏览器（/restart 触发的重启）")
            return
        time.sleep(0.6)
        try:
            import webbrowser
            webbrowser.open(f"http://127.0.0.1:{SERVER_PORT}/")
        except Exception as e:
            print(f"[WARN] 自动开浏览器失败: {e}")
    threading.Thread(target=_open_browser, daemon=True).start()

    # 终端 Ctrl+B 监听：守护线程循环读控制台按键，收到 Ctrl+B 就 os.execv 重启进程
    def _kbd_listener():
        if sys.platform != "win32":
            print("[提示] 终端 Ctrl+B 重启仅支持 Windows", flush=True)
            return
        try:
            import msvcrt
        except ImportError:
            print("[提示] msvcrt 不可用，终端 Ctrl+B 重启不可用", flush=True)
            return
        print("[提示] 终端按 Ctrl+B 可快速重启服务（无需关闭再启动）", flush=True)
        while True:
            try:
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch == b'\x02':  # Ctrl+B 的 ASCII 码
                        print("\n[Ctrl+B] 收到重启信号，500ms 后替换进程...", flush=True)
                        os.environ["OCR_NO_BROWSER"] = "1"
                        time.sleep(0.5)
                        try:
                            os.execv(sys.executable, [sys.executable] + sys.argv)
                        except Exception as e:
                            print(f"[FATAL] 重启失败: {e}", flush=True)
            except Exception:
                # 读键异常时继续循环，不让线程挂掉
                pass
            time.sleep(0.1)
    threading.Thread(target=_kbd_listener, daemon=True).start()
    # 启动定时任务守护线程
    threading.Thread(target=_scheduler_loop, daemon=True).start()
    print("⏰ 定时任务守护线程已启动（默认每天 00:05）", flush=True)

    server = ThreadingHTTPServer(('0.0.0.0', SERVER_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        server.shutdown()


# ---------- CDK CLI ----------
def cdk_cli_help():
    print("""CDK 管理命令（终端运行，不用启 HTTP 服务）:

  python ocr_server.py cdk add-daily <code1> [code2 ...]   添加每日 CDK
  python ocr_server.py cdk add-once <code1> [code2 ...]   添加一次性 CDK（跑完一轮自动删）
  python ocr_server.py cdk remove <code>                  删除指定 CDK
  python ocr_server.py cdk reset <code>                   重置每日 CDK 为未用（明天能再跑）
  python ocr_server.py cdk list                           列出所有 CDK
  python ocr_server.py cdk help                           显示本帮助
  python ocr_server.py account list                       列出所有账号（不显示密码）
  python ocr_server.py account add <账号> <密码>          新增账号
  python ocr_server.py account remove <账号>              删除账号

数据库位置：{DB_FILE}
""".replace("{DB_FILE}", DB_FILE))

def account_cli(args):
    """账号子命令入口"""
    if len(args) < 1 or args[0] in ("help", "-h", "--help"):
        print("用法:")
        print("  account list                列出所有账号（不显示密码）")
        print("  account add <账号> <密码>   新增/更新账号")
        print("  account remove <账号>       删除账号")
        return 0
    cmd = args[0]
    rest = args[1:]
    if cmd == "list":
        accounts = db_get_accounts(include_password=False)
        if not accounts:
            print("（数据库为空）")
            return 0
        print(f"{'ID':<5} {'账号'}")
        print("-" * 30)
        for a in accounts:
            print(f"{a.get('id', '?'):<5} {a['username']}")
        print(f"\n共 {len(accounts)} 个账号")
        return 0
    if cmd == "add":
        if len(rest) < 2:
            print("✗ 用法: account add <账号> <密码>", file=sys.stderr)
            return 1
        action = db_upsert_account(rest[0], rest[1])
        print(f"  ✓ 账号 {rest[0]}: {action}")
        return 0
    if cmd in ("remove", "rm", "delete"):
        if len(rest) < 1:
            print("✗ 用法: account remove <账号>", file=sys.stderr)
            return 1
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM accounts WHERE game_account = ?", (rest[0],))
        n = c.rowcount
        conn.commit()
        conn.close()
        if n:
            print(f"  ✓ 已删除 {rest[0]}")
        else:
            print(f"  - {rest[0]} 不存在")
        return 0
    print(f"✗ 未知子命令: {cmd}", file=sys.stderr)
    return 1

def cdk_cli(args):
    """CDK 子命令入口。返回 0=成功，非0=失败"""
    if len(args) < 1 or args[0] in ("help", "-h", "--help"):
        cdk_cli_help()
        return 0
    cmd = args[0]
    rest = args[1:]
    if cmd == "add-daily":
        if not rest:
            print("✗ 至少给一个 CDK code", file=sys.stderr)
            return 1
        ok = 0; skip = 0
        for code in rest:
            if db_add_cdk(code, once=0):
                print(f"  ✓ [每日] {code}")
                ok += 1
            else:
                print(f"  - [已存在] {code}")
                skip += 1
        print(f"\n共 {ok} 个新增，{skip} 个已存在")
        return 0
    if cmd == "add-once":
        if not rest:
            print("✗ 至少给一个 CDK code", file=sys.stderr)
            return 1
        ok = 0; skip = 0
        for code in rest:
            if db_add_cdk(code, once=1):
                print(f"  ✓ [一次性] {code}")
                ok += 1
            else:
                print(f"  - [已存在] {code}")
                skip += 1
        print(f"\n共 {ok} 个新增，{skip} 个已存在")
        return 0
    if cmd == "remove":
        if not rest:
            print("✗ 至少给一个 CDK code", file=sys.stderr)
            return 1
        for code in rest:
            n = db_delete_cdk_by_code(code)
            if n:
                print(f"  ✓ 已删 {code}")
            else:
                print(f"  - {code} 不存在")
        return 0
    if cmd == "reset":
        if not rest:
            print("✗ 至少给一个 CDK code", file=sys.stderr)
            return 1
        for code in rest:
            n = db_reset_cdk(code)
            if n:
                print(f"  ✓ 已重置 {code} 为未用")
            else:
                print(f"  - {code} 不存在")
        return 0
    if cmd == "list":
        cdks = db_get_cdks()
        if not cdks:
            print("（数据库为空）")
            return 0
        # 表格
        print(f"{'ID':<5} {'类型':<8} {'状态':<8} {'CDK'}")
        print("-" * 60)
        for c in cdks:
            ctype = "一次性" if c["once"] else "每日"
            status = "已用" if c["used"] else "可用"
            print(f"{c['id']:<5} {ctype:<8} {status:<8} {c['code']}")
        print(f"\n共 {len(cdks)} 个 CDK")
        return 0
    print(f"✗ 未知子命令: {cmd}", file=sys.stderr)
    cdk_cli_help()
    return 1


if __name__ == '__main__':
    # CLI 模式：python ocr_server.py cdk ... / account ...
    if len(sys.argv) >= 2 and sys.argv[1] == "cdk":
        _init_db()  # CLI 也要先建表
        sys.exit(cdk_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "account":
        _init_db()
        sys.exit(account_cli(sys.argv[2:]))
    main()
