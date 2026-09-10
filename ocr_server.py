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
import copy
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------- 时区：强制北京时间（容器默认 UTC，定时任务按北京时间跑） ----------
# 用 POSIX 格式 CST-8（固定 UTC+8）：不依赖系统的 /usr/share/zoneinfo/tzdata 文件，
# 容器没装 tzdata 时 Asia/Shanghai 会解析失败回退 UTC，CST-8 不会
os.environ["TZ"] = "CST-8"
try:
    time.tzset()  # Linux 生效；Windows 无此函数，忽略
except Exception:
    pass

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
# 验证码识别统计：最近一次 + 历史追加（任务结束落盘，前端断联也能查）
OCR_STATS_FILE = os.path.join(_DATA_DIR, "ocr_stats.json")
OCR_STATS_HISTORY_FILE = os.path.join(_DATA_DIR, "ocr_stats_history.jsonl")
# 任务独立日志目录：logs/<任务建立时间>_<任务id前8位>.log，启动时清理 7 天前的
LOG_DIR = os.path.join(_DATA_DIR, "logs")
LOG_RETENTION_DAYS = 7

def _new_job_log_path(job_id):
    try:
        return os.path.join(LOG_DIR, time.strftime("%Y%m%d_%H%M%S") + "_" + str(job_id)[:8] + ".log")
    except Exception:
        return None

def _init_log_dir():
    """启动/CLI 时确保目录存在，并清理超过保留天数的旧任务日志"""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        now = time.time()
        for fn in os.listdir(LOG_DIR):
            if not fn.endswith(".log"):
                continue
            p = os.path.join(LOG_DIR, fn)
            try:
                if now - os.path.getmtime(p) > LOG_RETENTION_DAYS * 86400:
                    os.remove(p)
            except OSError:
                pass
    except Exception:
        pass

def _job_log_append(job_id, msg, level="info"):
    """把任务日志追加到该任务独立文件（带时间戳；写失败不影响任务）"""
    try:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return
            path = job.get("logPath")
        if not path:
            return
        ts = time.strftime("[%H:%M:%S] ")
        tag = ("[" + level + "] ") if level and level != "info" else ""
        with open(path, "a", encoding="utf-8") as f:
            f.write(ts + tag + str(msg) + "\n")
    except Exception:
        pass

_init_log_dir()

# ---------- 运行设置（并发数等，命令 cc 管理） ----------
SETTINGS_FILE = os.path.join(_DATA_DIR, "autofill_settings.json")
_SETTINGS_LOCK = threading.Lock()

def _load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def _save_settings(d):
    with _SETTINGS_LOCK:
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

def get_concurrency():
    """并发数：环境变量 AUTOFILL_CONCURRENCY > cc 命令设置 > 默认 3"""
    try:
        v = int(os.environ.get("AUTOFILL_CONCURRENCY", "").strip())
        if v >= 1:
            return v
    except Exception:
        pass
    try:
        v = int(_load_settings().get("concurrency", 0))
        if v >= 1:
            return v
    except Exception:
        pass
    return 3

def set_concurrency(n):
    n = int(n)
    if n < 1:
        raise ValueError("并发数必须是 >=1 的整数")
    d = _load_settings()
    d["concurrency"] = n
    _save_settings(d)
    return n

def _db_conn():
    """带写等待超时的数据库连接：并发写时不直接报错，最多等 30 秒"""
    conn = sqlite3.connect(DB_FILE, timeout=30)
    try:
        conn.execute("PRAGMA busy_timeout=30000")
    except Exception:
        pass
    return conn

# ---------- SQLite 数据库 ----------
def _init_db():
    conn = _db_conn()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_account TEXT UNIQUE NOT NULL,
        game_password TEXT NOT NULL,
        regions TEXT DEFAULT '[]',
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
    # 兼容旧库：补 regions 字段（区列表，JSON 数组）
    try:
        c.execute("ALTER TABLE accounts ADD COLUMN regions TEXT DEFAULT '[]'")
    except Exception:
        pass
    # 要求3：账号级 CDK 码（日/周/月，默认 hmxdy666/777/888，每个账号可单独改）
    for _col, _dft in (("cdk_daily", "'hmxdy666'"), ("cdk_weekly", "'hmxdy777'"), ("cdk_monthly", "'hmxdy888'")):
        try:
            c.execute("ALTER TABLE accounts ADD COLUMN %s TEXT DEFAULT %s" % (_col, _dft))
        except Exception:
            pass
    # 要求3：账号×区 的周/月周期状态表（起始时间 = 用户填写的首期日期；last = 最近一次成功/上限日期）
    c.execute("""CREATE TABLE IF NOT EXISTS account_cdk_cycles (
        username TEXT NOT NULL,
        region TEXT NOT NULL,
        weekly_start TEXT DEFAULT '',
        monthly_start TEXT DEFAULT '',
        weekly_last TEXT DEFAULT '',
        monthly_last TEXT DEFAULT '',
        weekly_next TEXT DEFAULT '',
        monthly_next TEXT DEFAULT '',
        PRIMARY KEY (username, region)
    )""")
    # 兼容旧库：补 next 列（服务器给定的下次可用时间）
    for _col in ("weekly_next", "monthly_next"):
        try:
            c.execute("ALTER TABLE account_cdk_cycles ADD COLUMN %s TEXT DEFAULT ''" % _col)
        except Exception:
            pass
    conn.commit()
    conn.close()

def _parse_regions(raw):
    """解析数据库里的区列表（JSON 数组），容错返回 list"""
    try:
        lst = json.loads(raw) if raw else []
        return [str(r) for r in lst] if isinstance(lst, list) else []
    except Exception:
        return []

def db_get_accounts(include_password=False):
    """
    获取账号列表。密码在数据库中是加密存的，读取时自动解密。
    include_password=False (默认): 只返回账号名（用于前端展示/CLI 列表）
    include_password=True: 返回账号+明文密码（用于程序内部自动登录用）
    每个账号带 regions（区列表，可能多个）。
    """
    conn = _db_conn()
    c = conn.cursor()
    c.execute("SELECT id, game_account, game_password, regions FROM accounts ORDER BY id")
    rows = c.fetchall()
    conn.close()
    if include_password:
        return [{"id": r[0], "username": r[1], "password": _decrypt_password(r[2]), "regions": _parse_regions(r[3])} for r in rows]
    else:
        return [{"id": r[0], "username": r[1], "regions": _parse_regions(r[3])} for r in rows]

def db_find_account(username, password):
    """查「用户名+密码都匹配」的账号记录（统一执行逻辑用）。
    匹配返回 dict（含 regions / 日周月 CDK 码），否则返回 None。
    密码解密后比对，兼容旧库明文/PLAIN 前缀。"""
    if not username or not password:
        return None
    conn = _db_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT id, game_account, game_password, regions, cdk_daily, cdk_weekly, cdk_monthly FROM accounts WHERE game_account=?", (username,))
        row = c.fetchone()
        if not row:
            return None
        if _decrypt_password(row[2]) != password:
            return None
        return {
            "id": row[0],
            "username": row[1],
            "regions": _parse_regions(row[3]),
            "cdk_daily": row[4] or "hmxdy666",
            "cdk_weekly": row[5] or "hmxdy777",
            "cdk_monthly": row[6] or "hmxdy888",
        }
    finally:
        conn.close()

def db_upsert_account(game_account, game_password, regions=None):
    """按 game_account 去重：存在+密码不同→更新，存在+相同→跳过，不存在→新增
    密码在写入前加密存储（Fernet）。
    regions: 新增账号时记录的区列表（JSON 数组）。已存在账号不改动区。"""
    encrypted = _encrypt_password(game_password)
    regs_json = json.dumps([str(r).strip() for r in (regions or []) if str(r).strip()], ensure_ascii=False) if regions else '[]'
    conn = _db_conn()
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
    c.execute("INSERT INTO accounts (game_account, game_password, regions) VALUES (?, ?, ?)", (game_account, encrypted, regs_json))
    conn.commit()
    conn.close()
    return "insert"

def db_delete_account(aid):
    conn = _db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM accounts WHERE id = ?", (aid,))
    conn.commit()
    conn.close()

def db_get_account_row(game_account):
    """返回账号数据库行 (id, game_account, game_password, regions) 或 None"""
    conn = _db_conn()
    c = conn.cursor()
    c.execute("SELECT id, game_account, game_password, regions FROM accounts WHERE game_account = ?", (game_account,))
    row = c.fetchone()
    conn.close()
    return row

def db_add_account_regions(game_account, regions):
    """给已有账号追加区（去重）。账号不存在返回 None。返回更新后的区列表。"""
    cleaned = [_normalize_region(str(r)) for r in (regions or []) if str(r).strip()]
    if not cleaned:
        return None
    row = db_get_account_row(game_account)
    if not row:
        return None
    cur = _parse_regions(row[3])
    changed = False
    for r in cleaned:
        if r not in cur:
            cur.append(r)
            changed = True
    if changed:
        conn = _db_conn()
        c = conn.cursor()
        c.execute("UPDATE accounts SET regions = ? WHERE game_account = ?", (json.dumps(cur, ensure_ascii=False), game_account))
        conn.commit()
        conn.close()
    return cur

def db_verify_account_password(game_account, plain_password):
    """校验账号密码：解密存储的密码后比对。不存在/失败返回 False。"""
    row = db_get_account_row(game_account)
    if not row:
        return False
    stored = _decrypt_password(row[2])
    return bool(stored) and stored == (plain_password or "")

def db_set_account_regions(game_account, regions):
    """覆盖式写入账号的区列表（去重保序）。账号不存在返回 None。"""
    seen = []
    for r in (regions or []):
        r = _normalize_region(str(r))
        if r and r not in seen:
            seen.append(r)
    row = db_get_account_row(game_account)
    if not row:
        return None
    conn = _db_conn()
    c = conn.cursor()
    c.execute("UPDATE accounts SET regions = ? WHERE game_account = ?", (json.dumps(seen, ensure_ascii=False), game_account))
    conn.commit()
    conn.close()
    return seen

def db_get_account_cdks(game_account):
    """读取账号的日/周/月 CDK 码；无记录或空值返回默认 hmxdy666/777/888"""
    conn = _db_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT cdk_daily, cdk_weekly, cdk_monthly FROM accounts WHERE game_account=?", (game_account,))
        row = c.fetchone()
        if not row:
            return {"daily": "hmxdy666", "weekly": "hmxdy777", "monthly": "hmxdy888"}
        d = (row[0] or "").strip() or "hmxdy666"
        w = (row[1] or "").strip() or "hmxdy777"
        m = (row[2] or "").strip() or "hmxdy888"
        return {"daily": d, "weekly": w, "monthly": m}
    finally:
        conn.close()

def db_set_account_cdks(game_account, daily=None, weekly=None, monthly=None):
    """更新账号的日/周/月 CDK 码。传 None = 不改；传空字符串 = 恢复默认。返回更新后的三个码。"""
    cur = db_get_account_cdks(game_account)
    d = (daily if daily is not None else cur["daily"] or "").strip() or "hmxdy666"
    w = (weekly if weekly is not None else cur["weekly"] or "").strip() or "hmxdy777"
    m = (monthly if monthly is not None else cur["monthly"] or "").strip() or "hmxdy888"
    conn = _db_conn()
    try:
        c = conn.cursor()
        c.execute("UPDATE accounts SET cdk_daily=?, cdk_weekly=?, cdk_monthly=? WHERE game_account=?",
                  (d, w, m, game_account))
        conn.commit()
        return {"daily": d, "weekly": w, "monthly": m}
    finally:
        conn.close()

def db_get_cdk_cycle(username, region):
    """读取 账号×区 的周/月周期状态（起始时间/上次成功时间），无记录返回空 dict"""
    conn = _db_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT weekly_start, monthly_start, weekly_last, monthly_last, weekly_next, monthly_next FROM account_cdk_cycles WHERE username=? AND region=?",
                  (username, _normalize_region(region) or ""))
        row = c.fetchone()
        if not row:
            return {}
        return {"weekly_start": row[0] or "", "monthly_start": row[1] or "",
                "weekly_last": row[2] or "", "monthly_last": row[3] or "",
                "weekly_next": row[4] or "", "monthly_next": row[5] or ""}
    finally:
        conn.close()

def db_set_cdk_cycle(username, region, weekly_start=None, monthly_start=None):
    """写入/更新 账号×区 的周/月起始时间。传 None = 不改；传空字符串 = 清空（该码每天跑）。"""
    region = _normalize_region(region)
    cur = db_get_cdk_cycle(username, region)
    w = (weekly_start if weekly_start is not None else cur.get("weekly_start", "") or "").strip()
    m = (monthly_start if monthly_start is not None else cur.get("monthly_start", "") or "").strip()
    conn = _db_conn()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO account_cdk_cycles (username, region, weekly_start, monthly_start, weekly_last, monthly_last, weekly_next, monthly_next)
                     VALUES (?,?,?,?,?,?,?,?)
                     ON CONFLICT(username, region) DO UPDATE SET weekly_start=excluded.weekly_start, monthly_start=excluded.monthly_start,
                     weekly_next='', monthly_next=''""",
                  (username, region or "", w, m, cur.get("weekly_last", ""), cur.get("monthly_last", ""), "", ""))
        conn.commit()
        return {"weekly_start": w, "monthly_start": m}
    finally:
        conn.close()

def db_update_cdk_cycle_last(username, region, kind):
    """周/月 CDK 成功或命中"上限"后，把本次日期记为 last（下次周期从今天起算）。返回今天的日期字符串。"""
    today = datetime.now().strftime("%Y-%m-%d")
    col = "weekly_last" if kind == "weekly" else "monthly_last"
    conn = _db_conn()
    try:
        c = conn.cursor()
        c.execute("UPDATE account_cdk_cycles SET %s=?, %s='' WHERE username=? AND region=?" % (col, col.replace("last", "next")),
                  (today, username, region or ""))
        if c.rowcount == 0:
            cur = db_get_cdk_cycle(username, region)
            c.execute("""INSERT INTO account_cdk_cycles (username, region, weekly_start, monthly_start, weekly_last, monthly_last, weekly_next, monthly_next)
                         VALUES (?,?,?,?,?,?,?,?)
                         ON CONFLICT(username, region) DO UPDATE SET %s=excluded.%s, %s=''""" % (col, col, col.replace("last", "next")),
                      (username, region or "", cur.get("weekly_start", ""), cur.get("monthly_start", ""),
                       today if kind == "weekly" else "", today if kind == "monthly" else "",
                       "", ""))
        conn.commit()
        return today
    finally:
        conn.close()

def db_set_cdk_cycle_next(username, region, kind, next_date):
    """命中"上限"后，把服务器返回的下次可用日期写入周期状态（周/月）。"""
    col = "weekly_next" if kind == "weekly" else "monthly_next"
    conn = _db_conn()
    try:
        c = conn.cursor()
        c.execute("UPDATE account_cdk_cycles SET %s=? WHERE username=? AND region=?" % col,
                  (next_date, username, region or ""))
        if c.rowcount == 0:
            cur = db_get_cdk_cycle(username, region)
            c.execute("""INSERT INTO account_cdk_cycles (username, region, weekly_start, monthly_start, weekly_last, monthly_last, weekly_next, monthly_next)
                         VALUES (?,?,?,?,?,?,?,?)
                         ON CONFLICT(username, region) DO UPDATE SET %s=excluded.%s""" % (col, col),
                      (username, region or "", cur.get("weekly_start", ""), cur.get("monthly_start", ""),
                       cur.get("weekly_last", ""), cur.get("monthly_last", ""),
                       next_date if kind == "weekly" else cur.get("weekly_next", ""),
                       next_date if kind == "monthly" else cur.get("monthly_next", "")))
        conn.commit()
        return next_date
    finally:
        conn.close()

def _extract_next_date(text):
    """从上限提示文字里提取下次可用日期（如「2026年09月10日刷新次数」），返回 YYYY-MM-DD；提取不到返回 None"""
    if not text:
        return None
    from datetime import date
    for rx in (_NEXT_DATE_RE_CN, _NEXT_DATE_RE_ISO):
        m = rx.search(text)
        if m:
            try:
                d = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                return d.strftime("%Y-%m-%d")
            except Exception:
                continue
    return None


def db_get_cdks():
    conn = _db_conn()
    c = conn.cursor()
    c.execute("SELECT id, code, used, once FROM cdks ORDER BY id")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "code": r[1], "used": bool(r[2]), "once": bool(r[3])} for r in rows]

def db_add_cdk(code, once=0):
    conn = _db_conn()
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
    conn = _db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM cdks WHERE id = ?", (cid,))
    conn.commit()
    conn.close()

def db_delete_cdk_by_code(code):
    """按 code 删（CLI 用）"""
    conn = _db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM cdks WHERE code = ?", (code,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted

def db_delete_once_cdks():
    """删所有一次性 CDK（跑完一轮后调）"""
    conn = _db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM cdks WHERE once = 1")
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted

def db_reset_cdk(code):
    """重置某 CDK 为未用（每日 CDK 想重跑时）"""
    conn = _db_conn()
    c = conn.cursor()
    c.execute("UPDATE cdks SET used = 0 WHERE code = ?", (code,))
    updated = c.rowcount
    conn.commit()
    conn.close()
    return updated

def db_mark_cdk_used(code):
    conn = _db_conn()
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
    # beta=True 启用新模型；可用环境变量 OCR_BETA=0 切回默认模型对比效果（改后 ocr-restart 生效）
    ocr = ddddocr.DdddOcr(show_ad=False, beta=os.environ.get("OCR_BETA", "0") != "0")  # 默认老模型；显式 OCR_BETA=1 切新模型
    # 可选限定字符集：OCR_RANGES=0(纯数字)/1(小写)/2(大写)/5(大写+数字)/6(字母+数字) 或自定义字符串
    # 你的验证码是字母数字 4-5 位，默认字符集已覆盖，可不用设置；需要时再配
    try:
        _r = (os.environ.get("OCR_RANGES", "") or "").strip()
        if _r:
            ocr.set_ranges(int(_r) if _r.isdigit() else _r)
    except Exception:
        pass
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
# 页面没加载好（验证码图 src 空 / 按钮禁用 loading）时的整页刷新重试上限
MAX_PAGE_RELOADS = 3

class _ClaimStuck(Exception):
    """领取页操作卡死（按钮禁用/页面卡加载等），需刷新页面并重跑整个领取流程"""
    pass

# ---- 任务清单补完：并发防重 / 任务记录上限 / 区与域名规范化 ----
MAX_JOBS_KEPT = 20          # JOBS 内存只保留最近 20 条完成记录，防泄漏
_ACCOUNT_RUNNING = {}       # username -> job_id（该账号正在被哪个任务操作）
_ACCOUNT_RUNNING_LOCK = threading.Lock()

def _num_to_cn(n):
    """阿拉伯数字转中文数字（1→一，10→十，12→十二，101→一百零一）；超范围原样返回"""
    _d = "零一二三四五六七八九"
    if not isinstance(n, int) or n <= 0 or n >= 1000:
        return str(n)
    if n < 10:
        return _d[n]
    if n < 20:
        return "十" + (_d[n % 10] if n % 10 else "")
    if n < 100:
        return _d[n // 10] + "十" + (_d[n % 10] if n % 10 else "")
    h = _d[n // 100] + "百"
    t = n % 100
    if t == 0:
        return h
    if t < 10:
        return h + "零" + _d[t]
    return h + _num_to_cn(t)

def _normalize_region(r):
    """把「4区」「4 区」「第4区」等数字写法统一为汉字「四区」；已是汉字/其他原样返回"""
    if r is None:
        return r
    s = str(r).strip()
    import re as _re
    m = _re.match(r"^第?(\d+)\s*区$", s)
    if not m:
        return s
    return _num_to_cn(int(m.group(1))) + "区"

def _normalize_domain(d):
    """剥离协议/路径/查询/尾斜杠，只留 host[:port]（防拼出 https://http://xxx）"""
    if not d:
        return d
    s = str(d).strip()
    import re as _re
    s = _re.sub(r"^https?://", "", s, flags=_re.I)
    s = s.split("/")[0].split("?")[0].strip()
    return s

def _cleanup_old_jobs():
    """任务记录只保留最近 MAX_JOBS_KEPT 条已完成记录（防内存泄漏）"""
    try:
        with JOBS_LOCK:
            _done = [(jid, j.get("started") or 0) for jid, j in JOBS.items()
                     if j.get("status") in ("done", "error", "cancelled")]
            if len(_done) > MAX_JOBS_KEPT:
                _done.sort(key=lambda x: x[1])  # 最旧的在前
                for jid, _ in _done[:len(_done) - MAX_JOBS_KEPT]:
                    JOBS.pop(jid, None)
    except Exception:
        pass
# 验证码上下文：OCR 时设置，click 时检查并清空
class _CaptchaCtxProxy:
    """线程隔离的验证码上下文：每个线程一份 dict，并行跑互不串数据。
    保持 dict 接口（__getitem__/__setitem__/get），do_op 等现有代码零改动。"""
    def __init__(self, seed):
        self._seed = dict(seed)
        self._local = threading.local()
    def _d(self):
        v = getattr(self._local, "v", None)
        if v is None:
            v = dict(self._seed)
            self._local.v = v
        return v
    def __getitem__(self, k):
        return self._d()[k]
    def __setitem__(self, k, v):
        self._d()[k] = v
    def get(self, k, d=None):
        return self._d().get(k, d)

captcha_ctx = _CaptchaCtxProxy({
    "active": False,        # 当前是否有等待检查的 captcha
    "image_sel": "",        # 验证码图片选择器
    "input_sel": "",        # 验证码输入框选择器
    "attempts": 0,          # 已重试次数
    "page_reloads": 0,      # 页面刷新重试计数（验证码图 src 空 / 按钮禁用时整页刷新）
    "last_result": None,    # "success" / "failure" / "wrong_pwd" / None —— 给外层轮次循环判断用
})

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

def _pil_to_png_bytes(img):
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def preprocess_gray(img_bytes, scale=2):
    """灰度候选：转灰度 + 放大 scale 倍（小图放大对 ddddocr 提升明显）。PIL 不可用返回 None。"""
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(img_bytes)).convert("L")
        if scale and scale > 1:
            img = img.resize((img.width * scale, img.height * scale), Image.LANCZOS)
        return _pil_to_png_bytes(img)
    except Exception:
        return None

def preprocess_binary2(img_bytes, scale=2):
    """二值化候选：灰度 + 固定阈值 128 + 放大。"""
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(img_bytes)).convert("L")
        img = img.point(lambda x: 255 if x > 128 else 0)
        if scale and scale > 1:
            img = img.resize((img.width * scale, img.height * scale), Image.LANCZOS)
        return _pil_to_png_bytes(img)
    except Exception:
        return None

def preprocess_denoise(img_bytes, scale=2):
    """去噪候选：灰度 + 中值滤波去掉孤立噪点 + 放大。"""
    try:
        from PIL import Image, ImageFilter
        import io
        img = Image.open(io.BytesIO(img_bytes)).convert("L")
        img = img.filter(ImageFilter.MedianFilter(size=3))
        if scale and scale > 1:
            img = img.resize((img.width * scale, img.height * scale), Image.LANCZOS)
        return _pil_to_png_bytes(img)
    except Exception:
        return None

# 验证码识别统计：共享计数（任务内所有 worker 线程合计；任务开始 _reset_ocr_stats，结束 _finalize_ocr_stats）
_ocr_stats = {"total": 0, "ok": 0, "allfail": 0, "badlen": 0, "method_hits": {}}
_ocr_stats_lock = threading.Lock()

def _reset_ocr_stats():
    global _ocr_stats
    with _ocr_stats_lock:
        _ocr_stats = {"total": 0, "ok": 0, "allfail": 0, "badlen": 0, "method_hits": {}}

def _stats_bump(key, n=1):
    with _ocr_stats_lock:
        _ocr_stats[key] = _ocr_stats.get(key, 0) + n

def _stats_method(method_name):
    """记录最终被采用的方法命中数（去掉"×N"投票后缀，记基础方法名）"""
    with _ocr_stats_lock:
        base = method_name.split("×")[0]
        _ocr_stats.setdefault("method_hits", {})
        _ocr_stats["method_hits"][base] = _ocr_stats["method_hits"].get(base, 0) + 1

def _finalize_ocr_stats(emit):
    """任务结束时汇总验证码识别统计：emit 汇总行 + 落盘（最近一次 + 历史追加，断联也能查）"""
    with _ocr_stats_lock:
        st = dict(_ocr_stats)
    if not st.get("total"):
        return   # 一轮都没识别到验证码 → 不写空统计文件
    total = st.get("total", 0) or 0
    ok = st.get("ok", 0) or 0
    stats = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": total,
        "ok": ok,
        "rate": round(ok * 100.0 / total, 1) if total else 0.0,
        "allfail": st.get("allfail", 0) or 0,
        "badlen": st.get("badlen", 0) or 0,
        "method_hits": st.get("method_hits", {}) or {},
    }
    try:
        emit("📊 验证码识别统计：成功 {ok}/{total}（{rate}%）｜全失败 {allfail}｜长度异常 {badlen}｜方法命中 {hits}".format(
            ok=stats["ok"], total=stats["total"], rate=stats["rate"],
            allfail=stats["allfail"], badlen=stats["badlen"],
            hits=json.dumps(stats["method_hits"], ensure_ascii=False)), "info")
        with open(OCR_STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        with open(OCR_STATS_HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(stats, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[WARN] 写 OCR 统计失败: {e}", flush=True)

def ocr_with_variants(img_bytes, emit=None):
    """多候选 OCR：原图 / 灰度 / 二值化 / 去噪 → 4-5 位长度校验 + 一致性投票。
    返回 (text, method)；多个方法结果一致时 method 带次数（如"灰度×2"）更可信。"""
    _stats_bump("total")
    variants = [("原图", img_bytes)]
    for name, fn in (("灰度", preprocess_gray), ("二值化", preprocess_binary2), ("去噪", preprocess_denoise)):
        b = fn(img_bytes)
        if b is not None:
            variants.append((name, b))
    candidates = []
    for name, b in variants:
        t = do_ocr_once(b, emit)
        if t is not None:
            candidates.append((t, name))
    if not candidates:
        _stats_bump("allfail")
        return None, None
    good = [(t, m) for t, m in candidates if is_valid_captcha_text(t)]
    if good:
        # 一致性投票：相同结果出现 ≥2 次优先（多方法一致更可信）
        from collections import Counter
        cnt = Counter(t for t, _ in good)
        top_t, top_n = cnt.most_common(1)[0]
        if top_n >= 2:
            m = next(m for t, m in good if t == top_t)
            _stats_bump("ok")
            _stats_method(m)
            return top_t, m + "×" + str(top_n)
        _stats_bump("ok")
        _stats_method(good[0][1])
        return good[0]
    _stats_bump("badlen")
    return candidates[0]

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
    # 第一次点击换图（被弹窗挡住 → 立即关掉重试）
    try:
        _safe_click(page, image_sel, emit, timeout=15000)
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
                _safe_click(page, image_sel, emit, timeout=15000)
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
    全部走模拟人为操作，绝不优先 remove()：
      1) 模拟点击关闭按钮（.close / data-dismiss / 按钮文字"关闭/确定/知道了/OK"）
      2) 没按钮 → 模拟点击弹窗背景 backdrop（真人点弹窗外区域关闭）
      3) 再不行 → 模拟按 ESC（真人也会按 ESC 关弹窗）
      4) 以上全无效才强制清理兜底（极罕见，打日志说明）
    原因：remove() 跳过 Bootstrap 状态机，会破坏网站后续操作（人工操作走正常流程就没事）；
    关闭后只清理"残留遮罩/body 锁"这类状态残留（否则 z-index:1050 僵尸遮罩会拦截后续点击）。"""
    try:
        for _attempt in range(2):  # 最多两轮：模拟操作 → 等动画 → 未关再试
            result = page.evaluate("""() => {
                const steps = [];
                const modal = document.querySelector('.modal.show, .modal.fade.show');
                // 1) 模拟点击关闭按钮
                let closeBtn = document.querySelector(
                    '.modal.show .close, .modal.show [data-dismiss="modal"], .modal.show [data-bs-dismiss="modal"]'
                );
                if (!closeBtn) {
                    const btns = Array.from(document.querySelectorAll('.modal.show button, .modal.show .btn'));
                    closeBtn = btns.find(b => /关闭|确定|知道了|好的|确认|ok|close|cancel/i.test((b.textContent || '').trim())) || null;
                }
                if (closeBtn) { closeBtn.click(); steps.push('点击关闭按钮'); }
                else {
                    // 2) 模拟点击背景（真人点弹窗外区域关闭）
                    const backdrop = document.querySelector('.modal-backdrop.show, .modal-backdrop');
                    if (backdrop) { backdrop.click(); steps.push('点击背景关闭'); }
                    // 3) 模拟按 ESC
                    else if (modal) {
                        const ev = new KeyboardEvent('keydown', {
                            key: 'Escape', code: 'Escape', keyCode: 27, which: 27,
                            bubbles: true, cancelable: true
                        });
                        modal.dispatchEvent(ev);
                        document.dispatchEvent(ev);
                        steps.push('按 ESC');
                    }
                    // 4) 兜底：真没有可模拟操作的弹窗元素
                    else { steps.push('无弹窗元素'); }
                }
                return { steps, modalStill: !!document.querySelector('.modal.show, .modal.fade.show') };
            }""")
            if result and result.get("steps") and emit:
                emit(f"  [弹窗] {', '.join(result['steps'])}")
            time.sleep(0.35)  # 让 Bootstrap 完成 fade-out 动画
            if result and not result.get("modalStill"):
                break
        # 弹窗已关：清理残留遮罩/body 锁（状态残留，不是关闭动作；僵尸遮罩会拦截后续点击）
        r2 = page.evaluate("""() => {
            let n = 0;
            document.querySelectorAll('.modal-backdrop').forEach(m => { m.remove(); n++; });
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
            return n;
        }""")
        if r2 and emit:
            emit(f"  [弹窗] 清理残留遮罩 × {r2}")
    except Exception as e:
        if emit:
            emit(f"  ⚠ 关弹窗异常: {e}", "warn")

def _modal_visible(page):
    """页面是否有可见 Bootstrap 弹窗（modal.show）"""
    try:
        return bool(page.evaluate("() => !!document.querySelector('.modal.show, .modal.fade.show')"))
    except Exception:
        return False

def _close_modal_if_any(page, emit):
    """识别到弹窗挡住操作 → 立即模拟点击关闭。返回是否处理过弹窗。"""
    try:
        if not _modal_visible(page):
            return False
    except Exception:
        return False
    close_captcha_modal(page, emit)
    return True

def _safe_click(page, selector, emit, timeout=15000):
    """点击前先关弹窗；被弹窗挡 → 关掉重试；按钮禁用（页面卡 loading）→ 刷新页面重试（上限 MAX_PAGE_RELOADS 次）"""
    for _i in range(MAX_PAGE_RELOADS + 1):
        _close_modal_if_any(page, emit)
        try:
            page.click(selector, timeout=timeout)
            return
        except Exception as e:
            msg = str(e)
            if "intercepts pointer events" in msg:
                # 弹窗挡住 → 上面已尝试关，再试一次
                if _close_modal_if_any(page, emit):
                    time.sleep(0.3)
                    continue
                raise
            if "element is not enabled" in msg:
                # 按钮禁用（proxy-btn-loading 等页面卡加载）→ 抛给领取流程统一处理：
                # 刷新页面后重跑整个领取流程（重新选角色→加购→提交）。只重试点同一按钮没用，
                # 因为刷新后购物车/角色状态已丢失（任务1）
                raise _ClaimStuck(f"{selector} 按钮禁用（页面可能卡加载）")
            raise


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
            # 页面没加载好（验证码图 src 为空）→ 刷新整个页面重试（最多 MAX_PAGE_RELOADS 次）
            try:
                _src_empty = not (page.eval_on_selector(image_sel, "el => el.getAttribute('src') || ''") or "")
            except Exception:
                _src_empty = False
            if _src_empty:
                captcha_ctx["page_reloads"] += 1
                if captcha_ctx["page_reloads"] > MAX_PAGE_RELOADS:
                    emit(f"  ✗ 刷新页面 {MAX_PAGE_RELOADS} 次验证码图仍为空，放弃本次 OCR", "error")
                    return None, None
                emit(f"  ⚠ 验证码图 src 为空（页面未加载完整），刷新页面重试（第 {captcha_ctx['page_reloads']}/{MAX_PAGE_RELOADS} 次）", "warn")
                try:
                    page.reload(wait_until="commit")
                except Exception:
                    pass
                time.sleep(1.5)
                total_waits = 0
                click_retry = 0
                continue
            if total_waits < 3:
                emit(f"  ⚠ 验证码图未加载完成（naturalWidth=0），延 1s 再等（第 {total_waits}/3 次）", "warn")
                time.sleep(1.0)
            else:
                # 3 次 wait 都未加载——点击验证图刷新
                if click_retry < MAX_CLICK_RETRY:
                    click_retry += 1
                    emit(f"  ⚠ 验证码图 3 次 wait 未加载，点击图刷新（第 {click_retry}/{MAX_CLICK_RETRY} 次）", "warn")
                    try:
                        _safe_click(page, image_sel, emit, timeout=15000)
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
    # 多候选 OCR：原图/灰度/二值化/去噪 → 4-5 位长度校验 + 一致性投票
    text, method = ocr_with_variants(img_bytes, emit)
    if text is None:
        emit("  ✗ OCR 全部失败", "error")
        return None, None
    if is_valid_captcha_text(text):
        emit(f"  ✓ OCR 识别 ({method}): {text}")
        return text, method
    # 没有 4-5 位的——按用户要求：刷图重试，最多 3 次
    text_bad, method_bad = text, method
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
        text2, method2 = ocr_with_variants(img_bytes2, emit)
        if text2 is None:
            continue
        if is_valid_captcha_text(text2):
            emit(f"  ✓ OCR 识别 ({method2}): {text2}（刷图 {retry_n} 次后成功）")
            return text2, method2
        text_bad, method_bad = text2, method2
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
                page.goto(url, timeout=30000, wait_until="commit")
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
def _cycle_due(start_str, last_str, cycle_days, next_str=""):
    """周/月周期判定（要求3）：
    - next（服务器上限返回的下次可用时间）非空 → 今天 >= next 才跑（优先于其它）
    - 起始时间为空 → 每天跑（True）
    - 距起始时间不足一个周期 → 未到首期（False）
    - 从未成功过 → 到点即跑（True）
    - 上次成功距今满一个周期 → 跑（True，含错过补跑：跑完会重算下次周期）
    - 否则（本期已跑过）→ False
    """
    from datetime import date
    if (next_str or "").strip():
        try:
            return date.today() >= date.fromisoformat((next_str or "").strip())
        except Exception:
            pass  # next 解析失败 → 走下面的原逻辑
    if not (start_str or "").strip():
        return True
    try:
        s = date.fromisoformat((start_str or "").strip())
        t = date.today()
        if (t - s).days < cycle_days:
            return False
        if not (last_str or "").strip():
            return True
        l = date.fromisoformat((last_str or "").strip())
        return (t - l).days >= cycle_days
    except Exception:
        return True

def _account_active_cdks(acc, region, global_active):
    """要求3：某账号当天要跑的 CDK 列表 = 账号日码（每天）+ 周码（周周期到点）+ 月码（月周期到点）+ 全局 once（未用）"""
    out = []
    username = acc.get("username", "?")
    codes = db_get_account_cdks(username)
    cycle = db_get_cdk_cycle(username, region or "")
    if codes["daily"]:
        out.append({"code": codes["daily"], "schedule": "daily", "used": False, "account_cdk": True})
    if codes["weekly"] and _cycle_due(cycle.get("weekly_start", ""), cycle.get("weekly_last", ""), 7, cycle.get("weekly_next", "")):
        out.append({"code": codes["weekly"], "schedule": "weekly", "used": False, "account_cdk": True})
    if codes["monthly"] and _cycle_due(cycle.get("monthly_start", ""), cycle.get("monthly_last", ""), 30, cycle.get("monthly_next", "")):
        out.append({"code": codes["monthly"], "schedule": "monthly", "used": False, "account_cdk": True})
    for c in global_active:
        if c.get("schedule") == "once":
            out.append(c)
    return out

def _global_cdk_limited_by_next(acc, region, cdk, emit=None):
    """全局池跑 CDK 前过滤（要求3增强）：若该码是账号的周/月码，且该账号该区命中过上限（有下次时间）且今天未到 → True（跳过）。
    日码/一次性码/不是账号的周月码/未命中上限 → False（照跑）"""
    if not cdk or cdk.get("schedule") == "once":
        return False
    code = str(cdk.get("code", "") or "").strip()
    if not code:
        return False
    try:
        username = acc.get("username", "?")
        codes = db_get_account_cdks(username)
        kind = None
        if code == str(codes.get("weekly", "") or "").strip():
            kind = "weekly"
        elif code == str(codes.get("monthly", "") or "").strip():
            kind = "monthly"
        if not kind:
            return False  # 不是该账号的周/月码，不受限
        cyc = db_get_cdk_cycle(username, region or "")
        nx = (cyc.get(kind + "_next") or "").strip()
        if not nx:
            return False  # 没命中过上限，照跑
        from datetime import date
        try:
            if date.today() < date.fromisoformat(nx):
                if emit:
                    emit(f"  ⏭ 跳过 {kind}CDK[{code[:10]}]：该账号已达上限，下次 {nx} 再跑")
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False

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
# 上限提示里的日期格式（如「2026年09月10日刷新次数」）：中文年月日 + 常见分隔 ISO 格式
import re as _re2
_NEXT_DATE_RE_CN = _re2.compile(r"(\d{4})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日")
_NEXT_DATE_RE_ISO = _re2.compile(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})")
# 错误关键词：任一命中 → 视为失败
_ERROR_KEYWORDS = ["错误", "失败", "无效", "已使用", "已兑换", "失效", "限兑", "校验码", "captcha", "incorrect", "不存在"]
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
        # 密码脱敏：密码框不输出明文（日志可导出，防泄露）
        if "password" in selector.lower() or "pwd" in selector.lower():
            _show = (value[:1] + "****") if value else "(空)"
            emit(f"  ✓ 填: {selector} = {_show}（已脱敏）")
        else:
            emit(f"  ✓ 填: {selector} = {value[:30]}{'...' if len(value)>30 else ''}")

    elif action == "click":
        page.wait_for_selector(selector, timeout=10000)
        _safe_click(page, selector, emit, timeout=15000)
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
        "logPath": _new_job_log_path(job_id),   # 任务独立日志文件
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
        _msg = str(msg)
        extra = None
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job: return
            job["log"].append({"time": time.time(), "msg": _msg, "level": level})
            # 日志增强：错误级/含"错误|失败"关键词的日志，若正处异常块则附带完整 traceback，方便排查
            if level == "error" or ("错误" in _msg) or ("失败" in _msg):
                _ei = sys.exc_info()
                if _ei and _ei[0] is not None:
                    import traceback as _tb
                    _full = _tb.format_exception(*_ei)
                    _joined = "".join(_full).strip()
                    if _joined and _joined not in _msg:
                        job["log"].append({"time": time.time(), "msg": "\n" + _joined, "level": "error"})
                        extra = _joined
        print(f"[{job_id[:8]}] {_msg}", flush=True)
        if extra:
            print(f"[{job_id[:8]}] {extra}", flush=True)
        # 任务独立日志文件（锁外写，避免死锁/阻塞）
        _job_log_append(job_id, _msg, level)
        if extra:
            _job_log_append(job_id, extra, "error")
        # 唤醒 SSE 等待的客户端
        with job["cond"]:
            job["cond"].notify_all()

    def th():
        _reset_ocr_stats()
        try:
            _run_job_impl(job_id, config, emit)
            _finalize_ocr_stats(emit)
        except Exception as e:
            import traceback
            _finalize_ocr_stats(emit)
            emit(f"✗ 异常: {e}", "error")
            emit(traceback.format_exc(), "error")
            JOBS[job_id]["status"] = "error"
        _cleanup_old_jobs()

    threading.Thread(target=th, daemon=True).start()


def _build_scheduled_config():
    """组装定时任务/手动 now 的执行配置：页面配置 + 全部账号 + 可用 CDK。
    配置来源：LAST_CONFIG（内存，最近一次前端保存/执行）为空时回退持久化文件 autofill_config.json。
    区分 once / daily：每日 CDK 只能 used=0 的才跑；一次性 CDK 不论 used 都跑。"""
    cfg = json.loads(json.dumps(LAST_CONFIG)) if LAST_CONFIG else load_persisted_config()
    cfg = dict(cfg or {})
    cfg.pop("schedule", None)  # 调度信息不传给执行逻辑
    # 定时/now = 全部自动化：强制登录+领取+CDK 全跑，不受前端最近一次勾选影响
    cfg["runTargets"] = ["login", "claim", "cdk"]
    cfg["accounts"] = db_get_accounts(include_password=True)
    # 要求3：定时任务/now 用账号级日/周/月码（每账号各自生成），全局 CDK 池只取一次性（once）；
    # 全局 daily 池由账号级日/周/月码体系接管，不再在定时任务里使用
    cfg["cdkList"] = []
    for c in db_get_cdks():
        if c["once"]:
            cfg["cdkList"].append({"code": c["code"], "schedule": "once", "used": False, "_db_id": c["id"]})
    cfg["accountCdks"] = True
    return cfg


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
                        "logPath": _new_job_log_path(jid),   # 任务独立日志文件
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
                    cfg_to_run = _build_scheduled_config()
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
                                _job_log_append(jid, msg, level)
                                with job["cond"]:
                                    job["cond"].notify_all()
                            _reset_ocr_stats()
                            _run_job_impl(jid, cfg_to_run, _emit)
                            _finalize_ocr_stats(_emit)
                        except Exception as e:
                            import traceback
                            try: _finalize_ocr_stats(_emit)
                            except Exception: pass
                            print(f"[scheduler] 任务异常: {e}", flush=True)
                            print(traceback.format_exc(), flush=True)
                            JOBS[jid]["status"] = "error"
                        _cleanup_old_jobs()
                    threading.Thread(target=_sched_th, daemon=True).start()
        except Exception as e:
            print(f"[scheduler] 异常: {e}", flush=True)
        time.sleep(30)


# ---------- 区（region）执行 ----------
# 页面配置里代表"区"的下拉框选择器（CDK 页 #server、领取页 #giftServer）。
# 站点选择器变化时，同步改这里。
REGION_SELECTORS = ("#server", "#giftServer")

def _override_region_selects(pages_cfg, region):
    """返回 pages 的深拷贝：把区下拉框（REGION_SELECTORS）的值替换为指定区。
    region 为空或 pages 结构不对时原样返回。"""
    if not region or not isinstance(pages_cfg, dict):
        return pages_cfg
    out = copy.deepcopy(pages_cfg)
    for pobj in out.values():
        if not isinstance(pobj, dict):
            continue
        for op in pobj.get("actions", []):
            if isinstance(op, dict) and op.get("type") == "select" and op.get("selector") in REGION_SELECTORS:
                op["value"] = region
    return out


def _normalize_run_targets(config):
    """登录页与领取页强制绑定：含任一个就补另一个；为空时默认三个全跑。
    绑定规则：领取页必须带登录页（领取依赖已登录），登录页必须带领取页（登录后必走领取）。"""
    run_targets = list((config or {}).get("runTargets") or [])
    if not run_targets:
        run_targets = ["login", "claim", "cdk"]
    if "login" in run_targets or "claim" in run_targets:
        if "login" not in run_targets:
            run_targets.insert(0, "login")
        if "claim" not in run_targets:
            run_targets.append("claim")
    return run_targets, config


def _run_job_impl(job_id, config, emit):
    """要求4 并发入口：按账号分组并发执行；并发=1 或单账号时走原串行逻辑（_run_job_impl_serial）。"""
    if not playwright:
        emit("✗ Playwright 未安装，无法执行", "error")
        JOBS[job_id]["status"] = "error"
        return

    accounts = config.get("accounts", [])
    if not accounts:
        emit("✗ 没有账号", "error")
        JOBS[job_id]["status"] = "error"
        return

    cdk_list = config.get("cdkList", [])
    pages_cfg = config.get("pages", {})
    domain = _normalize_domain(config.get("domain", ""))
    browser_type = (config.get("browserType") or os.environ.get("BROWSER_TYPE") or "msedge").lower()
    launch_kwargs = {
        "headless": config.get("headless", True),  # 改回 True
        "args": ["--no-sandbox", "--disable-blink-features=AutomationControlled"],
    }
    if browser_type in ("msedge", "chrome"):
        launch_kwargs["channel"] = browser_type
    run_targets, _ = _normalize_run_targets(config)

    concurrency = get_concurrency()
    if concurrency < 1:
        concurrency = 1
    # 按账号分组（同一账号的多区在组内顺序跑，不并发登同一账号）
    groups = []
    group_map = {}
    for acc in accounts:
        k = id(acc)
        g = group_map.get(k)
        if g is None:
            g = {"account": acc}
            group_map[k] = g
            groups.append(g)
    worker_count = min(concurrency, len(groups))
    emit(f"🧵 并发数: {concurrency}，账号: {len(groups)} 个，工作线程: {worker_count}")

    # 并发=1：走原串行逻辑，日志与之前完全一致
    if worker_count == 1:
        _run_job_impl_serial(job_id, config, emit, quiet=False)
        return

    # 并行：一次性 CDK 按线程切分（互斥不重复），每日 CDK 每个线程共享全部
    active_cdks = [c for c in cdk_list if cdk_active_today(c)]
    emit(f"📋 今日活跃 CDK: {len(active_cdks)} 个（总计 {len(cdk_list)}）")
    if active_cdks:
        for c in active_cdks:
            emit(f"  - [{c.get('schedule')}] {c.get('code', '')[:20]}...")
    emit(f"🌐 启动浏览器: {browser_type} (headless={launch_kwargs['headless']})")
    emit(f"🎯 执行目标: {', '.join(run_targets)}")

    once_cdks = [c for c in active_cdks if c.get("schedule") == "once"]
    daily_cdks = [c for c in active_cdks if c.get("schedule") != "once"]

    base_cfg = {
        "domain": domain,
        "pages": pages_cfg,
        "runTargets": run_targets,
        "browserType": config.get("browserType"),
        "headless": config.get("headless", True),
        "accountCdks": bool(config.get("accountCdks")),   # 修复：账号级日/周/月码模式必须传给 worker，否则定时/now 的 CDK 池只剩 once，一空就一个都不跑
    }

    errors = []
    errors_lock = threading.Lock()

    def _worker(wi, wgroups):
        w_cdks = daily_cdks + list(once_cdks[wi::worker_count])
        for g in wgroups:
            gcfg = dict(base_cfg)
            gcfg["accounts"] = [g["account"]]
            gcfg["cdkList"] = list(w_cdks)
            try:
                _run_job_impl_serial(job_id, gcfg, emit, quiet=True)
            except Exception as e:
                with errors_lock:
                    errors.append(str(e))
                emit(f"✗ 线程异常（账号 {g['account'].get('username', '?')}）: {e}", "error")

    threads = []
    for wi in range(worker_count):
        t = threading.Thread(target=_worker, args=(wi, groups[wi::worker_count]), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    # 汇总结果
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        cancelled = bool(job and job.get("cancel_requested"))
    if cancelled:
        with JOBS_LOCK:
            if job: job["status"] = "cancelled"
        return  # 取消不标 CDK（与原逻辑一致）
    if errors and len(errors) >= worker_count:
        with JOBS_LOCK:
            if job: job["status"] = "error"
        emit("✗ 全部工作线程异常，任务失败", "error")
        return
    if errors:
        emit(f"⚠ {len(errors)} 个工作线程异常（其余正常），任务完成", "warn")

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            job["status"] = "done"
            job["result"] = "completed"
    emit("\n✅ 全部完成")
    # 持久化 CDK 状态到数据库（各 worker 已标记各自子集，这里兜底全量）
    try:
        n_marked = 0
        for cdk in cdk_list:
            if cdk.get("schedule") == "once":
                if db_mark_cdk_used(cdk.get("code", "")):
                    n_marked += 1
        if n_marked:
            emit(f"  ✓ {n_marked} 个一次性 CDK 已标已用")
    except Exception as e:
        emit(f"  ⚠ 保存 CDK 状态失败: {e}", "warn")
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            job["updatedConfig"] = config


def _run_job_impl_serial(job_id, config, emit, quiet=False):
    # ---- 卡死看门狗：每个账号单元 N 秒无日志视为卡死（默认 180s，可用环境变量 ACCOUNT_STALL_TIMEOUT 调），
    #       watchdog close 当前页打断卡住的 Playwright 调用，重开页面 + 进下一轮 ----
    ACCOUNT_STALL_TIMEOUT = int(os.environ.get("ACCOUNT_STALL_TIMEOUT", "180") or "180")
    _stall = {"ts": time.time(), "killed": False, "timed_out": False, "lock": threading.Lock()}
    _orig_emit = emit
    _cancel_raised = [False]
    def emit(msg, level="info"):
        with _stall["lock"]:
            _stall["ts"] = time.time()
        # 取消检查：任何一步日志输出时若已请求取消 → 立即中断当前操作（防重入，避免 except 路径递归）
        if not _cancel_raised[0]:
            with JOBS_LOCK:
                _j = JOBS.get(job_id)
                if _j and _j.get("cancel_requested"):
                    _cancel_raised[0] = True
                    try:
                        _orig_emit("⏹ 收到取消请求，正在停止当前操作...", "warn")
                    except Exception:
                        pass
                    raise _JobCancelled()
        _orig_emit(msg, level)

    def _start_stall_watchdog(page_ref):
        """每账号单元一个 daemon 线程：N 秒无日志 → close 当前 page，让卡死的调用抛异常"""
        _stall["killed"] = False
        _stall["timed_out"] = False
        with _stall["lock"]:
            _stall["ts"] = time.time()
        def _wd():
            time.sleep(ACCOUNT_STALL_TIMEOUT)
            with _stall["lock"]:
                if _stall["killed"]:
                    return
                _stall["timed_out"] = True
                _stall["killed"] = True
            try:
                page_ref[0].close()
            except Exception:
                pass
        t = threading.Thread(target=_wd, daemon=True)
        t.start()
        return t

    if not playwright:
        emit("✗ Playwright 未安装，无法执行", "error")
        JOBS[job_id]["status"] = "error"
        return

    accounts = config.get("accounts", [])
    cdk_list = config.get("cdkList", [])
    pages_cfg = config.get("pages", {})
    domain = config.get("domain", "")

    # 展开 账号×区：一个账号有多个区（regions 列表）就跑多遍，每遍一个区；
    # 没有区记录 → 用页面配置里的默认值（跑一遍）
    run_units = []
    for _acc in accounts:
        _regs = _acc.get("regions")
        # 兼容旧账号：只有单字段 region（字符串）时也按区跑；两者都空 → 用页面配置默认值
        if not isinstance(_regs, list) or not _regs:
            _r0 = _acc.get("region")
            _regs = [_r0] if _r0 else []
        if _regs:
            for _r in _regs:
                run_units.append({"account": _acc, "region": _normalize_region(str(_r))})
        else:
            run_units.append({"account": _acc, "region": None})

    # 筛选今日活跃 CDK
    active_cdks = [c for c in cdk_list if cdk_active_today(c)]
    # 要求3：账号级 CDK 模式（定时任务/now 用），每账号按自己的日/周/月码生成 CDK
    account_cdks_mode = bool(config.get("accountCdks"))
    if not quiet:
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

    if not quiet:
        emit(f"🌐 启动浏览器: {browser_type} (headless={launch_kwargs['headless']})")

    # 选择要执行的页面（前端勾选；登录<->领取强制绑定，默认三个全跑）
    run_targets, _ = _normalize_run_targets(config)
    if not quiet:
        emit(f"🎯 执行目标: {', '.join(run_targets)}")

    # 先试启动浏览器，失败给出明确提示
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**launch_kwargs)
            try:
                # 阻断第三方 analytics 脚本（devbox 数据中心 IP 容易被这些 CDN 限速，
                # 它们又是同步 script，会拖慢 DCL + 后续 click 等元素；阻断对业务无副作用）
                def _route(route):
                    url = route.request.url
                    if any(h in url for h in [
                        "cloudflareinsights.com",
                        "google-analytics.com",
                        "googletagmanager.com",
                        "facebook.net",
                        "doubleclick.net",
                    ]):
                        route.abort()
                    else:
                        route.continue_()
                # 监听 JS 弹窗：emit 日志后自动 accept，避免卡住任务
                def _on_dialog(dialog):
                    try:
                        emit(f"  ⚠ 弹窗 [{dialog.type}]: {dialog.message}", "warn")
                    except Exception:
                        pass
                    try: dialog.accept()
                    except Exception: pass
                def _make_page(browser):
                    _ctx = browser.new_context(
                        viewport={"width": 1280, "height": 800},
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    )
                    _pg = _ctx.new_page()
                    _pg.route("**/*", _route)
                    # 反爬：隐藏 webdriver
                    _pg.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
                    _pg.on("dialog", _on_dialog)
                    return _pg
                page = _make_page(browser)

                # 根据 run_targets 计算总步骤数
                total_steps = 0
                if "login" in run_targets: total_steps += len(run_units)
                if "claim" in run_targets: total_steps += len(run_units)
                if "cdk" in run_targets:
                    if account_cdks_mode:
                        # 账号级模式：每 unit 最多 3 个账号码 + once 池数量
                        once_n = len([c for c in active_cdks if c.get("schedule") == "once"])
                        total_steps += len(run_units) * (3 + once_n)
                    else:
                        total_steps += len(run_units) * len(active_cdks)
                done = 0

                # 多轮重试：每个轮次只跑"验证码未成功"的账号，全部成功或达轮次上限才停
                # 业务失败（"失败: 1 个"等）不算验证码失败，不会进下一轮
                MAX_CAPTCHA_ROUNDS = 5
                round_num = 1
                remaining_units = list(run_units)  # 复制：每轮从头遍历失败的单元（账号×区）

                while remaining_units and round_num <= MAX_CAPTCHA_ROUNDS:
                    if round_num > 1:
                        emit(f"\n===== 第 {round_num} 轮：重试 {len(remaining_units)} 个验证码失败的单元 =====")
                    next_remaining = []

                    for unit in remaining_units:
                        acc = unit["account"]
                        region = unit["region"]
                        acc_user = acc.get("username", "?")
                        # 账号级防重：同一账号正在被其他任务操作 → 本轮跳过（防两批入口同时跑同一账号）
                        with _ACCOUNT_RUNNING_LOCK:
                            _holder = _ACCOUNT_RUNNING.get(acc_user)
                            if _holder and _holder != job_id:
                                emit(f"  ⚠ 账号 {acc_user} 正在被其他任务（{_holder[:8]}）操作，本轮跳过", "warn")
                                continue
                            _ACCOUNT_RUNNING[acc_user] = job_id
                        # 每账号开始前重置验证码状态
                        captcha_ctx["last_result"] = None
                        captcha_ctx["attempts"] = 0
                        captcha_ctx["page_reloads"] = 0
                        captcha_ctx["active"] = False
                        _check_pause(job_id, emit)
                        _check_cancel(job_id, emit)
                        # 卡死看门狗：本单元开始计时，N 秒无日志 → watchdog 关页打断
                        _page_ref = [page]
                        _start_stall_watchdog(_page_ref)
                        # 按区覆盖页面配置里的区下拉框；无区 → 用页面配置默认值
                        pages_run = _override_region_selects(pages_cfg, region)
                        if region:
                            emit(f"\n=== 账号: {acc_user}（区: {region}）===")
                        else:
                            emit(f"\n=== 账号: {acc_user} ===")

                        if "login" in run_targets:
                            page_obj = pages_run.get("login", {})
                            if not page_obj.get("actions"):
                                emit("  (未配置登录页操作，跳过登录)", "warn")
                            else:
                                try:
                                    target = page_obj.get("urlPattern", "https://" + domain + "/player/login")
                                    if not target.startswith("http"):
                                        target = "https://" + domain + target
                                    page.goto(target, timeout=30000, wait_until="commit")
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
                                    # 卡死看门狗：登录卡死 → 重开页面 + 进下一轮
                                    with _stall["lock"]:
                                        _stall["killed"] = True
                                        _timed_out = _stall.get("timed_out", False)
                                    if _timed_out:
                                        _stall["timed_out"] = False
                                        emit(f"  ⚠ 账号 {acc_user}（区: {region or '默认'}）登录卡死，已重开页面，下轮重试", "warn")
                                        try: page.close()
                                        except Exception: pass
                                        page = _make_page(browser)
                                        _page_ref[0] = page
                                        next_remaining.append(unit)
                                    continue
                                done += 1

                        if "claim" in run_targets:
                            # 登录<->领取强制绑定：规范化后 claim 必有 login，直接执行
                            page_obj = pages_run.get("claim", {})
                            if not page_obj.get("actions"):
                                emit("  (未配置领取页操作，跳过)", "warn")
                            else:
                                # 领取页 #giftServer 等不到 → 刷新页面重试，最多 3 次
                                for _try_n in range(1, 4):
                                    try:
                                        # claim 默认 autoGoto=False（不跳转，登录后已在那）
                                        if page_obj.get("autoGoto", False):
                                            target = page_obj.get("urlPattern", "")
                                            if target:
                                                if not target.startswith("http"):
                                                    target = "https://" + domain + target
                                                page.goto(target, timeout=30000, wait_until="commit")
                                                emit(f"  打开: {target}")
                                            else:
                                                emit("  (claim 设了 autoGoto 但没配 urlPattern，跳过 goto)", "warn")
                                        # 不管跳不跳，都跑动作
                                        for op in page_obj.get("actions", []):
                                            _check_pause(job_id, emit)
                                            _check_cancel(job_id, emit)
                                            do_op(page, op, acc, None, emit)
                                        time.sleep(0.5)
                                        break
                                    except Exception as e:
                                        if "#giftServer" in str(e) and _try_n < 3:
                                            try:
                                                page.reload(wait_until="commit")
                                            except Exception:
                                                pass
                                            emit(f"  ⚠ 领取页 #giftServer 等不到（第 {_try_n}/3 次），已刷新页面重试", "warn")
                                            time.sleep(1)
                                            continue
                                        if isinstance(e, _ClaimStuck) and _try_n < 3:
                                            # 提交按钮禁用/页面卡加载：刷新后重跑整个领取流程（重新选区→获取角色→选角色→加购→提交）
                                            try:
                                                page.reload(wait_until="commit")
                                            except Exception:
                                                pass
                                            emit(f"  ⚠ 领取页卡住（{e}），刷新后重跑领取流程（第 {_try_n}/3 次）", "warn")
                                            time.sleep(1.5)
                                            continue
                                        emit(f"  ✗ 领取失败: {e}", "error")
                                        # 刷新 3 次仍不行（#giftServer 等不到 / 按钮禁用卡死）→ 跟验证码错误一样进下一轮重试
                                        if "#giftServer" in str(e) or isinstance(e, _ClaimStuck):
                                            captcha_ctx["last_result"] = "failure"
                                        break
                                done += 1

                        if "cdk" in run_targets:
                            # 跑 CDK（要求3：账号级模式 = 该账号日/周/月码 + once 池；原模式 = 全局 CDK 池）
                            if account_cdks_mode:
                                unit_cdks = _account_active_cdks(acc, region, active_cdks)
                            else:
                                # 全局池模式：该账号的周/月码若命中过上限且未到期 → 跳过（中间时间不再跑）
                                unit_cdks = []
                                for _c in active_cdks:
                                    if _global_cdk_limited_by_next(acc, region, _c, emit):
                                        continue
                                    unit_cdks.append(_c)
                            for cdk in unit_cdks:
                                _check_pause(job_id, emit)
                                _check_cancel(job_id, emit)
                                page_obj = pages_run.get("cdk", {})
                                if not page_obj.get("actions"):
                                    emit("  (未配置 CDK 页操作，跳过)", "warn")
                                    continue
                                try:
                                    target = page_obj.get("urlPattern", "https://" + domain + "/index/cdk")
                                    if not target.startswith("http"):
                                        target = "https://" + domain + target
                                    page.goto(target, timeout=30000, wait_until="commit")
                                    emit(f"  打开: {target}")
                                    for op in page_obj.get("actions", []):
                                        _check_pause(job_id, emit)
                                        _check_cancel(job_id, emit)
                                        do_op(page, op, acc, cdk, emit)
                                    time.sleep(0.5)
                                    # 要求3：周/月码跑完，命中成功关键词或"上限" → 记录下次周期
                                    # 命中"上限"：尝试提取服务器返回的下次刷新日期（如「2026年09月10日刷新次数」）设为下次可跑时间；
                                    # 提取不到或普通成功：按原逻辑记 last=今天（+7/+30 起算）
                                    if cdk.get("account_cdk") and cdk.get("schedule") in ("weekly", "monthly"):
                                        try:
                                            _st, _dtl = _check_page_error(page, emit)
                                            if _st == "success":
                                                _d = str(_dtl or "")
                                                if "上限" in _d:
                                                    _nx = _extract_next_date(_d)
                                                    if _nx:
                                                        db_set_cdk_cycle_next(acc.get("username", "?"), region or "", cdk["schedule"], _nx)
                                                        emit(f"  ✓ {cdk['schedule']}CDK 达上限，下次 {_nx} 再跑（已自动设置）")
                                                    else:
                                                        _last = db_update_cdk_cycle_last(acc.get("username", "?"), region or "", cdk["schedule"])
                                                        emit(f"  ✓ {cdk['schedule']}CDK 达上限（未识别到日期），下次周期从 {_last} 起算")
                                                else:
                                                    _last = db_update_cdk_cycle_last(acc.get("username", "?"), region or "", cdk["schedule"])
                                                    emit(f"  ✓ {cdk['schedule']}CDK 成功（{_d[:40]}），下次周期从 {_last} 起算")
                                        except Exception as _e:
                                            emit(f"  ⚠ 记录 {cdk['schedule']}CDK 周期失败: {_e}", "warn")
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
                        # 卡死看门狗：本单元结束，停 watchdog；若因超时触发 → 重开页面 + 进下一轮
                        with _stall["lock"]:
                            _stall["killed"] = True
                            _timed_out = _stall.get("timed_out", False)
                        if _timed_out:
                            _stall["timed_out"] = False
                            emit(f"  ⚠ 账号 {acc_user}（区: {region or '默认'}）{ACCOUNT_STALL_TIMEOUT}s 无日志，视为卡死，已重开页面，下轮重试", "warn")
                            try: page.close()
                            except Exception: pass
                            page = _make_page(browser)
                            _page_ref[0] = page
                            next_remaining.append(unit)
                            continue
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
                            emit(f"  ⚠ 账号 {acc_user}（区: {region or '默认'}）验证码失败，加入下一轮重试", "warn")
                            next_remaining.append(unit)
                        elif last == "success":
                            # 任务2：手动/测试入口跑成功 → 自动入库（账号+区），下次执行直接走数据库配置
                            # 定时/now 入口不重复入库（账号本来就在数据库）
                            _trig = (JOBS.get(job_id) or {}).get("trigger")
                            if _trig in ("manual", "test-redeem"):
                                _u = acc.get("username", "")
                                _p = acc.get("password", "")
                                if _u and _p:
                                    try:
                                        _act = db_upsert_account(_u, _p)
                                        _regs = acc.get("regions")
                                        if not isinstance(_regs, list) or not _regs:
                                            _r0 = acc.get("region")
                                            _regs = [_r0] if _r0 else []
                                        if _regs:
                                            db_add_account_regions(_u, _regs)
                                        emit(f"  ✓ 账号 {_u} 执行成功，已自动入库（下次执行直接走数据库配置）", "success")
                                    except Exception as _e:
                                        emit(f"  ⚠ 账号 {_u} 入库失败: {_e}", "warn")
                    # 本轮结束：更新 remaining + round
                    if not next_remaining:
                        emit("\n✅ 所有账号验证码都已通过")
                        remaining_units = []
                    else:
                        remaining_units = next_remaining
                        round_num += 1
                    # 本轮结束：清除本任务标记的账号（下轮重新竞争）
                    with _ACCOUNT_RUNNING_LOCK:
                        for _u in list(_ACCOUNT_RUNNING):
                            if _ACCOUNT_RUNNING[_u] == job_id:
                                del _ACCOUNT_RUNNING[_u]
                if remaining_units:
                    emit(f"\n⚠ 经过 {MAX_CAPTCHA_ROUNDS} 轮，仍有 {len(remaining_units)} 个账号验证码失败: {[u['account'].get('username','?') for u in remaining_units]}", "warn")
            finally:
                try: browser.close()
                except: pass
                # 兜底清除本任务的账号标记（异常中断也不残留）
                with _ACCOUNT_RUNNING_LOCK:
                    for _u in list(_ACCOUNT_RUNNING):
                        if _ACCOUNT_RUNNING[_u] == job_id:
                            del _ACCOUNT_RUNNING[_u]
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
    # - 每日 CDK（schedule != "once"）：不动 used=0，可反复跑
    # - 一次性 CDK（schedule == "once"）：标 used=1，用过的不再 append
    # 注：旧的"删 once"和"daily 标 used"逻辑已移除（避免 daily 池子被锁、once 误删）
    try:
        n_marked = 0
        for cdk in cdk_list:
            if cdk.get("schedule") == "once":
                if db_mark_cdk_used(cdk.get("code", "")):
                    n_marked += 1
        if n_marked:
            emit(f"  ✓ {n_marked} 个一次性 CDK 已标已用")
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

                    if job["status"] in ("done", "error", "cancelled"):
                        _st = job["status"]
                        _msg = "全部完成" if _st == "done" else ("执行失败" if _st == "error" else "任务已取消")
                        self._sse_send({
                            "type": "done",
                            "ok": _st == "done",
                            "cancelled": _st == "cancelled",
                            "msg": _msg,
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
            elif self.path == '/api/accounts':
                # 添加/更新账号（前端 + 添加账号 按钮）
                body = self._read_body()
                ga = (body.get("username") or body.get("game_account") or "").strip()
                gp = (body.get("password") or body.get("game_password") or "").strip()
                if not ga or not gp:
                    return self._json(400, {"error": "账号密码不能为空"})
                regions = body.get("regions")
                action = db_upsert_account(ga, gp, regions if isinstance(regions, list) else None)
                self._json(200, {"ok": True, "action": action})
            elif self.path == '/api/account-regions/query':
                # 查询账号的区（需密码校验，防止乱改他人账号）
                body = self._read_body()
                ga = (body.get("username") or "").strip()
                gp = (body.get("password") or "").strip()
                if not ga or not gp:
                    return self._json(400, {"error": "账号密码不能为空"})
                if not db_verify_account_password(ga, gp):
                    return self._json(200, {"ok": False, "error": "账号不存在或密码不对"})
                row = db_get_account_row(ga)
                regions = _parse_regions(row[3]) if row else []
                self._json(200, {"ok": True, "username": ga, "regions": regions})
            elif self.path == '/api/account-regions/update':
                # 修改账号的区（覆盖式，需密码校验）
                body = self._read_body()
                ga = (body.get("username") or "").strip()
                gp = (body.get("password") or "").strip()
                if not ga or not gp:
                    return self._json(400, {"error": "账号密码不能为空"})
                if not db_verify_account_password(ga, gp):
                    return self._json(200, {"ok": False, "error": "账号不存在或密码不对"})
                new_regions = body.get("regions")
                updated = db_set_account_regions(ga, new_regions if isinstance(new_regions, list) else [])
                self._json(200, {"ok": True, "username": ga, "regions": updated or []})
            elif self.path == '/api/cdk-schedule/query':
                # 要求3：查询账号的 CDK 周期设置（需密码校验，防乱改他人账号）
                body = self._read_body()
                ga = (body.get("username") or "").strip()
                gp = (body.get("password") or "").strip()
                if not ga or not gp:
                    return self._json(400, {"error": "账号密码不能为空"})
                if not db_verify_account_password(ga, gp):
                    return self._json(200, {"ok": False, "error": "账号不存在或密码不对"})
                region = (body.get("region") or "").strip()
                codes = db_get_account_cdks(ga)
                cycle = db_get_cdk_cycle(ga, region)
                self._json(200, {"ok": True, "username": ga, "region": region,
                                 "cdk_daily": codes["daily"], "cdk_weekly": codes["weekly"], "cdk_monthly": codes["monthly"],
                                 "weekly_start": cycle.get("weekly_start", ""), "monthly_start": cycle.get("monthly_start", ""),
                                 "weekly_next": cycle.get("weekly_next", ""), "monthly_next": cycle.get("monthly_next", "")})
            elif self.path == '/api/cdk-schedule/update':
                # 要求3：修改账号的 CDK 码与周/月起始时间（覆盖式，需密码校验）
                body = self._read_body()
                ga = (body.get("username") or "").strip()
                gp = (body.get("password") or "").strip()
                if not ga or not gp:
                    return self._json(400, {"error": "账号密码不能为空"})
                if not db_verify_account_password(ga, gp):
                    return self._json(200, {"ok": False, "error": "账号不存在或密码不对"})
                region = (body.get("region") or "").strip()
                _d = body.get("cdk_daily"); _w = body.get("cdk_weekly"); _m = body.get("cdk_monthly")
                _ws = body.get("weekly_start"); _ms = body.get("monthly_start")
                codes = db_set_account_cdks(ga,
                                            _d if isinstance(_d, str) else None,
                                            _w if isinstance(_w, str) else None,
                                            _m if isinstance(_m, str) else None)
                db_set_cdk_cycle(ga, region,
                                 _ws if isinstance(_ws, str) else None,
                                 _ms if isinstance(_ms, str) else None)
                cycle = db_get_cdk_cycle(ga, region)
                self._json(200, {"ok": True, "username": ga, "region": region,
                                 "cdk_daily": codes["daily"], "cdk_weekly": codes["weekly"], "cdk_monthly": codes["monthly"],
                                 "weekly_start": cycle.get("weekly_start", ""), "monthly_start": cycle.get("monthly_start", ""),
                                 "weekly_next": cycle.get("weekly_next", ""), "monthly_next": cycle.get("monthly_next", "")})
            elif self.path == '/api/cdks':
                # 添加 CDK（前端如有用到）
                body = self._read_body()
                code = (body.get("code") or "").strip()
                if not code:
                    return self._json(400, {"error": "CDK 不能为空"})
                ok = db_add_cdk(code, once=0)
                self._json(200, {"ok": ok})
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
                use_db = body.get("useDb", True)
                # 任务2：开关开时，每个账号优先读数据库配置（区）——有匹配账密用库的区，否则保留前端本地
                if use_db:
                    _accs = []
                    for _a in (cfg.get("accounts") or []):
                        _rec = db_find_account(_a.get("username", ""), _a.get("password", ""))
                        if _rec and _rec.get("regions"):
                            _aa = dict(_a)
                            _aa["regions"] = _rec["regions"]
                            _accs.append(_aa)
                        else:
                            _accs.append(_a)
                    cfg["accounts"] = _accs
                # 任务2：统一走账号级 CDK（每账号日/周/月码 + once 池），不再用前端本地全局池
                cfg["accountCdks"] = True
                jid = uuid.uuid4().hex
                # 保存最新 config 给定时任务用
                global LAST_CONFIG
                LAST_CONFIG = cfg
                run_job(jid, cfg)
                self._json(200, {"job_id": jid})
            elif self.path == '/api/test-redeem':
                # 任务2：测试兑换 = 临时账密 + 账号级日/周/月码（有 db 匹配走 db 区/码，无则前端区+默认码）
                # 结果三分类：账密错→不入库；验证码5轮失败→不入库；成功→serial 已自动入库
                body = self._read_body()
                username = (body.get("username") or "").strip()
                password = (body.get("password") or "").strip()
                if not username or not password:
                    return self._json(400, {"error": "账号密码不能为空"})
                regions = body.get("regions")
                req_regions = [str(r).strip() for r in regions if str(r).strip()] if isinstance(regions, list) else []
                use_db = body.get("useDb", True)
                # 开关开：查数据库有没有该账密（用户名+密码都匹配）
                db_rec = db_find_account(username, password) if use_db else None
                pages_cfg = (LAST_CONFIG.get("pages") if LAST_CONFIG else None) or (json.load(open(CONFIG_FILE, encoding="utf-8")).get("pages", {}) if os.path.exists(CONFIG_FILE) else {})
                cfg = {
                    "domain": LAST_CONFIG.get("domain", "newxiadan.3f8cz.com") if LAST_CONFIG else "newxiadan.3f8cz.com",
                    "pages": pages_cfg,
                    "accounts": [{"username": username, "password": password}],
                    "cdkList": [],
                    "runTargets": ["login", "claim", "cdk"],
                    "accountCdks": True,   # 任务2：统一账号级日/周/月码（serial 读 db 码，无记录用默认 666/777/888）
                }
                # 区：开关开且有 db 匹配（且 db 有区）→ 用 db 的区（serial 会逐区跑）；否则用前端传的区
                if db_rec and db_rec.get("regions"):
                    cfg["accounts"][0]["regions"] = db_rec["regions"]
                elif req_regions:
                    cfg["accounts"][0]["regions"] = req_regions
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
                        # 跑完后判断结果（入库由 serial 统一做，这里只做状态分类）
                        with JOBS_LOCK:
                            job = JOBS.get(jid)
                            log = job.get("log", []) if job else []
                        wrong_pwd = any("账密错误" in item.get("msg", "") for item in log)
                        captcha_fail = any(("仍有" in item.get("msg", "") and "验证码失败" in item.get("msg", "")) for item in log)
                        if wrong_pwd:
                            with JOBS_LOCK:
                                if job: job["saved"] = False; job["save_reason"] = "账密错误"
                        elif captcha_fail:
                            with JOBS_LOCK:
                                if job: job["saved"] = False; job["save_reason"] = "验证码错误，请重跑"
                        else:
                            with JOBS_LOCK:
                                if job: job["saved"] = True; job["save_reason"] = "已入库"
                    except Exception as e:
                        import traceback
                        print(f"[test-redeem] 异常: {e}", flush=True)
                        print(traceback.format_exc(), flush=True)
                        with JOBS_LOCK:
                            job = JOBS.get(jid)
                            if job: job["status"] = "error"
                    _cleanup_old_jobs()
                threading.Thread(target=_test_th, daemon=True).start()
                self._json(200, {"job_id": jid, "cdk_count": 0})
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
  python ocr_server.py cdk add-once <code1> [code2 ...]   添加一次性 CDK（跑完一次后 used=1，不再参与）
  python ocr_server.py cdk remove <code>                  删除指定 CDK
  python ocr_server.py cdk reset <code>                   重置每日 CDK 为未用（明天能再跑）
  python ocr_server.py cdk reset-all                     一次性重置所有每日 CDK 为未用（调试反复跑用）
  python ocr_server.py cdk list                           列出所有 CDK
  python ocr_server.py cdk help                           显示本帮助
  python ocr_server.py account list                       列出所有账号（不显示密码）
  python ocr_server.py account add <账号> <密码>          新增账号
  python ocr_server.py account remove <账号>              删除账号
  python ocr_server.py cc [数字]                          查看/设置并发数（默认 3，>=1 整数）

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
        print(f"{'ID':<5} {'账号':<24} 区")
        print("-" * 50)
        for a in accounts:
            regs = a.get("regions") or []
            print(f"{a.get('id', '?'):<5} {a['username']:<24} {'/'.join(regs) if regs else '-'}")
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
        conn = _db_conn()
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
    if cmd == "reset-all":
        # 一次性重置所有每日 CDK（once=0）为未用，方便反复跑测试
        conn = _db_conn()
        c = conn.cursor()
        c.execute("UPDATE cdks SET used = 0 WHERE once = 0")
        n = c.rowcount
        conn.commit()
        conn.close()
        if n:
            print(f"  ✓ 已重置 {n} 个每日 CDK 为未用")
        else:
            print("  - 没有每日 CDK 需要重置")
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


def stats_cli(args):
    """python ocr_server.py stats [n]：查看验证码识别统计（默认最近一次 + 最近 5 条历史）"""
    n = 5
    if args:
        try:
            n = max(1, int(args[0]))
        except Exception:
            pass
    try:
        with open(OCR_STATS_FILE, encoding="utf-8") as f:
            last = json.load(f)
        print("最近一次验证码识别统计：")
        print(f"  时间:     {last.get('time', '')}")
        print(f"  成功率:   {last.get('rate')}%  （{last.get('ok')}/{last.get('total')}）")
        print(f"  全失败:   {last.get('allfail')}   长度异常: {last.get('badlen')}")
        print(f"  方法命中: {json.dumps(last.get('method_hits', {}), ensure_ascii=False)}")
    except FileNotFoundError:
        print("还没有统计记录（先跑一轮任务，任务结束自动落盘）")
    except Exception as e:
        print("读取统计失败:", e)
    try:
        lines = [l for l in open(OCR_STATS_HISTORY_FILE, encoding="utf-8") if l.strip()]
        if lines:
            print(f"\n最近 {min(n, len(lines))} 次历史记录：")
            for l in lines[-n:]:
                try:
                    d = json.loads(l)
                    print(f"  {d.get('time', '')}  成功率 {d.get('rate')}%  ({d.get('ok')}/{d.get('total')})  全失败 {d.get('allfail')}  长度异常 {d.get('badlen')}")
                except Exception:
                    pass
    except Exception:
        pass
    return 0


def config_cli(args):
    """python3 ocr_server.py config：查看当前运行配置（OCR 模型/字符集/并发数/定时/数据目录）"""
    print("═══ OCR 自动兑换 当前配置 ═══")
    print(f"数据目录:  {_DATA_DIR}")
    print(f"数据库:    {DB_FILE}")
    # OCR 模型
    beta = os.environ.get("OCR_BETA", "0") != "0"
    print(f"OCR 模型:  {'新模型 common.onnx（beta=True）' if beta else '老模型 common_old.onnx（beta=False）'}")
    # 字符集
    _r = (os.environ.get("OCR_RANGES", "") or "").strip()
    _names = {"0": "纯数字 0-9", "1": "小写 a-z", "2": "大写 A-Z", "3": "a-z + A-Z",
              "4": "a-z + 0-9", "5": "A-Z + 0-9", "6": "a-z + A-Z + 0-9"}
    if _r:
        print(f"字符集:    {_names.get(_r, _r)}（OCR_RANGES={_r}）")
    else:
        print("字符集:    默认（字母数字全覆盖，未设 OCR_RANGES）")
    # 预处理（固定开启：四路识别 + 4-5 位长度校验 + 一致性投票）
    print("预处理:    原图 + 灰度 + 二值化 + 去噪（四路识别 + 4-5 位长度校验 + 一致性投票）")
    # 并发
    print(f"并发数:    {get_concurrency()}（环境变量 AUTOFILL_CONCURRENCY > cc 设置 > 默认 3）")
    # 定时时间（读持久化配置）
    try:
        _sched = (LAST_CONFIG or {}).get("schedule") or {}
        if not _sched:
            _sched = (load_persisted_config() or {}).get("schedule") or {}
        _t = _sched.get("time", "00:05")
        _on = _sched.get("enabled", True)
        print(f"定时任务:  每天 {_t}（{'启用' if _on else '停用'}，配置存于前端页面配置）")
    except Exception:
        pass
    print(f"验证码统计: python3 ocr_server.py stats 查看")
    return 0


def concurrency_cli(args):
    """并发数子命令：cc 查看 / cc <数字> 设置（默认 3）"""
    if args and args[0] in ("help", "-h", "--help"):
        print("用法:")
        print("  cc          查看当前并发数（默认 3）")
        print("  cc <数字>   设置并发数（>=1 的整数，保存后重启仍生效；环境变量 AUTOFILL_CONCURRENCY 优先）")
        return 0
    if not args:
        print(f"当前并发数: {get_concurrency()}")
        print("来源优先级：环境变量 AUTOFILL_CONCURRENCY > cc 命令设置 > 默认 3")
        return 0
    try:
        n = int(args[0])
        if n < 1:
            raise ValueError()
        set_concurrency(n)
        print(f"✓ 并发数已设为 {n}（环境变量 AUTOFILL_CONCURRENCY 设置时优先于它）")
        return 0
    except ValueError:
        print("✗ 用法: cc <数字>（>=1 的整数）", file=sys.stderr)
        return 1


def run_now_cli(args):
    """手动执行一次定时任务（同凌晨 00:05 的全部自动化），跑完退出。"""
    _init_db()
    with JOBS_LOCK:
        has_running = any(j.get("status") == "running" for j in JOBS.values())
    if has_running:
        print("✗ 有任务在跑，稍后再试", flush=True)
        return 1
    cfg = _build_scheduled_config()
    if not cfg.get("accounts"):
        print("✗ 数据库没有账号，无法执行（先加账号）", flush=True)
        return 1
    jid = uuid.uuid4().hex
    JOBS[jid] = {
        "status": "running", "log": [], "logPath": _new_job_log_path(jid), "result": None,
        "started": time.time(), "cond": threading.Condition(), "last_index": 0,
        "subscribers": 0, "updatedConfig": None, "paused": False, "cancel_requested": False,
        "trigger": "now",
    }
    def _emit(msg, level="info"):
        with JOBS_LOCK:
            job = JOBS.get(jid)
            if job:
                job["log"].append({"time": time.time(), "msg": msg, "level": level})
        print(msg, flush=True)
        _job_log_append(jid, msg, level)
        with JOBS[jid]["cond"]:
            JOBS[jid]["cond"].notify_all()
    print("⏰ 手动执行定时任务（同凌晨 00:05 的全部自动化）", flush=True)
    try:
        _reset_ocr_stats()
        _run_job_impl(jid, cfg, _emit)
        _finalize_ocr_stats(_emit)
        with JOBS_LOCK:
            job = JOBS.get(jid)
            if job and job.get("status") == "running":
                job["status"] = "done"
        return 0
    except Exception as e:
        import traceback
        try: _finalize_ocr_stats(_emit)
        except Exception: pass
        print(f"✗ 执行异常: {e}", flush=True)
        print(traceback.format_exc(), flush=True)
        with JOBS_LOCK:
            job = JOBS.get(jid)
            if job:
                job["status"] = "error"
        return 1


if __name__ == '__main__':
    # CLI 模式：python ocr_server.py cdk ... / account ... / cc ...
    if len(sys.argv) >= 2 and sys.argv[1] == "cdk":
        _init_db()  # CLI 也要先建表
        sys.exit(cdk_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "account":
        _init_db()
        sys.exit(account_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "cc":
        sys.exit(concurrency_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "stats":
        sys.exit(stats_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "config":
        sys.exit(config_cli(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "now":
        sys.exit(run_now_cli(sys.argv[2:]))
    main()
