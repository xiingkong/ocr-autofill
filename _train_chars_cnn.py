# -*- coding: utf-8 -*-
"""
_train_chars_cnn.py — 字符分类器训练（torch CPU）
输入: chars_dataset36|62/{label}/*.png（由 _make_chars_dataset.py --cs 生成）
输出: chars_cnn_36.pt / chars_cnn_62.pt
用法: python _train_chars_cnn.py [epochs=100] [--cs 36|62]
"""
import os, sys, glob, random, io
import numpy as np
from PIL import Image
import torch
import torch.nn as nn
import torch.nn.functional as F

BASE = os.path.dirname(os.path.abspath(__file__))
CS = "34"
if "--cs" in sys.argv:
    _i = sys.argv.index("--cs")
    if _i + 1 < len(sys.argv) and sys.argv[_i + 1] in ("31", "34", "36", "62"):
        CS = sys.argv[_i + 1]
DS = os.path.join(BASE, f"chars_dataset{CS}")
CHARSET = ("23456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" if CS == "31"
           else "0123456789ABCDEFGHKLMNOPQRSTUVWXYZ" if CS == "34"
           else "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" if CS == "36"
           else "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
C2I = {c: i for i, c in enumerate(CHARSET)}
N_CLS = len(CHARSET)
IMG_SIZE = 28
EPOCHS = 100
BATCH = 64
LR = 1e-3
MODEL_OUT = os.path.join(BASE, f"chars_cnn_{CS}.pt")


class CharCNN(nn.Module):
    """轻量字符分类器：~150k 参数，CPU 秒级推理"""
    def __init__(self, n_cls=N_CLS):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv2d(1, 16, 3, padding=1), nn.BatchNorm2d(16), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(16, 32, 3, padding=1), nn.BatchNorm2d(32), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(32, 64, 3, padding=1), nn.BatchNorm2d(64), nn.ReLU(), nn.MaxPool2d(2),
        )  # 28 -> 14 -> 7 -> 3
        self.fc = nn.Sequential(
            nn.Linear(64 * 3 * 3, 128), nn.ReLU(), nn.Dropout(0.4),
            nn.Linear(128, n_cls),
        )

    def forward(self, x):
        x = self.conv(x)
        x = x.view(x.size(0), -1)
        return self.fc(x)


def aug(x):
    """数据增强：平移/缩放/亮度/噪声（输入 28x28 ndarray [0,1]）"""
    import random as _r
    im = Image.fromarray((x * 255).astype(np.uint8))
    # 平移 ±2
    dx, dy = _r.randint(-2, 2), _r.randint(-2, 2)
    im = im.transform(im.size, Image.AFFINE, (1, 0, dx, 0, 1, dy), resample=Image.BILINEAR)
    # 缩放 0.92-1.08
    s = _r.uniform(0.92, 1.08)
    if s < 1:
        nw, nh = int(28 * s), int(28 * s)
        im2 = im.resize((nw, nh), Image.BILINEAR)
        canvas = Image.new("L", (28, 28), 255)
        canvas.paste(im2, ((28 - nw) // 2, (28 - nh) // 2))
        im = canvas
    else:
        nw, nh = int(28 * s), int(28 * s)
        im = im.resize((nw, nh), Image.BILINEAR).crop(((nw - 28) // 2, (nh - 28) // 2, (nw - 28) // 2 + 28, (nh - 28) // 2 + 28))
    a = np.array(im, dtype=np.float32) / 255.0
    # 亮度
    a = a * _r.uniform(0.85, 1.15)
    # 噪声
    if _r.random() < 0.5:
        a = a + np.random.normal(0, 0.03, a.shape).astype(np.float32)
    return np.clip(a, 0, 1)


def load_data():
    samples = []  # (img_array, label_idx)
    for lab in CHARSET:
        d = os.path.join(DS, lab)
        if not os.path.isdir(d):
            continue
        for f in glob.glob(os.path.join(d, "*.png")):
            im = Image.open(f).convert("L")
            a = np.array(im, dtype=np.float32) / 255.0
            samples.append((a, C2I[lab]))
    random.Random(42).shuffle(samples)
    print(f"样本总数: {len(samples)}")
    return samples


def collate(batch):
    xs = torch.tensor(np.stack([b[0] for b in batch])).unsqueeze(1)
    ys = torch.tensor([b[1] for b in batch], dtype=torch.long)
    return xs, ys


def focal_loss(out, ys, gamma=2.0, alpha=None):
    """焦点损失：自动放大难样本（低置信预测）的梯度，提升易混淆对区分度"""
    logp = F.log_softmax(out, dim=1)
    p = logp.exp()
    ce = -logp.gather(1, ys.unsqueeze(1)).squeeze(1)
    pt = p.gather(1, ys.unsqueeze(1)).squeeze(1)
    fl = (1 - pt) ** gamma * ce
    if alpha is not None:
        fl = fl * alpha[ys]
    return fl.mean()


def train():
    samples = load_data()
    if len(samples) < 200:
        print("样本太少，先去跑 _make_chars_dataset.py 攒数据")
        return

    # ---- 阶段2：自训练去噪（可选 --stage2 或 --clean）----
    clean_src = samples
    if "--stage2" in sys.argv or "--clean" in sys.argv:
        # 用阶段1模型（chars_cnn_31.pt）过滤：模型预测 == 伪标签 才保留
        _sd = os.path.join(BASE, f"chars_cnn_{CS}.pt")
        if os.path.exists(_sd):
            m2 = CharCNN()
            m2.load_state_dict(torch.load(_sd, map_location="cpu"))
            m2.eval()
            keep = []
            drop = 0
            with torch.no_grad():
                for i in range(0, len(samples), BATCH):
                    xs, ys = collate([(b[0], b[1]) for b in samples[i:i + BATCH]])
                    pred = m2(xs).argmax(1)
                    for j, (px, py) in enumerate(zip(pred.tolist(), ys.tolist())):
                        if px == py:
                            keep.append(samples[i + j])
                        else:
                            drop += 1
            print(f"[阶段2] 模型自过滤：保留 {len(keep)} / 丢弃 {drop}（不一致样本=噪声标签）")
            clean_src = keep
            if len(clean_src) < 400:
                print("过滤后样本太少，中止阶段2")
                return
        else:
            print(f"[阶段2] 未找到阶段1模型 {_sd}，跳过（先跑一轮 --cs {CS}）")
    samples = clean_src

    split = int(len(samples) * 0.85)
    tr, va = samples[:split], samples[split:]
    print(f"训练 {len(tr)} / 验证 {len(va)}")

    model = CharCNN()
    opt = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=EPOCHS)
    lossf = nn.CrossEntropyLoss()

    best, best_ep, patience = 0.0, 0, 20
    for ep in range(1, EPOCHS + 1):
        model.train()
        random.shuffle(tr)
        tot_n, corr, lsum = 0, 0, 0.0
        for i in range(0, len(tr), BATCH):
            xs, ys = collate([(aug(b[0]), b[1]) for b in tr[i:i + BATCH]])
            opt.zero_grad()
            out = model(xs)
            loss = lossf(out, ys)
            loss.backward()
            opt.step()
            lsum += loss.item() * len(xs)
            corr += (out.argmax(1) == ys).sum().item()
            tot_n += len(xs)
        sched.step()
        # 验证
        model.eval()
        vc = 0
        with torch.no_grad():
            for i in range(0, len(va), BATCH):
                xs, ys = collate(va[i:i + BATCH])
                vc += (model(xs).argmax(1) == ys).sum().item()
        va_acc = vc / len(va)
        if va_acc > best:
            best = va_acc
            best_ep = ep
            torch.save(model.state_dict(), MODEL_OUT)
        else:
            patience -= 1
            if patience <= 0:
                print(f"  早停于 epoch {ep}（best {best:.3f} @ {best_ep}）")
                break
        if ep % 5 == 0 or ep == 1:
            print(f"  epoch {ep:3d}  loss {lsum/tot_n:.4f}  train {corr/tot_n:.3f}  val {va_acc:.3f}  best {best:.3f}", flush=True)
    print(f"\n训练完成，最佳验证准确率 {best:.3f}（epoch {best_ep}），模型: {MODEL_OUT}")


if __name__ == "__main__":
    train()
