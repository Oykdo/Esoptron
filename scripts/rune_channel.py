#!/usr/bin/env python3
"""EPX-R WP-1 / M2 — rune set + confusion matrix (the rune channel study).

Needs numpy and the package's rune alphabet (eopx.metatron.runes). Takes its
16 glyphs from there, then defines a capture degradation model, a
nearest-prototype classifier with a confidence margin, and measures the
16x16 confusion matrix -> per-cell error rate p_cell(level),
compared to the code thresholds p*:

    errors-only          p_cell <= ~8.4 %    (2t <= d-1, t<=43, n=255)
    confidence->erasures p_cell <= ~16.9 %   (e <= d-1)

Also runs a concrete end-to-end usage example through the EPX-R PoC:
a short secret -> runic mini-plate -> simulated scan -> recovered bytes.

Run with:  py -3.11 scripts/rune_channel.py
"""

from __future__ import annotations

import os
import sys
import numpy as np

S = 28  # cell raster size (px)

# --------------------------------------------------------------------------- #
# 16 rune glyphs as stroke lists in [0,1]^2 (y down). Futhark-inspired, chosen
# for distinct stroke topology. Index = the F_16 symbol it carries.
#
# The table itself now lives in the package (eopx.metatron.runes): a confusion
# matrix only describes the alphabet it measured, so the study and the shipped
# glyphs must be the same object, not two copies free to drift apart.
# --------------------------------------------------------------------------- #
from eopx.metatron.runes import RUNES  # noqa: E402


def rasterize(segs, size=S, width=1.3, aa=0.9):
    """Render stroke list to a [size,size] float grid in [0,1] (ink=1)."""
    ys, xs = np.mgrid[0:size, 0:size].astype(np.float64)
    px, py = (xs + 0.5) / size, (ys + 0.5) / size
    grid = np.zeros((size, size), dtype=np.float64)
    w = width / size
    for (x0, y0, x1, y1) in segs:
        dx, dy = x1 - x0, y1 - y0
        L2 = dx * dx + dy * dy
        if L2 == 0:
            d = np.hypot(px - x0, py - y0)
        else:
            t = np.clip(((px - x0) * dx + (py - y0) * dy) / L2, 0.0, 1.0)
            d = np.hypot(px - (x0 + t * dx), py - (y0 + t * dy))
        ink = np.clip(1.0 - (d - w) / (aa / size + 1e-9), 0.0, 1.0)
        grid = np.maximum(grid, ink)
    return grid


# --------------------------------------------------------------------------- #
# Capture degradation model
# --------------------------------------------------------------------------- #
def _gauss_kernel(sigma):
    if sigma < 1e-3:
        return np.array([1.0])
    r = max(1, int(3 * sigma))
    x = np.arange(-r, r + 1)
    k = np.exp(-(x ** 2) / (2 * sigma ** 2))
    return k / k.sum()


def blur(img, sigma):
    k = _gauss_kernel(sigma)
    if k.size == 1:
        return img
    out = np.apply_along_axis(lambda m: np.convolve(m, k, mode="same"), 0, img)
    out = np.apply_along_axis(lambda m: np.convolve(m, k, mode="same"), 1, out)
    return out


def affine(img, deg, shear):
    """Rotate by deg and shear, about center, bilinear inverse sampling."""
    size = img.shape[0]
    th = np.deg2rad(deg)
    c, s = np.cos(th), np.sin(th)
    # inverse map output->input
    ys, xs = np.mgrid[0:size, 0:size].astype(np.float64)
    cx = cy = (size - 1) / 2
    X, Y = xs - cx, ys - cy
    # un-shear then un-rotate
    Xs = X - shear * Y
    xin = c * Xs + s * Y + cx
    yin = -s * Xs + c * Y + cy
    x0 = np.floor(xin).astype(int); y0 = np.floor(yin).astype(int)
    x1, y1 = x0 + 1, y0 + 1
    wx, wy = xin - x0, yin - y0
    def samp(yy, xx):
        m = (xx >= 0) & (xx < size) & (yy >= 0) & (yy < size)
        v = np.zeros_like(xin);
        v[m] = img[np.clip(yy, 0, size - 1)[m], np.clip(xx, 0, size - 1)[m]]
        return v
    out = (samp(y0, x0) * (1 - wx) * (1 - wy) + samp(y0, x1) * wx * (1 - wy)
           + samp(y1, x0) * (1 - wx) * wy + samp(y1, x1) * wx * wy)
    return out


def bleed(img, amt):
    """Ink spread (dilation blended in by amt) — simulates print/ink bleed."""
    if amt <= 0:
        return img
    d = img.copy()
    for sh in ((1, 0), (-1, 0), (0, 1), (0, -1)):
        d = np.maximum(d, np.roll(img, sh, axis=(0, 1)))
    return (1 - amt) * img + amt * d


def degrade(img, level, rng):
    sigma = level * 1.6
    deg = rng.uniform(-level * 16, level * 16)
    shear = rng.uniform(-level * 0.18, level * 0.18)
    out = affine(img, deg, shear)
    out = blur(out, sigma)
    out = bleed(out, level * 0.5)
    out = out + rng.normal(0, level * 0.28, out.shape)
    return np.clip(out, 0.0, 1.0)


# --------------------------------------------------------------------------- #
# Classifier: nearest prototype by cosine similarity; margin = top1 - top2
# --------------------------------------------------------------------------- #
def build_prototypes():
    P = np.stack([rasterize(RUNES[i]).ravel() for i in range(16)])
    P = P - P.mean(axis=1, keepdims=True)
    P = P / (np.linalg.norm(P, axis=1, keepdims=True) + 1e-9)
    return P


def classify(sample_vec, P):
    s = sample_vec - sample_vec.mean()
    s = s / (np.linalg.norm(s) + 1e-9)
    sims = P @ s
    order = np.argsort(sims)[::-1]
    return int(order[0]), float(sims[order[0]] - sims[order[1]])


# --------------------------------------------------------------------------- #
# Study: confusion matrix + p_cell(level)
# --------------------------------------------------------------------------- #
def study(levels=(0.15, 0.30, 0.45, 0.60, 0.75, 0.90), trials=200):
    P = build_prototypes()
    rng = np.random.default_rng(11)
    print("[WP-1] rune channel — p_cell(level) vs thresholds "
          "(p*=8.4% errors / 16.9% erasures)\n")
    print("  level | p_cell  | verdict")
    show_cm_at = 0.45
    cm_to_show = None
    for lv in levels:
        cm = np.zeros((16, 16), dtype=int)
        for r in range(16):
            base = rasterize(RUNES[r])
            for _ in range(trials):
                pred, _m = classify(degrade(base, lv, rng).ravel(), P)
                cm[r, pred] += 1
        acc = np.trace(cm) / cm.sum()
        p_cell = 1 - acc
        verdict = ("OK<8.4%" if p_cell <= 0.084 else
                   "OK<16.9% (needs erasures)" if p_cell <= 0.169 else
                   "OVER")
        print(f"  {lv:4.2f}  | {p_cell:6.2%} | {verdict}")
        if abs(lv - show_cm_at) < 1e-6:
            cm_to_show = cm
    if cm_to_show is not None:
        print(f"\n  confusion matrix @ level={show_cm_at} "
              f"(rows=true, cols=pred; diagonal omitted if =trials):")
        print("     " + "".join(f"{c:4d}" for c in range(16)))
        for r in range(16):
            cells = "".join(
                ("   ." if (c == r) else f"{cm_to_show[r, c]:4d}")
                if cm_to_show[r, c] else "    " for c in range(16))
            print(f"  {r:2d} |{cells}  (diag={cm_to_show[r, r]})")
    return P


# --------------------------------------------------------------------------- #
# A4 — confidence-threshold ROC: erasures vs confident-errors vs recovery
# --------------------------------------------------------------------------- #
def roc(P, level=0.60, trials=5):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from epx_r_poc import RS
    rs = RS(255, 169)
    rng = np.random.default_rng(99)
    print(f"\n[A4 ROC] confidence-threshold sweep @ level={level} "
          f"(1 RS block n={rs.n}, k={rs.k}, d-1={rs.nsym}; "
          f"a confident-error costs 2, an erasure costs 1)")
    print("  thresh | erasures | conf-errors | 2t+e | vs d-1 | decode")
    for thr in [0.00, 0.02, 0.04, 0.06, 0.08, 0.12, 0.16, 0.20]:
        E = T = okc = 0
        for _ in range(trials):
            msg = rng.integers(0, 256, size=rs.k, dtype=np.uint8)
            cw = rs.encode_blocks(msg.reshape(1, rs.k))[0]
            cells = np.empty(rs.n * 2, np.uint8)
            cells[0::2] = cw >> 4
            cells[1::2] = cw & 0x0F
            rec = cells.copy()
            erased = np.zeros(cells.size, bool)
            for i, v in enumerate(cells):
                pred, m = classify(
                    degrade(rasterize(RUNES[int(v)]), level, rng).ravel(), P)
                if m < thr:
                    erased[i] = True
                else:
                    rec[i] = pred
            syms = (rec[0::2] << 4) | rec[1::2]
            ser = erased[0::2] | erased[1::2]
            e = int(ser.sum())
            t = int(np.sum((syms != np.asarray(cw)) & ~ser))
            E += e
            T += t
            try:
                dec = rs.decode(syms.tolist(), np.nonzero(ser)[0].tolist())
                okc += int(dec[: rs.k] == msg.tolist())
            except Exception:
                pass
        ea, ta = E / trials, T / trials
        print(f"  {thr:5.2f}  | {ea:7.1f}  | {ta:10.1f}  | {2*ta+ea:5.1f} | "
              f"{rs.nsym:^6d} | {okc}/{trials} {'OK' if okc == trials else ''}")
    print("  -> too low: confident-errors (×2 cost) dominate; too high: erasures"
          " pile up. The sweet spot maximises decode.")


# --------------------------------------------------------------------------- #
# Concrete usage example: secret -> runic mini-plate -> scan -> recover
# --------------------------------------------------------------------------- #
def demo_usage(P, level=0.50, margin_thresh=0.06):
    """Concrete end-to-end: a secret -> runic plate -> noisy scan (with some
    confident-wrong reads = errors) + a physical scratch (erasures) -> recover
    EXACT, thanks to the WP-2 errors-and-erasures decoder."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from epx_r_poc import RS, encode_private, decode_private

    rs = RS(255, 169)
    secret = (b"ESOPTRON VAULT BACKUP // owner=Logos Project // "
              b"seed=7b3f...e1a9 // do-not-share")
    print(f"\n[usage] secret ({len(secret)} B): {secret.decode()!r}")

    grid, meta = encode_private(secret, rs, interleave=True)
    M, ncells = meta["M"], meta["ncells"]
    print(f"[usage] engraved plate: {meta['B']} block (n=255,k=169,d=87), "
          f"{M}x{M} cells, {ncells} runes used")

    # --- (1) simulate scanning every engraved rune (mild degradation) ---
    rng = np.random.default_rng(2024)
    flat = grid.reshape(-1)
    recovered = flat.copy()
    erased = np.zeros(M * M, dtype=bool)
    confident_errors = 0
    for idx in range(ncells):
        true_v = int(flat[idx])
        pred, margin = classify(
            degrade(rasterize(RUNES[true_v]), level, rng).ravel(), P)
        if margin < margin_thresh:
            erased[idx] = True                 # low confidence -> erasure
        else:
            recovered[idx] = pred
            if pred != true_v:
                confident_errors += 1
    n_conf_er = int(erased[:ncells].sum())

    # --- (2) a physical scratch tears a band of cells (within budget) ---
    band = max(1, int(0.12 * M))
    r0 = M // 3
    erased.reshape(M, M)[r0:r0 + band, :] = True
    n_total_er = int(erased[:ncells].sum())

    print(f"[usage] scan @ level={level}: reads clean "
          f"({confident_errors} confident-wrong), "
          f"{n_conf_er} low-confidence erasures")
    print(f"[usage] + physical scratch ({band} rows) -> "
          f"{n_total_er} erased cells total ({n_total_er/ncells:.0%})")

    meta2 = dict(meta)
    meta2["erased"] = erased.reshape(M, M)
    grid2 = recovered.reshape(M, M)
    try:
        out = decode_private(grid2, rs, meta2)
        ok = out == secret
        print(f"[usage] recovered: {'EXACT MATCH' if ok else 'MISMATCH'}")
        if ok:
            print(f"[usage] -> {out.decode()!r}")
    except Exception as e:
        print(f"[usage] decode failed: {e}")
        if confident_errors:
            print("[usage] (confident-wrong reads need the errors-and-erasures "
                  "decoder of WP-2; erasure-only cannot repair them)")


if __name__ == "__main__":
    P = study()
    roc(P)
    demo_usage(P)
