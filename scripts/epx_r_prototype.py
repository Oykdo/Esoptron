#!/usr/bin/env python3
"""EPX-R WP-3/WP-4 — printable A4 prototype + detect pipeline (phone/PC camera).

Builds a real, print-ready A4 runic plate with ArUco corner fiducials, then
validates the full capture path in software:

    render A4 plate (PNG + PDF, 300 dpi)
      -> simulate a phone photo (perspective warp + lighting + blur + noise + JPEG)
      -> detect:  ArUco -> homography -> rectify -> sample cells
                  -> classify runes (+confidence -> erasures)
                  -> de-interleave -> RS errors-and-erasures decode -> unframe
      -> byte-exact recovery

Also prints the WP-4 capture-tier capacity map for A4.

Run:  py -3.11 scripts/epx_r_prototype.py
Needs: numpy, opencv-python (cv2), Pillow.  Reuses epx_r_poc + rune_channel.
"""

from __future__ import annotations

import math
import os
import struct
import sys
import zlib

import cv2
import numpy as np
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from epx_r_poc import (RS, MAGIC, _frame, _unframe, ReedSolomonError,
                       rs_calc_syndromes)
from rune_channel import RUNES, rasterize, build_prototypes, classify

# --------------------------------------------------------------------------- #
# Fixed A4 layout (shared by render + detect) — 300 dpi
# --------------------------------------------------------------------------- #
DPI = 300
A4_W, A4_H = 2480, 3508          # A4 @ 300 dpi (px)
MARK = 260                       # ArUco marker side (px, ~22 mm)
MARGIN = 100
CELL = 40                        # rune cell side (px, ~3.4 mm — phone-readable)
GW, GH = 43, 69                  # data grid (cells) — fixed
NBLOCKS = 5                      # fixed number of RS blocks
RS_N, RS_K = 255, 169
ARUCO = cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_4X4_50)

# data-region inner corners (where the four marker inner corners sit)
DX0, DY0 = MARGIN + MARK, MARGIN + MARK              # = (360, 360)
DX1, DY1 = DX0 + GW * CELL, DY0 + GH * CELL          # = (2080, 3120)


def _aruco_img(idx, size):
    img = np.zeros((size, size), np.uint8)
    cv2.aruco.generateImageMarker(ARUCO, idx, size, img, 1)
    return img


# --------------------------------------------------------------------------- #
# Render
# --------------------------------------------------------------------------- #
def render_a4(payload: bytes, rs: RS):
    framed = _frame(payload)
    cap = NBLOCKS * rs.k
    assert len(framed) <= cap, f"payload too big ({len(framed)} > {cap})"
    buf = framed + b"\x00" * (cap - len(framed))
    msgs = np.frombuffer(buf, np.uint8).reshape(NBLOCKS, rs.k)
    cw = rs.encode_blocks(msgs)                       # [B, n]
    stream = cw.T.reshape(-1)                          # interleave (pos-major)
    cells = np.zeros(GW * GH, np.uint8)
    nib = np.empty(stream.size * 2, np.uint8)
    nib[0::2] = stream >> 4
    nib[1::2] = stream & 0x0F
    cells[: nib.size] = nib                            # rest = rune 0 (filler)

    plate = np.full((A4_H, A4_W), 255, np.uint8)       # white
    # data grid
    glyph = {v: (255 * (1 - rasterize(RUNES[v], CELL))).astype(np.uint8)
             for v in range(16)}
    k = 0
    for r in range(GH):
        for c in range(GW):
            g = glyph[int(cells[k])]; k += 1
            y, x = DY0 + r * CELL, DX0 + c * CELL
            plate[y:y + CELL, x:x + CELL] = g
    # four ArUco markers at the corners (inner corner = data-region corner)
    m = _aruco_img(0, MARK); plate[MARGIN:MARGIN + MARK, MARGIN:MARGIN + MARK] = m
    m = _aruco_img(1, MARK); plate[MARGIN:MARGIN + MARK, DX1:DX1 + MARK] = m
    m = _aruco_img(2, MARK); plate[DY1:DY1 + MARK, DX1:DX1 + MARK] = m
    m = _aruco_img(3, MARK); plate[DY1:DY1 + MARK, MARGIN:MARGIN + MARK] = m
    return plate, len(framed)


# --------------------------------------------------------------------------- #
# Simulate a phone photo: perspective + lighting + blur + noise + JPEG
# --------------------------------------------------------------------------- #
def simulate_photo(plate, rng):
    H, W = plate.shape
    pad = 400
    scene = np.full((H + 2 * pad, W + 2 * pad), 235, np.uint8)
    scene[pad:pad + H, pad:pad + W] = plate
    h, w = scene.shape
    src = np.float32([[0, 0], [w, 0], [w, h], [0, h]])
    j = 0.06
    dst = np.float32([[rng.uniform(0, j) * w, rng.uniform(0, j) * h],
                      [w * (1 - rng.uniform(0, j)), rng.uniform(0, j) * h],
                      [w * (1 - rng.uniform(0, j)), h * (1 - rng.uniform(0, j))],
                      [rng.uniform(0, j) * w, h * (1 - rng.uniform(0, j))]])
    Hm = cv2.getPerspectiveTransform(src, dst)
    warp = cv2.warpPerspective(scene, Hm, (w, h), borderValue=235)
    # lighting gradient
    yy, xx = np.mgrid[0:h, 0:w]
    grad = 0.75 + 0.5 * (xx / w) * (1 - 0.4 * yy / h)
    warp = np.clip(warp.astype(np.float32) * grad, 0, 255)
    warp = cv2.GaussianBlur(warp, (0, 0), 1.1)
    warp = np.clip(warp + rng.normal(0, 5, warp.shape), 0, 255).astype(np.uint8)
    ok, enc = cv2.imencode(".jpg", warp, [cv2.IMWRITE_JPEG_QUALITY, 72])
    return cv2.imdecode(enc, cv2.IMREAD_GRAYSCALE)


# --------------------------------------------------------------------------- #
# Detect
# --------------------------------------------------------------------------- #
def detect(photo, rs: RS, margin_thresh=0.05, verbose=False):
    if photo.ndim == 3:
        photo = cv2.cvtColor(photo, cv2.COLOR_BGR2GRAY)
    det = cv2.aruco.ArucoDetector(ARUCO, cv2.aruco.DetectorParameters())
    corners, ids, _ = det.detectMarkers(photo)
    if ids is None:
        raise RuntimeError("no ArUco markers found")
    found = {int(i): c[0] for i, c in zip(ids.ravel(), corners)}
    if verbose:
        print(f"[detect] markers found: {sorted(found)}")
    if not {0, 1, 2, 3} <= set(found):
        raise RuntimeError(f"missing markers, found {sorted(found)}")
    # inner corner of each marker (ArUco order: TL,TR,BR,BL)
    src = np.float32([found[0][2], found[1][3], found[2][0], found[3][1]])
    dst = np.float32([[0, 0], [GW * CELL, 0], [GW * CELL, GH * CELL], [0, GH * CELL]])
    Hm = cv2.getPerspectiveTransform(src, dst)
    rect = cv2.warpPerspective(photo, Hm, (GW * CELL, GH * CELL))

    P = build_prototypes()
    n_used = 2 * NBLOCKS * rs.n
    cells = np.zeros(GW * GH, np.uint8)
    erased = np.zeros(GW * GH, bool)
    for idx in range(n_used):
        r, c = divmod(idx, GW)
        patch = rect[r * CELL:(r + 1) * CELL, c * CELL:(c + 1) * CELL]
        patch = cv2.resize(patch, (28, 28)).astype(np.float64) / 255.0
        ink = 1.0 - patch                              # black ink -> 1
        pred, margin = classify(ink.ravel(), P)
        cells[idx] = pred
        if margin < margin_thresh:
            erased[idx] = True

    syms = (cells[0:n_used:2] << 4) | cells[1:n_used:2]
    ser = erased[0:n_used:2] | erased[1:n_used:2]
    cw = syms.reshape(rs.n, NBLOCKS).T
    ce = ser.reshape(rs.n, NBLOCKS).T

    if verbose:
        print(f"[detect] {int(ser.sum())} symbol-erasures of {ser.size}")
    out = np.empty((NBLOCKS, rs.k), np.uint8)
    fails = 0
    for b in range(NBLOCKS):
        er = np.nonzero(ce[b])[0].tolist()
        blk = cw[b].tolist()
        if not er and max(rs_calc_syndromes(blk, rs.nsym)) == 0:
            out[b] = cw[b, : rs.k]; continue
        try:
            out[b] = rs.decode(blk, er)[: rs.k]
        except (ReedSolomonError, ValueError):
            fails += 1; out[b] = cw[b, : rs.k]
    # self-describing: read the framed length from the recovered header
    raw = out.reshape(-1).tobytes()
    if raw[:4] != MAGIC:
        raise RuntimeError("frame magic not found (decode failed)")
    ln = struct.unpack(">I", raw[5:9])[0]
    return _unframe(raw[: 9 + ln + 4]), fails


# --------------------------------------------------------------------------- #
# WP-4: A4 capacity by capture tier
# --------------------------------------------------------------------------- #
def wp4_tier_map():
    usable_cm2 = 19.0 * 27.7                            # A4 minus margins
    rate, bits_per_cell = 0.663, 4
    print("\n[WP-4] A4 capacity by capture tier "
          f"(usable {usable_cm2:.0f} cm^2, rate {rate}, 4 b/cell):")
    print("  tier              | cell pitch | cells/cm^2 |  cells   | useful")
    tiers = [("phone camera", 0.40), ("scanner 1200dpi", 0.030),
             ("scanner 2400dpi", 0.015), ("microscopy 20um", 0.0020),
             ("lab optics 5um", 0.0005)]
    for name, pitch_cm in tiers:
        dens = 1.0 / pitch_cm ** 2
        cells = usable_cm2 * dens
        useful_bits = cells * bits_per_cell * rate
        b = useful_bits / 8
        size = (f"{b/1e6:.1f} MB" if b >= 1e6 else
                f"{b/1e3:.0f} KB" if b >= 1e3 else f"{b:.0f} B")
        print(f"  {name:17s} | {pitch_cm*10:5.2f} mm  | {dens:9.0f}  | "
              f"{cells:8.0f} | {size}")


# --------------------------------------------------------------------------- #
def cli_detect(path):
    """Decode a REAL photo of a printed plate:  prototype.py detect <photo>"""
    rs = RS(RS_N, RS_K)
    photo = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if photo is None:
        print(f"[detect] cannot read image: {path}")
        return 1
    print(f"[detect] {path}  ({photo.shape[1]}x{photo.shape[0]})")
    try:
        rec, fails = detect(photo, rs, verbose=True)
        print(f"[detect] block-fails={fails}/{NBLOCKS}")
        print(f"[detect] RECOVERED ({len(rec)} B): "
              f"{rec.decode('utf-8', 'replace')!r}")
        return 0
    except Exception as e:
        print(f"[detect] FAILED: {e}")
        return 2


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "detect":
        sys.exit(cli_detect(sys.argv[2]))

    rs = RS(RS_N, RS_K)
    secret = (b"ESOPTRON A4 PROTOTYPE // Logos Project // "
              b"vault=#1 // seed=7b3f-e1a9-... // scan-me-with-your-phone")
    print(f"[proto] payload {len(secret)} B (cap {NBLOCKS*rs.k} B), "
          f"grid {GW}x{GH} cells, {NBLOCKS} RS blocks")

    plate, flen = render_a4(secret, rs)
    out_png = os.path.join(os.path.dirname(__file__), "..", "epx_r_A4_prototype.png")
    Image.fromarray(plate).save(out_png, dpi=(DPI, DPI))
    Image.fromarray(plate).save(out_png.replace(".png", ".pdf"),
                                resolution=DPI)
    print(f"[proto] rendered A4 -> {os.path.normpath(out_png)} "
          f"(+ .pdf) {A4_W}x{A4_H}px @ {DPI}dpi")

    # validate the whole capture path in software (3 simulated photos)
    okc = 0
    for trial in range(3):
        rng = np.random.default_rng(1000 + trial)
        photo = simulate_photo(plate, rng)
        try:
            rec, fails = detect(photo, rs)
            ok = rec == secret
            okc += int(ok)
            print(f"[proto] sim photo {trial}: markers OK, block-fails={fails}, "
                  f"recovered={'EXACT' if ok else 'MISMATCH'}")
        except Exception as e:
            print(f"[proto] sim photo {trial}: FAILED ({e})")
    print(f"[proto] capture-path round-trip: {okc}/3 simulated photos exact")

    wp4_tier_map()
