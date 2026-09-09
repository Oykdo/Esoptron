"""Measure the decode envelope of the Metatron camera path, axis by axis.

    py scripts/detect_envelope.py
    py scripts/detect_envelope.py --canvas 2048 --seed 7

For each degradation axis this sweeps a ladder of levels and reports, at every
step, how many of the 91 carriers were misread and — the number that actually
decides — how many landed in the *worst* interleaved RS block. Per block the
code corrects one error or three erasures, so a scan lives or dies on
``worst_block``, not on the global rate.

The last line of each table is the envelope: the harshest level at which the
worst block still holds at 1. Those are the values pinned (with margin) in
``tests/test_detect_envelope.py``.

This is a model of a photograph, not a photograph. Fiducials are handed to the
rectifier exactly, so fiducial *detection* error is excluded; real capture is
strictly harder than this.
"""

from __future__ import annotations

import argparse
import random

from eopx.metatron import encode_private, render
from eopx.metatron.degrade import (
    blur,
    canonical_fiducials,
    chroma_noise,
    illumination,
    jpeg,
    perspective,
    score,
)

PERSPECTIVE_LEVELS = (0.0, 1.0, 1.5, 2.0, 2.25, 2.5, 3.0, 4.0)
BLUR_LEVELS = (0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0)
JPEG_LEVELS = (95, 90, 80, 70, 60, 50, 40, 30, 20, 15, 10, 5)
ILLUMINATION_LEVELS = (0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7)
NOISE_LEVELS = (0.0, 4.0, 8.0, 16.0, 24.0, 32.0, 48.0, 64.0, 96.0)


def _table(name: str, unit: str, rows) -> None:
    print(f"\n=== {name} ===")
    print(f"{unit:>10}  {'errors':>7}  {'worst block':>11}  verdict")
    envelope = None
    for level, sc in rows:
        ok = sc.worst_block <= 1
        if ok:
            envelope = level
        print(f"{level:>10}  {sc.errors:>7}  {sc.worst_block:>11}  "
              f"{'within budget' if ok else 'BEYOND BUDGET'}")
    print(f"envelope: worst block still <= 1 at {unit} = {envelope}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--canvas", type=int, default=1024)
    ap.add_argument("--seed", type=int, default=2026)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    seed = bytes(rng.randrange(256) for _ in range(32))
    codeword = encode_private(seed)
    img = render(codeword, size=args.canvas)
    fid = canonical_fiducials(args.canvas)

    print(f"canvas={args.canvas}px  seed={args.seed}  "
          f"carriers=91  blocks=7  budget=1 error or 3 erasures per block")

    _table("perspective (x = handheld tilt unit)", "strength", [
        (lvl, score(*perspective(img, lvl, canvas=args.canvas),
                    codeword, canvas=args.canvas))
        for lvl in PERSPECTIVE_LEVELS])

    _table("gaussian blur", "radius px", [
        (lvl, score(blur(img, lvl), fid, codeword, canvas=args.canvas))
        for lvl in BLUR_LEVELS])

    _table("JPEG round trip", "quality", [
        (lvl, score(jpeg(img, lvl), fid, codeword, canvas=args.canvas))
        for lvl in JPEG_LEVELS])

    _table("illumination gradient", "strength", [
        (lvl, score(illumination(img, lvl), fid, codeword, canvas=args.canvas))
        for lvl in ILLUMINATION_LEVELS])

    _table("chroma noise", "sigma", [
        (lvl, score(chroma_noise(img, lvl, seed=args.seed), fid, codeword,
                    canvas=args.canvas))
        for lvl in NOISE_LEVELS])

    print("\nReminder: fiducials are exact here. A real photo also pays for "
          "ArUco detection error, motion blur and print gamut.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
