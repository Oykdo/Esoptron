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

The geometry axis is a real tilt: the card plane is rotated in 3-D and
reprojected, and the fiducial destinations are *derived from* that homography
rather than fitted to it. Its predecessor displaced the six fiducials by six
hand-chosen vectors no homography can realise, fitted a matrix to them, warped
by the fit and returned the unfitted targets — 68 px of injected fiducial
error at the level once pinned as the envelope. An angle also means something
a person can act on: "the card may be tilted N degrees".

The last two tables measure the term the others exclude. Every image axis
hands the rectifier the six fiducials exactly; a scanner has to *find* them
and is wrong by some amount, and that error is what separates one
rectification strategy from another. Common-mode error (the whole estimate
slides) and differential error (the six points stop describing one rigid
figure) are reported apart, because they do not cost the same.

This is still a model of a photograph, not a photograph: real capture also
pays for motion blur, rolling shutter and print gamut.
"""

from __future__ import annotations

import argparse
import random

from eopx.metatron import encode_private, render
from eopx.metatron.degrade import (
    blur,
    canonical_fiducials,
    chroma_noise,
    fiducial_jitter,
    fiducial_radius,
    fiducial_shift,
    illumination,
    jpeg,
    tilt,
    score,
)

TILT_LEVELS = (0.0, 30.0, 60.0, 70.0, 75.0, 80.0, 82.0, 84.0, 85.0, 86.0)
BLUR_LEVELS = (0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0)
JPEG_LEVELS = (95, 90, 80, 70, 60, 50, 40, 30, 20, 15, 10, 5)
ILLUMINATION_LEVELS = (0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7)
NOISE_LEVELS = (0.0, 4.0, 8.0, 16.0, 24.0, 32.0, 48.0, 64.0, 96.0)
SHIFT_LEVELS = (0.0, 2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 16.0, 24.0)
JITTER_LEVELS = (0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, 8.0)
JITTER_SEEDS = 5


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


def _jitter_table(img, fid, codeword, canvas: int) -> None:
    """Differential fiducial error, swept over seeds rather than reduced.

    One badly-placed fiducial dominates the fit, so a single draw at a given
    sigma says almost nothing: at sigma 2 px the worst block across five seeds
    has been seen to range from 0 to 13. Printing the distribution keeps that
    visible, where a mean would hide exactly the tail that decides a scan.
    """
    print("\n=== fiducial error, differential (per-fiducial sigma) ===")
    print(f"{'sigma px':>10}  {'worst block per seed':>26}  {'in budget':>10}")
    envelope = None
    for sigma in JITTER_LEVELS:
        worst = [score(img, fiducial_jitter(fid, sigma, seed=s), codeword,
                       canvas=canvas).worst_block
                 for s in range(JITTER_SEEDS)]
        ok = sum(1 for w in worst if w <= 1)
        if ok == JITTER_SEEDS:
            envelope = sigma
        print(f"{sigma:>10}  {str(worst):>26}  {ok:>7}/{JITTER_SEEDS}")
    print(f"envelope: every seed within budget up to sigma = {envelope} px")



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

    _table("tilt (card plane rotated and reprojected)", "degrees", [
        (lvl, score(*tilt(img, lvl, canvas=args.canvas),
                    codeword, canvas=args.canvas))
        for lvl in TILT_LEVELS])

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

    # The term this bench used to exclude. Everything above degrades the image
    # and then hands the rectifier the six fiducials exactly; a scanner has to
    # find them and is wrong by some amount. That error is what separates one
    # rectification strategy from another, so omitting it collapsed two
    # questions -- how good must the photo be, and where should the fiducials
    # go -- into one, and left the second unanswerable.
    print(f"\nfiducial radius = {fiducial_radius(args.canvas):.0f} px "
          f"on this canvas; read a sigma below as that fraction")

    _table("fiducial error, common mode (uniform slide)", "px", [
        (lvl, score(img, fiducial_shift(fid, lvl, 0.0), codeword,
                    canvas=args.canvas))
        for lvl in SHIFT_LEVELS])

    _jitter_table(img, fid, codeword, args.canvas)

    print("\nReminder: this is still a model. A real photo also pays "
          "for motion blur, rolling shutter and print gamut.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
