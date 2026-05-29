"""Decode a Metatron cube from a photograph.

By default this script auto-detects the ArUco fiducials printed by
``scripts/print_sheet.py`` (page-corner IDs 0..3 and/or cube-adjacent
IDs 10..13). The manual ``--fiducials`` mode is kept as a fallback for
photos taken from a cube that was rendered without ArUco markers (e.g.
raw output of ``make_test_vault.py``).

Usage examples
--------------

  # Fully automatic (recommended): just pass the photo
  python scripts/decode_from_photo.py photo.jpg

  # Fully automatic with diagnostic output
  python scripts/decode_from_photo.py photo.jpg \
      --save-rectified out/rect.png

  # Manual mode (legacy): pass the 6 outer-hexagon vertices yourself
  python scripts/decode_from_photo.py photo.jpg --manual-fiducials \
      --fiducials "1230,310 1820,500 1830,1110 1240,1300 650,1110 660,500"

  # Manual interactive (prompts for 6 coords)
  python scripts/decode_from_photo.py photo.jpg --manual-fiducials
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import List, Tuple

from PIL import Image

from eopx.metatron import (
    extract_from_photo, extract_canonical, decode_private, is_in_code,
    erasures_from_confidences,
)


def parse_fiducials(text: str) -> List[Tuple[float, float]]:
    pts: List[Tuple[float, float]] = []
    for token in text.replace(";", " ").split():
        x_str, y_str = token.split(",")
        pts.append((float(x_str), float(y_str)))
    if len(pts) != 6:
        raise ValueError(f"expected 6 fiducial points, got {len(pts)}")
    return pts


def prompt_fiducials() -> List[Tuple[float, float]]:
    print("Enter the 6 outer-hexagon vertex pixel coordinates of the photograph.")
    print("They must be given in canonical order, matching VERTICES[7..12]:")
    print("  - V[7]:  outer hex vertex at canonical angle  30 deg")
    print("  - V[8]:           ''                          90 deg  (top of figure)")
    print("  - V[9]:           ''                         150 deg")
    print("  - V[10]:          ''                         210 deg")
    print("  - V[11]:          ''                         270 deg  (bottom)")
    print("  - V[12]:          ''                         330 deg")
    print("Tip: open the photo in any viewer; most show pixel coords on hover.")
    print()
    pts: List[Tuple[float, float]] = []
    for k in range(6):
        idx = 7 + k
        while True:
            raw = input(f"  V[{idx}] (x,y) = ").strip()
            try:
                x_str, y_str = raw.split(",")
                pts.append((float(x_str), float(y_str)))
                break
            except Exception as exc:
                print(f"    parse error: {exc}; try again as 'x,y'")
    return pts


def _decode_and_report(syms, dists, args) -> int:
    n_uncertain = sum(1 for d in dists if d > args.erasure_threshold)
    max_d = max(dists)
    print("\nClassification confidence:")
    print(f"  carriers with Oklab distance > {args.erasure_threshold}: "
          f"{n_uncertain} / 91")
    print(f"  worst Oklab distance: {max_d:.3f}")

    in_C = is_in_code(syms)
    role = "private_*" if in_C else "public_render"
    print("\nAlgebraic test (Whitepaper III Theorem 2):")
    print(f"  symbols lie in code C: {in_C}")
    print(f"  inferred role: {role}")

    fp = hashlib.sha3_256(bytes(syms)).hexdigest()[:16]
    print(f"  symbol-vector fingerprint (sha3_256[:16]): {fp}")

    if in_C:
        erasures = erasures_from_confidences(dists, threshold=args.erasure_threshold)
        try:
            seed, version = decode_private(syms, erasures=erasures)
            print("\nPRIVATE DECODE successful:")
            print(f"  seed (hex)       : {seed.hex()}")
            print(f"  version          : {version}")
            print(f"  sha3-256[:16]    : {hashlib.sha3_256(seed).hexdigest()[:16]}")
            return 0
        except ValueError as exc:
            print(f"\nPRIVATE DECODE failed:  {exc}")
            print(f"  ({n_uncertain} carriers were flagged as erasures)")
            return 3
    print("\nPUBLIC RENDER detected (Theorem 2: symbols not in code C).")
    print("Signature verification requires the Eidolon registry; skipping.")
    return 0


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("photo", help="Path to the photograph (jpg/png/heic etc.)")
    p.add_argument("--manual-fiducials", action="store_true",
                   help="Disable ArUco auto-detection and read 6 fiducials "
                        "from --fiducials or interactively.")
    p.add_argument("--fiducials",
                   help="(manual mode) 6 'x,y' pairs separated by spaces or ';'")
    p.add_argument("--canonical-size", type=int, default=1024,
                   help="Canonical square size to rectify into (default 1024)")
    p.add_argument("--save-rectified", help="Write the rectified canonical image here")
    p.add_argument("--save-a4",
                   help="(auto mode, page-aruco fallback) Write the rectified A4 here")
    p.add_argument("--prefer", choices=("cube", "page"), default="cube",
                   help="(auto mode) Which marker family to try first")
    p.add_argument("--erasure-threshold", type=float, default=0.13,
                   help="Oklab distance above which a carrier is treated as erased")
    args = p.parse_args(argv[1:])

    photo_path = Path(args.photo)
    if not photo_path.is_file():
        print(f"Photo not found: {photo_path}", file=sys.stderr)
        return 2
    img = Image.open(photo_path).convert("RGB")
    print(f"Loaded: {photo_path} ({img.size[0]}x{img.size[1]})")

    # ---------- AUTO mode (default) ----------
    if not args.manual_fiducials:
        try:
            from eopx.metatron.aruco import autodetect_cube
        except RuntimeError as exc:
            print(f"ArUco backend unavailable: {exc}", file=sys.stderr)
            print("Re-run with --manual-fiducials to use manual rectification.",
                  file=sys.stderr)
            return 2

        try:
            det = autodetect_cube(img, dst_size=args.canonical_size,
                                   prefer=args.prefer)
        except ValueError as exc:
            print(f"\nAuto-detect failed: {exc}", file=sys.stderr)
            print("Hint: re-shoot the page with all ArUco corners visible, or "
                  "fall back to --manual-fiducials.", file=sys.stderr)
            return 2

        print(f"Auto-detected via {det.method} ({det.markers_used} markers).")
        if args.save_rectified:
            det.cube_image.save(args.save_rectified)
            print(f"Saved rectified cube to {args.save_rectified}")
        if args.save_a4 and det.rectified_a4 is not None:
            import cv2
            cv2.imwrite(args.save_a4, det.rectified_a4)
            print(f"Saved rectified A4 to {args.save_a4}")

        syms, dists = extract_canonical(det.cube_image)
        return _decode_and_report(syms, dists, args)

    # ---------- MANUAL mode (legacy) ----------
    if args.fiducials:
        try:
            src_pts = parse_fiducials(args.fiducials)
        except Exception as exc:
            print(f"Bad --fiducials: {exc}", file=sys.stderr)
            return 2
    else:
        src_pts = prompt_fiducials()

    print(f"Rectifying to {args.canonical_size}x{args.canonical_size}...")
    syms, dists, rect = extract_from_photo(img, src_pts, dst_size=args.canonical_size)
    if args.save_rectified:
        rect.save(args.save_rectified)
        print(f"Saved rectified image to {args.save_rectified}")
    return _decode_and_report(syms, dists, args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
