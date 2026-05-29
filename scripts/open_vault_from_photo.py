"""End-to-end CLI: photo of a Metatron sheet -> vault session.

Three modes mapped to the three vault protocols:

  --mode private    Protocol A: recover seed + derive master_key.
                    Requires the photographed sheet to be a PRIVATE one.

  --mode verify     Protocol B: check that the card belongs to a known
                    vault. Requires --spinor <128 hex chars>.

  --mode sas        Protocol C: 2FA -- check the card AND derive a session
                    key bound to a fresh nonce. Requires --spinor.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import List, Tuple

from PIL import Image

from eopx.metatron import (
    extract_canonical, extract_from_photo, erasures_from_confidences,
)
from eopx.vault import (
    unlock_from_private_symbols,
    verify_card,
    new_challenge, respond, verify_response,
)


def parse_fiducials(s: str) -> List[Tuple[float, float]]:
    parts = s.replace(";", " ").split()
    if len(parts) != 6:
        raise SystemExit("--fiducials must list exactly 6 'x,y' points (V[7..12]).")
    out = []
    for p in parts:
        x_str, y_str = p.split(",")
        out.append((float(x_str), float(y_str)))
    return out


def extract_symbols(args) -> Tuple[List[int], List[float], Image.Image, str, object]:
    photo_path = Path(args.photo)
    if not photo_path.is_file():
        raise ValueError(f"photo not found: {photo_path}")

    img = Image.open(photo_path).convert("RGB")

    if args.manual_fiducials or args.fiducials:
        if not args.fiducials:
            raise ValueError("--fiducials is required with --manual-fiducials")
        src_pts = parse_fiducials(args.fiducials)
        symbols, dists, rect = extract_from_photo(
            img, src_pts, dst_size=args.canonical_size)
        return symbols, dists, rect, "manual_fiducials", None

    try:
        from eopx.metatron.aruco import autodetect_cube
    except RuntimeError as exc:
        raise ValueError(
            f"ArUco backend unavailable: {exc}; "
            "re-run with --manual-fiducials --fiducials ..."
        ) from exc

    det = autodetect_cube(img, dst_size=args.canonical_size,
                          prefer=args.prefer)
    symbols, dists = extract_canonical(det.cube_image)
    method = f"{det.method} ({det.markers_used} markers)"
    return symbols, dists, det.cube_image, method, det.rectified_a4


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="open_vault_from_photo")
    p.add_argument("photo", help="path to photo of the printed sheet")
    p.add_argument("--manual-fiducials", action="store_true",
                   help="Disable ArUco auto-detection and use --fiducials.")
    p.add_argument("--fiducials",
                   help="Legacy manual fallback: 6 outer-hexagon pixel positions, e.g. "
                        "'x7,y7 x8,y8 x9,y9 x10,y10 x11,y11 x12,y12'")
    p.add_argument("--canonical-size", type=int, default=1024,
                   help="Canonical square size to rectify into (default 1024)")
    p.add_argument("--prefer", choices=("cube", "page"), default="cube",
                   help="Auto mode: marker family to try first")
    p.add_argument("--mode", choices=("private", "verify", "sas"),
                   required=True)
    p.add_argument("--spinor", help="64-byte spinor_hash hex (for verify/sas)")
    p.add_argument("--vault-id",
                   help="32-byte vault id hex (for sas, defaults to SHA3-256 of spinor)")
    p.add_argument("--save-rectified", help="write the rectified frame as PNG")
    p.add_argument("--save-a4",
                   help="Auto mode: write the rectified A4 page when available")
    args = p.parse_args(argv[1:])

    try:
        symbols, dists, rect, method, rect_a4 = extract_symbols(args)
    except ValueError as exc:
        print(f"  scan failed: {exc}", file=sys.stderr)
        return 2

    print(f"  scan method: {method}")

    if args.save_rectified:
        rect.save(args.save_rectified, format="PNG")
        print(f"  rectified saved to {args.save_rectified}")
    if args.save_a4 and rect_a4 is not None:
        import cv2
        cv2.imwrite(args.save_a4, rect_a4)
        print(f"  rectified A4 saved to {args.save_a4}")

    erasures = erasures_from_confidences(dists)
    print(f"  detected 91 symbols, {len(erasures)} flagged as erasures.")

    if args.mode == "private":
        try:
            seed, master_key = unlock_from_private_symbols(symbols,
                                                            erasures=erasures)
        except Exception as e:
            print(f"  PRIVATE decode failed: {e}")
            return 2
        print(f"  seed (hex)       : {seed.hex()}")
        print(f"  master_key (hex) : {master_key.hex()}")
        return 0

    if args.spinor is None:
        raise SystemExit("--spinor is required in modes verify/sas")
    spinor = bytes.fromhex(args.spinor.strip())

    if args.mode == "verify":
        ok = verify_card(symbols, spinor)
        print(f"  card matches local vault: {ok}")
        return 0 if ok else 3

    # --- SAS ---
    vault_id = (bytes.fromhex(args.vault_id) if args.vault_id
                else hashlib.sha3_256(spinor).digest())
    if len(vault_id) != 32:
        raise SystemExit("vault_id must be 32 bytes")
    challenge = new_challenge(vault_id)
    print(f"  challenge issued, nonce = {challenge.nonce.hex()}")
    try:
        resp = respond(symbols, spinor, challenge)
    except ValueError as e:
        print(f"  SAS abort: {e}")
        return 4
    session = verify_response(resp, spinor, symbols)
    if session is None:
        print("  SAS verification FAILED")
        return 5
    print(f"  session_key (hex): {session.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
