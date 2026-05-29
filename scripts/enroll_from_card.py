"""Phone-only onboarding demo (Protocol D).

Photograph a PUBLIC Metatron card, derive a shadow hologram + identity,
and render the hologram preview as a local PNG. No PC or remote server
contacted at any step beyond saving local files.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import sys
from pathlib import Path
from typing import List, Tuple

from PIL import Image, ImageDraw

from eopx.metatron import (
    extract_canonical, extract_from_photo, erasures_from_confidences,
)
from eopx.metatron.palette import palette_srgb
from eopx.vault import enroll_from_card


def parse_fiducials(s: str) -> List[Tuple[float, float]]:
    parts = s.replace(";", " ").split()
    if len(parts) != 6:
        raise SystemExit("--fiducials must list 6 'x,y' points (V[7..12]).")
    out = []
    for p in parts:
        x_str, y_str = p.split(",")
        out.append((float(x_str), float(y_str)))
    return out


def extract_symbols(args) -> Tuple[List[int], List[float], Image.Image, str]:
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
        return symbols, dists, rect, "manual_fiducials"

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
    return symbols, dists, det.cube_image, method


def render_shadow_hologram(shadow: bytes, size: int = 512) -> Image.Image:
    """Render the per-device shadow hologram as a static preview.

    The bytes drive: petal count (3..12), radial frequency, phase, and the
    13-color palette used by Metatron itself. The phone app would replace
    this with a GLSL shader for animated holograms; here we just emit a
    deterministic static PNG so the user can see something now.
    """
    petal_count = 3 + (shadow[0] % 10)
    radial_freq = 3 + (shadow[1] % 8)
    phase_seed = int.from_bytes(shadow[2:6], "big") / 2**32
    palette = palette_srgb()

    img = Image.new("RGB", (size, size), (8, 8, 14))
    d = ImageDraw.Draw(img)
    cx = cy = size / 2.0
    r_max = size * 0.45

    # 13 concentric rings, each tinted by one palette colour, with a
    # rosette modulation derived from the hologram seed.
    for ring in range(13):
        col = palette[shadow[ring % len(shadow)] % 13]
        r0 = r_max * (ring + 0.5) / 13
        # Sample the ring at 720 angular positions, draw small dots whose
        # brightness follows cos(petal_count * theta + phase) modulated by
        # a secondary radial frequency.
        for k in range(720):
            theta = 2 * math.pi * k / 720
            radial = math.cos(radial_freq * theta + 2 * math.pi * phase_seed)
            petal = math.cos(petal_count * theta + ring * 0.37)
            amp = 0.5 + 0.5 * radial * petal
            if amp < 0.45:
                continue
            x = cx + r0 * math.cos(theta)
            y = cy + r0 * math.sin(theta)
            shade = int(round(60 + 195 * amp))
            tinted = tuple(min(255, (c * shade) // 255) for c in col)
            d.ellipse((x - 1, y - 1, x + 1, y + 1), fill=tinted)

    # Central glyph: the user's public_tag rendered as 4 nested squares
    # whose tilt depends on the hologram bytes.
    for i in range(4):
        s = size * (0.10 + i * 0.025)
        angle = (shadow[10 + i] / 255.0) * math.pi
        pts = []
        for a in (angle, angle + math.pi / 2,
                  angle + math.pi, angle + 3 * math.pi / 2):
            pts.append((cx + s * math.cos(a), cy + s * math.sin(a)))
        d.polygon(pts, outline=palette[shadow[i] % 13], fill=None)

    return img


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="enroll_from_card")
    p.add_argument("photo", help="photo of a PUBLIC Metatron card")
    p.add_argument("--manual-fiducials", action="store_true",
                   help="Disable ArUco auto-detection and use --fiducials.")
    p.add_argument("--fiducials",
                   help="Legacy manual fallback: 6 outer hexagon points 'x,y x,y ...'")
    p.add_argument("--canonical-size", type=int, default=1024,
                   help="Canonical square size to rectify into (default 1024)")
    p.add_argument("--prefer", choices=("cube", "page"), default="cube",
                   help="Auto mode: marker family to try first")
    p.add_argument("--device-entropy",
                   help="(testing only) 64 hex chars; default = OS CSPRNG")
    p.add_argument("--out", default="out/hologram.png",
                   help="where to write the local hologram preview")
    p.add_argument("--save-rectified", help="write the rectified frame as PNG")
    args = p.parse_args(argv[1:])

    try:
        symbols, dists, rect, method = extract_symbols(args)
    except ValueError as exc:
        print(f"  scan failed: {exc}", file=sys.stderr)
        return 2

    print(f"  scan method: {method}")
    if args.save_rectified:
        rect.save(args.save_rectified, format="PNG")
        print(f"  rectified saved to {args.save_rectified}")
    print(f"  scanned 91 symbols  ({len(erasures_from_confidences(dists))} erasures)")

    entropy = (bytes.fromhex(args.device_entropy)
               if args.device_entropy else None)
    rec = enroll_from_card(symbols, device_entropy=entropy)
    print()
    print("=" * 60)
    print("  ENROLLED  (this device is now a member of the ecosystem)")
    print("=" * 60)
    print(f"  card fingerprint : {rec.vault_fp.hex()}")
    print(f"  public tag       : {rec.public_tag.hex()}")
    print(f"  shadow hologram  : {rec.shadow_hologram.hex()[:64]}...")
    print()
    print("  device_secret   : <kept private on this device, not shown>")
    print()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    holo = render_shadow_hologram(rec.shadow_hologram, size=720)
    holo.save(out_path, format="PNG")
    print(f"  hologram preview written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
