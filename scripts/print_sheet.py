r"""Generate a print-ready A4 sheet (300 DPI) carrying a Metatron cube.

Usage examples
--------------
  # Private inscription from a known seed (hex 64 chars = 256 bits)
  py scripts/print_sheet.py --seed 7ef1ea...331 --role private --out out\sheet_private.png

  # Private inscription from a passphrase (SHA3-256 of UTF-8 bytes)
  py scripts/print_sheet.py --passphrase "metatron.test_vault.v1" --role private \
      --out out\sheet_private.png

  # Public render from a 64-byte hex spinor_hash (e.g. Eidolon Phase 6 output)
  py scripts/print_sheet.py --spinor 9af3...e1 --role public --out out\sheet_public.png

  # Random fresh seed (only for testing!), prints it on the sheet for reference
  py scripts/print_sheet.py --random --role private --out out\sheet_random.png

What you get
------------
Single 2480 x 3508 px PNG (A4 at 300 DPI), portrait, white background. Layout:

  - role banner at the top (PRIVATE INSCRIPTION / PUBLIC RENDER)
  - 4 black square fiducials near the corners (for rectification)
  - 10 mm calibration scale below the cube
  - Metatron cube centered, ~150 mm side
  - footer:
      * full hash printed in monospace, broken in 16-char groups
      * SHA3-256 checksum of the printed hash (for OCR cross-check)
      * generation date and tool version
      * fold/cut crop marks at the page corners
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
import textwrap
from pathlib import Path
from typing import Optional, Tuple

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from eopx.metatron import encode_private, encode_public, render

try:
    import cv2  # used to generate real ArUco markers
    _HAS_CV2 = True
except Exception:
    cv2 = None  # type: ignore[assignment]
    _HAS_CV2 = False

# ---------- A4 @ 300 DPI ----------
DPI = 300
MM_PER_INCH = 25.4
A4_W_MM = 210.0
A4_H_MM = 297.0
PAGE_W = int(round(A4_W_MM / MM_PER_INCH * DPI))   # 2480
PAGE_H = int(round(A4_H_MM / MM_PER_INCH * DPI))   # 3508

# ---------- Layout (all in millimetres, converted to px) ----------
SAFE_MARGIN_MM = 10.0     # most consumer printers cannot print closer than ~5 mm
FIDUCIAL_MM = 30.0        # outer side of the corner fiducial square (was 12, then 22)
FIDUCIAL_INSET_MM = 8.0   # from the page edge to the OUTER side of the fiducial
FIDUCIAL_QUIET_MM = 5.0   # white quiet zone around each ArUco (helps detection)
CUBE_SIDE_MM = 100.0      # printable area of the cube on paper (reduced to fit grid)
SCALE_BAR_MM = 50.0       # 50 mm calibration ruler

BG = (255, 255, 255)
INK = (0, 0, 0)
SOFT = (90, 90, 90)
WARN = (170, 0, 0)


def mm(x_mm: float) -> int:
    """Millimetres to pixels at our DPI."""
    return int(round(x_mm / MM_PER_INCH * DPI))


def load_font(size_px: int, mono: bool = False
              ) -> "ImageFont.FreeTypeFont | ImageFont.ImageFont":
    """Best-effort font loader. Falls back to PIL default if nothing is found."""
    candidates_sans = [
        "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    candidates_mono = [
        "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/cour.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    for path in (candidates_mono if mono else candidates_sans):
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size=size_px)
            except OSError:
                continue
    return ImageFont.load_default()


# ---------- Fiducial markers (real ArUco DICT_4X4_50) ----------

ARUCO_DICT_NAME = "DICT_4X4_50"
# IDs assigned to each page corner. Match the constants in scripts/live_scan.py.
ARUCO_IDS = {"TL": 0, "TR": 1, "BR": 2, "BL": 3}
# IDs for cube-adjacent ArUco markers (4 corners of the cube frame)
CUBE_ARUCO_IDS = {"TL": 10, "TR": 11, "BR": 12, "BL": 13}
CUBE_ARUCO_MM = 30.0  # size of cube-adjacent markers (currently NOT rendered)


def aruco_outer_corners() -> dict:
    """Return the outer-corner pixel position of each ArUco on the A4 page.

    Each ArUco is a `mm(FIDUCIAL_MM)` square inset by `mm(FIDUCIAL_INSET_MM)`
    from the page edge. We return the corner of the marker that points
    AWAY from the page center for each ID (TL=top-left, TR=top-right, etc.).
    These act as 4 known correspondences for the photo->A4 homography.
    """
    inset = mm(FIDUCIAL_INSET_MM)
    return {
        0: (inset,                inset),               # TL outer
        1: (PAGE_W - inset,       inset),               # TR outer
        2: (PAGE_W - inset,       PAGE_H - inset),      # BR outer
        3: (inset,                PAGE_H - inset),      # BL outer
    }


def cube_aruco_corners() -> dict:
    """Return the center pixel position of each cube-adjacent ArUco on the A4 page.

    These are at the 4 corners of the cube frame, offset by gap + side/2.
    Used for local homography near the cube.
    """
    cube_px = mm(CUBE_SIDE_MM)
    inset = mm(FIDUCIAL_INSET_MM)
    fid_side = mm(FIDUCIAL_MM)
    quiet_px = mm(FIDUCIAL_QUIET_MM)
    banner_y = inset + fid_side + quiet_px + mm(8.0)
    banner_h = mm(14.0)
    cube_x = (PAGE_W - cube_px) // 2
    cube_y = banner_y + banner_h + mm(10.0)

    gap = mm(4.0)
    side = mm(CUBE_ARUCO_MM)
    half = side // 2
    return {
        10: (cube_x - gap - half,          cube_y - gap - half),           # TL center
        11: (cube_x + cube_px + gap + half, cube_y - gap - half),          # TR center
        12: (cube_x + cube_px + gap + half, cube_y + cube_px + gap + half),# BR center
        13: (cube_x - gap - half,          cube_y + cube_px + gap + half), # BL center
    }


def cube_rect_in_page() -> tuple:
    """Return (x, y, side) in A4 pixel coords for the central cube area.

    Must match the layout produced by `make_sheet`.
    """
    inset = mm(FIDUCIAL_INSET_MM)
    fid_side = mm(FIDUCIAL_MM)
    quiet_px = mm(FIDUCIAL_QUIET_MM)
    banner_y = inset + fid_side + quiet_px + mm(8.0)
    banner_h = mm(14.0)
    cube_px = mm(CUBE_SIDE_MM)
    cube_x = (PAGE_W - cube_px) // 2
    cube_y = banner_y + banner_h + mm(10.0)
    return (cube_x, cube_y, cube_px)


def draw_corner_fiducial(img: Image.Image,
                         x: int, y: int, side: int,
                         marker_id: int,
                         quiet_mm: float = FIDUCIAL_QUIET_MM) -> None:
    """Paste a real ArUco marker from DICT_4X4_50 onto `img` at (x, y) with
    a white quiet zone of `quiet_mm` mm around it for robust detection.

    The total footprint is (side + 2*quiet_px) x (side + 2*quiet_px).
    The caller should account for this when positioning the fiducial.

    Falls back to a plain black square if OpenCV is not installed.
    """
    quiet_px = mm(quiet_mm)

    # White quiet zone rectangle first.
    d = ImageDraw.Draw(img)
    d.rectangle(
        (x - quiet_px, y - quiet_px, x + side + quiet_px, y + side + quiet_px),
        fill=BG,
    )

    if not _HAS_CV2 or cv2 is None:
        d.rectangle((x, y, x + side, y + side), fill=INK)
        return

    aruco = cv2.aruco
    dictionary = aruco.getPredefinedDictionary(getattr(aruco, ARUCO_DICT_NAME))
    # borderBits=1 to match the dictionary definition; we draw a thick black
    # frame AROUND the marker via PIL to boost detection at distance.
    marker = aruco.generateImageMarker(dictionary, marker_id, side, borderBits=1)
    arr = np.stack([marker, marker, marker], axis=-1)
    img.paste(Image.fromarray(arr, mode="RGB"), (x, y))

    # Thick black frame around the marker (2 px on the A4 canvas = 0.17 mm,
    # purely cosmetic for human visibility; the quiet zone handles detection).
    frame_w = max(3, side // 40)
    d.rectangle(
        (x - frame_w, y - frame_w, x + side + frame_w, y + side + frame_w),
        outline=INK, width=frame_w,
    )


# ---------- Crop marks ----------

def draw_crop_marks(d: ImageDraw.ImageDraw,
                    margin_px: int, length_px: int = 60, w: int = 3) -> None:
    """L-shaped crop marks just outside the safe area, all four corners."""
    W, H = PAGE_W, PAGE_H
    m = margin_px
    # TL
    d.line((m, m + length_px, m, m), fill=INK, width=w)
    d.line((m, m, m + length_px, m), fill=INK, width=w)
    # TR
    d.line((W - m - length_px, m, W - m, m), fill=INK, width=w)
    d.line((W - m, m, W - m, m + length_px), fill=INK, width=w)
    # BL
    d.line((m, H - m - length_px, m, H - m), fill=INK, width=w)
    d.line((m, H - m, m + length_px, H - m), fill=INK, width=w)
    # BR
    d.line((W - m, H - m - length_px, W - m, H - m), fill=INK, width=w)
    d.line((W - m - length_px, H - m, W - m, H - m), fill=INK, width=w)


# ---------- Scale bar ----------

def draw_scale_bar(d: ImageDraw.ImageDraw,
                   x: int, y: int, length_mm: float,
                   font: "ImageFont.FreeTypeFont | ImageFont.ImageFont") -> None:
    """Horizontal calibration ruler with 10 mm ticks and a 50 mm label."""
    L = mm(length_mm)
    h = mm(3.0)
    d.rectangle((x, y, x + L, y + h), fill=INK)
    # 10 mm ticks (above the bar)
    for i in range(int(length_mm) // 10 + 1):
        tx = x + mm(i * 10.0)
        tick_h = mm(2.0) if i % 5 == 0 else mm(1.2)
        d.line((tx, y - tick_h, tx, y), fill=INK, width=2)
    label = f"{int(length_mm)} mm calibration"
    d.text((x + L + mm(3.0), y - mm(2.5)), label, font=font, fill=INK)


# ---------- The sheet ----------

def make_sheet(symbols, role: str, label: str, hash_hex: str,
               extra_lines: Optional[list] = None,
               cube_renderer=None, egg=None) -> Image.Image:
    """Compose the full A4 page.

    cube_renderer:
        Optional ``callable(symbols, size) -> PIL.Image`` used to draw the
        central cube. Defaults to ``eopx.metatron.render``. Pass a closure
        wrapping ``render_seal_revealed`` to emit an EPX-H "seal" badge while
        keeping the page's validated page-corner ArUco fiducials unchanged.
    egg:
        Optional :class:`eopx.egg_token.GoldenEgg` won by this vault. When
        given, its emblem is engraved in the right margin beside the cube
        (brand/legend, not security — the signed EggSeal is the real record).
    """
    img = Image.new("RGB", (PAGE_W, PAGE_H), BG)
    d = ImageDraw.Draw(img)

    margin = mm(SAFE_MARGIN_MM)
    draw_crop_marks(d, margin)

    # --- Fiducials (4 corners) ---
    fid_side = mm(FIDUCIAL_MM)
    quiet_px = mm(FIDUCIAL_QUIET_MM)
    inset = mm(FIDUCIAL_INSET_MM)
    # The OUTER corner of each fiducial is at `inset` from the page edge.
    # The quiet zone extends quiet_px beyond the marker on each side.
    draw_corner_fiducial(img, inset,                inset,                fid_side, 0)  # TL
    draw_corner_fiducial(img, PAGE_W - inset - fid_side, inset,           fid_side, 1)  # TR
    draw_corner_fiducial(img, PAGE_W - inset - fid_side, PAGE_H - inset - fid_side, fid_side, 2)  # BR
    draw_corner_fiducial(img, inset,                PAGE_H - inset - fid_side, fid_side, 3)  # BL

    # --- Banner (role) ---
    banner_y = inset + fid_side + quiet_px + mm(8.0)
    banner_h = mm(14.0)
    is_private = role.lower() == "private"
    banner_fill = (252, 224, 224) if is_private else (220, 232, 245)
    banner_text_color = WARN if is_private else (10, 60, 110)
    d.rectangle(
        (inset, banner_y, PAGE_W - inset, banner_y + banner_h),
        fill=banner_fill, outline=INK, width=2,
    )
    title_font = load_font(mm(7.0))
    sub_font = load_font(mm(3.2))
    title_txt = ("PRIVATE INSCRIPTION  -  DO NOT SHARE"
                 if is_private else "PUBLIC RENDER  -  shareable")
    tw = d.textlength(title_txt, font=title_font)
    d.text(
        ((PAGE_W - tw) / 2, banner_y + mm(2.5)),
        title_txt, font=title_font, fill=banner_text_color,
    )
    sub_txt = f"Metatron canvas v1   /   {label}"
    sw = d.textlength(sub_txt, font=sub_font)
    d.text(
        ((PAGE_W - sw) / 2, banner_y + mm(9.5)),
        sub_txt, font=sub_font, fill=SOFT,
    )

    # --- Cube ---
    cube_px = mm(CUBE_SIDE_MM)
    # Render the cube at native printable resolution (~1772 px @ 150 mm @ 300 DPI).
    cube_img = (cube_renderer or render)(symbols, size=cube_px)
    cube_x = (PAGE_W - cube_px) // 2
    cube_y = banner_y + banner_h + mm(10.0)
    img.paste(cube_img, (cube_x, cube_y))
    # Thin frame around the cube for visual containment.
    d.rectangle(
        (cube_x - 2, cube_y - 2, cube_x + cube_px + 2, cube_y + cube_px + 2),
        outline=(140, 140, 140), width=1,
    )

    # --- Golden-egg emblem (engraved in the right margin when won) ---
    if egg is not None:
        from eopx.metatron.egg_emblem import render_egg_emblem
        em_px = mm(30.0)
        em_x = cube_x + cube_px + mm(7.0)
        em_y = cube_y + (cube_px - em_px) // 2
        # The corner fiducials sit at top/bottom; the emblem is at the cube's
        # mid-height, so it only needs to clear the right safe margin.
        if em_x + em_px <= PAGE_W - inset:
            emblem = render_egg_emblem(egg, size=em_px)
            img.paste(emblem, (em_x, em_y), emblem)  # RGBA alpha mask
            tag_font = load_font(mm(2.8))
            tag = "GOLDEN EGG WON"
            d.text((em_x, em_y - mm(4.5)), tag, font=tag_font, fill=(150, 120, 0))
            # Strip the tier glyph from the name: this line uses the page's
            # latin font, which may lack ☾/✦/◈/▣/✸ (the emblem itself carries
            # the glyph in a symbol font).
            name = getattr(egg, "name", "")
            glyph = getattr(egg, "glyph", "")
            if glyph:
                name = name.replace(glyph, "").replace("  ", " ").strip()
            name_font = load_font(mm(2.2))
            d.text((em_x, em_y + em_px + mm(1.0)),
                   name, font=name_font, fill=SOFT)

    # --- Cube-adjacent ArUco markers (DISABLED: not reliably detected by OpenCV) ---
    # These would provide local rectification but OpenCV fails to detect them
    # on the dense A4 sheet. The page-corner ArUco (IDs 0-3) remains the primary method.

    # --- Scale bar ---
    scale_y = cube_y + cube_px + mm(5.0)
    draw_scale_bar(d, cube_x, scale_y, SCALE_BAR_MM, sub_font)

    # --- Footer: compact hash (2 lines) ---
    foot_y = scale_y + mm(4.0)
    small_font = load_font(mm(2.2))

    role_word = "seed" if is_private else "spinor"
    d.text((cube_x, foot_y), f"{role_word}: {hash_hex[:32]} {hash_hex[32:]}",
           font=small_font, fill=INK)
    foot_y += mm(3.0)
    checksum = hashlib.sha3_256(hash_hex.encode("ascii")).hexdigest()[:16]
    d.text((cube_x, foot_y),
           f"SHA3-256[:16]={checksum}",
           font=small_font, fill=SOFT)
    foot_y += mm(3.0)

    if extra_lines:
        for line in extra_lines:
            d.text((cube_x, foot_y), line, font=small_font, fill=SOFT)
            foot_y += mm(3.0)

    # --- Chromatic scan grid (6-color base-6 encoding) ---
    from eopx.metatron.grid_render import render_grid_on_a4, GRID_ROWS, GRID_COLS
    grid_cell_mm = 3.5
    grid_cell_px = mm(grid_cell_mm)
    grid_gap_px = max(2, grid_cell_px // 10)
    grid_header_px = max(14, grid_cell_px // 2)
    grid_w = grid_header_px + grid_gap_px + GRID_COLS * (grid_cell_px + grid_gap_px) + grid_gap_px
    grid_h = grid_header_px + grid_gap_px + GRID_ROWS * (grid_cell_px + grid_gap_px) + grid_gap_px
    grid_x = (PAGE_W - grid_w) // 2
    grid_y = foot_y + mm(2.0)
    # Only render if it fits before the warning strip
    warn_y_estimate = PAGE_H - inset - fid_side - mm(14.0)
    if grid_y + grid_h + mm(2.0) < warn_y_estimate:
        render_grid_on_a4(img, symbols, grid_y, grid_x, grid_cell_px)

    # --- Bottom warning strip for PRIVATE ---
    if is_private:
        warn_y = PAGE_H - inset - fid_side - mm(14.0)
        warn_h = mm(8.0)
        d.rectangle((inset, warn_y, PAGE_W - inset, warn_y + warn_h),
                    fill=(252, 232, 232), outline=WARN, width=2)
        warn_txt = ("WARNING: this sheet reconstructs a 256-bit secret. "
                    "Store offline. Do not photograph in public.")
        wfont = load_font(mm(3.0))
        ww = d.textlength(warn_txt, font=wfont)
        d.text(((PAGE_W - ww) / 2, warn_y + mm(2.2)),
               warn_txt, font=wfont, fill=WARN)

    return img


# ---------- Input resolution ----------

def _resolve_inputs(args) -> Tuple[list, str, str, str]:
    """Return (symbols, role, hash_hex, label) from the CLI arguments."""
    role = args.role.lower()

    if args.passphrase is not None:
        seed = hashlib.sha3_256(args.passphrase.encode("utf-8")).digest()
        hash_hex = seed.hex()
        label = f"passphrase = {args.passphrase!r}"
        if role == "public":
            spinor = hashlib.sha3_512(args.passphrase.encode("utf-8")
                                       + b".public").digest()
            return encode_public(spinor), role, spinor.hex(), label
        return encode_private(seed), role, hash_hex, label

    if args.seed is not None:
        seed = bytes.fromhex(args.seed.strip())
        if len(seed) != 32:
            raise SystemExit("--seed must be exactly 32 bytes (64 hex chars)")
        if role != "private":
            raise SystemExit("--seed is only valid with --role private")
        return encode_private(seed), role, seed.hex(), "user-provided seed"

    if args.spinor is not None:
        spinor = bytes.fromhex(args.spinor.strip())
        if len(spinor) not in (32, 48, 64):
            raise SystemExit(
                "--spinor must be 32, 48 or 64 bytes (64/96/128 hex chars); "
                "Eidolon Phase 6 produces 64 bytes."
            )
        if role != "public":
            raise SystemExit("--spinor is only valid with --role public")
        return encode_public(spinor), role, spinor.hex(), "user-provided spinor_hash"

    if args.random:
        if role == "private":
            seed = secrets.token_bytes(32)
            return encode_private(seed), role, seed.hex(), "RANDOM SEED (testing only)"
        spinor = secrets.token_bytes(64)
        return encode_public(spinor), role, spinor.hex(), "RANDOM SPINOR (testing only)"

    raise SystemExit(
        "no input provided: use one of --seed / --spinor / --passphrase / --random"
    )


# ---------- Golden-egg resolution ----------

def _resolve_egg(vault_hex: str):
    """Compute the Golden Egg a vault wins from the committed Genesis block.

    Reads ``ESOPTRON_BTC_BLOCK_HASH`` / ``ESOPTRON_BTC_BLOCK_HEIGHT`` (the
    committed block, see ``docs/GENESIS_COMMITMENT.md``). Exits with a clear
    message if no block is committed.
    """
    from eopx.egg_token import founder_egg

    blk = os.environ.get("ESOPTRON_BTC_BLOCK_HASH", "").strip()
    if not blk:
        raise SystemExit(
            "--egg-vault needs a committed Genesis block: set "
            "ESOPTRON_BTC_BLOCK_HASH (and ESOPTRON_BTC_BLOCK_HEIGHT)."
        )
    try:
        block = bytes.fromhex(blk)
    except ValueError:
        raise SystemExit("ESOPTRON_BTC_BLOCK_HASH must be valid hex")
    if len(block) != 32:
        raise SystemExit("ESOPTRON_BTC_BLOCK_HASH must be 32 bytes (64 hex)")
    h = os.environ.get("ESOPTRON_BTC_BLOCK_HEIGHT", "").strip()
    height = int(h) if h.isdigit() else 900_000
    try:
        vault_fp = bytes.fromhex(vault_hex.strip())
    except ValueError:
        raise SystemExit("--egg-vault must be a hex vault fingerprint")
    return founder_egg(vault_fp, block, height)


# ---------- CLI ----------

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="print_sheet",
        description="Generate a print-ready A4 sheet (300 DPI) carrying a Metatron cube.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__ or "").strip(),
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--seed", help="32-byte secret seed in hex (private inscription)")
    src.add_argument("--spinor", help="32/48/64-byte spinor_hash in hex (public render)")
    src.add_argument("--passphrase", help="UTF-8 passphrase; SHA3-256 -> seed, SHA3-512 -> spinor")
    src.add_argument("--random", action="store_true",
                     help="Generate a fresh random seed/spinor (testing only)")
    p.add_argument("--role", choices=("private", "public"), required=True,
                   help="Determines banner, encoder path, and warning strip.")
    p.add_argument("--out", required=True, help="Output PNG path (A4 @ 300 DPI).")
    p.add_argument("--pdf", help="Optional secondary PDF output (uses Pillow's PDF writer).")
    p.add_argument("--egg-vault", metavar="HEX",
                   help="64-hex vault fingerprint: engrave the Golden Egg this "
                        "vault wins from the committed Genesis block "
                        "(needs ESOPTRON_BTC_BLOCK_HASH / _HEIGHT).")
    args = p.parse_args(argv[1:])

    symbols, role, hash_hex, label = _resolve_inputs(args)

    egg = _resolve_egg(args.egg_vault) if args.egg_vault else None
    img = make_sheet(symbols, role, label, hash_hex, egg=egg)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Embed physical DPI so the file is recognized as A4 by print dialogs.
    img.save(out_path, format="PNG", dpi=(DPI, DPI), optimize=False)
    print(f"wrote {out_path}  ({out_path.stat().st_size} bytes, "
          f"{PAGE_W}x{PAGE_H} @ {DPI} DPI)")

    if args.pdf:
        pdf_path = Path(args.pdf)
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        # Pillow's native PDF writer is sufficient for a 1-page raster page.
        img.save(pdf_path, format="PDF", resolution=DPI)
        print(f"wrote {pdf_path}  ({pdf_path.stat().st_size} bytes, PDF)")

    print()
    print(f"role        : {role}")
    print(f"label       : {label}")
    print(f"{ 'seed' if role == 'private' else 'spinor' } hex  : {hash_hex}")
    print(f"check[:16]  : {hashlib.sha3_256(hash_hex.encode('ascii')).hexdigest()[:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
