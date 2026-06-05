"""Render the Esoptron Codex relics as images — the visual representation.

Each relic has a **deterministic graphic fingerprint**: a Metatron cube with
its EPX-H seal revealed, derived purely from the relic's key (so the image is
reproducible and unique per relic). This tool writes one PNG per relic plus a
contact sheet of all twelve — no keys, no anchor, just the visuals.

Usage
-----
::

    py scripts/render_codex.py --out-dir out/codex_badges --size 512

The per-relic PNGs are the same pixels the forge packs into the signed
``<key>.badge.eopx``; this script just lets you *see* the collection without
minting anything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from eopx.collection import CODEX
from eopx.collection.forge import render_relic_badge

# Element accent colours (RGB) — echo the seal palette used on the badges.
_ELEMENT_RGB = {
    "Fire": (210, 70, 40),
    "Water": (70, 130, 210),
    "Air": (210, 180, 90),
    "Earth": (90, 170, 110),
}
_BG = (10, 10, 20)
_FG = (236, 237, 243)
_DIM = (141, 143, 166)


def _font(size: int):
    """Best-effort TrueType for legible labels; fall back to the bitmap font."""
    for name in ("DejaVuSans.ttf", "arial.ttf", "Arial.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _contact_sheet(thumbs, cols: int, cell: int) -> Image.Image:
    rows = (len(thumbs) + cols - 1) // cols
    pad = max(8, cell // 24)
    label_h = max(22, cell // 7)
    cw, ch = cell + pad, cell + label_h + pad
    title_h = label_h + pad
    sheet = Image.new("RGB", (cols * cw + pad, rows * ch + pad + title_h), _BG)
    draw = ImageDraw.Draw(sheet)
    title_font = _font(max(16, cell // 12))
    name_font = _font(max(12, cell // 18))
    elem_font = _font(max(10, cell // 24))

    draw.text((pad, pad // 2), "The Esoptron Codex — twelve relics",
              fill=_FG, font=title_font)

    for i, (relic, thumb) in enumerate(thumbs):
        r, c = divmod(i, cols)
        x = pad + c * cw
        y = title_h + pad + r * ch
        sheet.paste(thumb, (x, y))
        col = _ELEMENT_RGB.get(relic.element, _FG)
        # element swatch + name + title
        draw.rectangle([x, y + cell + 2, x + cell, y + cell + 4], fill=col)
        draw.text((x + 2, y + cell + 5),
                  f"{relic.rank}. {relic.name}", fill=_FG, font=name_font)
        draw.text((x + 2, y + cell + 5 + (label_h // 2)),
                  f"{relic.element} · {relic.title}", fill=_DIM,
                  font=elem_font)
    return sheet


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--out-dir", default="out/codex_badges")
    p.add_argument("--size", type=int, default=512, help="per-relic PNG side")
    p.add_argument("--sheet-cell", type=int, default=256,
                   help="badge size inside the contact sheet")
    p.add_argument("--cols", type=int, default=4, help="contact-sheet columns")
    p.add_argument("--no-sheet", action="store_true",
                   help="skip the combined contact sheet")
    args = p.parse_args(argv[1:])

    out = Path(args.out_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)

    relics = sorted(CODEX, key=lambda r: r.rank)
    thumbs = []
    print(f"rendering {len(relics)} relic badges into {out}")
    for relic in relics:
        img = render_relic_badge(relic, size=args.size)
        path = out / f"{relic.key}.png"
        img.save(path, format="PNG")
        print(f"  #{relic.rank:>2} {relic.name:<18} {relic.element:<6} -> {path.name}")
        if not args.no_sheet:
            thumbs.append((relic, img.resize((args.sheet_cell, args.sheet_cell),
                                             Image.Resampling.LANCZOS)))

    if not args.no_sheet:
        sheet = _contact_sheet(thumbs, cols=args.cols, cell=args.sheet_cell)
        sheet_path = out / "codex.png"
        sheet.save(sheet_path, format="PNG")
        print(f"contact sheet: {sheet_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
