"""Render a Golden Egg emblem — the insignia engraved beside a Metatron
cube when the vault has won an egg (EPX-E).

This is **brand / legend**, not security (POSITIONING): the emblem is a
decorative mark celebrating a deterministic win. The cryptographic record
of the win is the signed ``EggSeal`` on the anchor, never the drawing.

The function is duck-typed on the egg object — it reads ``.tier``,
``.glyph``, ``.egg_id`` and ``.tier`` only — so it does not import
:mod:`eopx.egg_token` (keeps the metatron package free of that dependency).
Pass any :class:`eopx.egg_token.GoldenEgg`.
"""

from __future__ import annotations

import os
from typing import Tuple

from PIL import Image, ImageDraw, ImageFont

RGB = Tuple[int, int, int]

# tier -> (light fill / highlight, base body, dark accent + glyph)
TIER_PALETTE: dict[str, Tuple[RGB, RGB, RGB]] = {
    "Cosmic": ((232, 214, 250), (138, 43, 226), (74, 20, 120)),
    "Stellar": ((250, 240, 205), (212, 175, 55), (140, 105, 10)),
    "Lunar": ((232, 238, 248), (150, 170, 200), (70, 90, 130)),
    "Crystal": ((216, 244, 244), (64, 196, 200), (16, 110, 115)),
    "Stone": ((236, 230, 220), (165, 150, 128), (95, 82, 64)),
}
_DEFAULT_PALETTE: Tuple[RGB, RGB, RGB] = (
    (235, 235, 235), (150, 150, 150), (80, 80, 80))


def _load_font(size_px: int) -> "ImageFont.FreeTypeFont | ImageFont.ImageFont":
    """A font that carries the tier glyphs (☾ ✦ ◈ ▣ ✸) where possible."""
    candidates = [
        "C:/Windows/Fonts/seguisym.ttf",   # Segoe UI Symbol — has all glyphs
        "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size=size_px)
            except OSError:
                continue
    return ImageFont.load_default()


def tier_palette(tier: str) -> Tuple[RGB, RGB, RGB]:
    """``(light, base, dark)`` colours for a tier (fallback for unknown)."""
    return TIER_PALETTE.get(tier, _DEFAULT_PALETTE)


def render_egg_emblem(egg, size: int = 512, *,
                      with_caption: bool = True) -> Image.Image:
    """Return an ``RGBA`` emblem (transparent background) for ``egg``.

    ``size`` is the square canvas side in pixels. The egg body is tier-tinted
    with a soft highlight, the tier glyph sits centred, and (when
    ``with_caption``) a ``"GE-NNN · Tier"`` caption is drawn beneath.
    """
    light, base, dark = tier_palette(egg.tier)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    cx = size // 2
    egg_w = int(size * 0.52)
    egg_h = int(size * 0.68)
    top = int(size * 0.05)
    box = (cx - egg_w // 2, top, cx + egg_w // 2, top + egg_h)

    # Body, soft top-left highlight, then a crisp outline.
    d.ellipse(box, fill=base + (255,))
    hl_w, hl_h = int(egg_w * 0.46), int(egg_h * 0.38)
    hl_x = int(cx - egg_w * 0.08) - hl_w // 2
    hl_y = top + int(egg_h * 0.08)
    d.ellipse((hl_x, hl_y, hl_x + hl_w, hl_y + hl_h), fill=light + (150,))
    d.ellipse(box, outline=dark + (255,), width=max(3, size // 110))

    # Tier glyph, centred in the body.
    glyph_font = _load_font(int(size * 0.30))
    gw = d.textlength(egg.glyph, font=glyph_font)
    gy = top + int(egg_h * 0.50) - int(size * 0.19)
    d.text((cx - gw / 2, gy), egg.glyph, font=glyph_font, fill=dark + (255,))

    if with_caption:
        cap_font = _load_font(max(10, int(size * 0.085)))
        cap = f"{egg.egg_id} · {egg.tier}"
        cw = d.textlength(cap, font=cap_font)
        d.text((cx - cw / 2, top + egg_h + int(size * 0.015)),
               cap, font=cap_font, fill=dark + (255,))

    return img


__all__ = ["render_egg_emblem", "tier_palette", "TIER_PALETTE"]
