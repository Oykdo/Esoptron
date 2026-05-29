"""13 simple geometric glyphs for the F_13 symbols.

Whitepaper II, section 3.3.

Each glyph is drawn as a small shape *on top of* the colored vertex disk,
in a contrasting tone, doubling the encoding (color + glyph) for robustness
against grayscale capture or color drift.

The shapes here are intentionally minimal -- the prototype prioritises
mathematical correctness over typographic polish. A future normative spec
will refine the stroke widths and proportions.
"""

from __future__ import annotations

import math
from typing import Tuple

from PIL import ImageDraw


GlyphFn = callable  # type alias documentation only


def _circle_full(d: ImageDraw.ImageDraw, cx: float, cy: float, r: float, color, stroke):
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=color)


def _circle_empty(d, cx, cy, r, color, stroke):
    d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=color, width=stroke)


def _ngon(d, cx, cy, r, n_sides, rotation_rad, color, stroke, fill=False):
    pts = []
    for i in range(n_sides):
        a = rotation_rad + 2.0 * math.pi * i / n_sides
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    if fill:
        d.polygon(pts, fill=color)
    else:
        d.polygon(pts, outline=color, width=stroke)


def _triangle_up(d, cx, cy, r, color, stroke):
    _ngon(d, cx, cy, r, 3, -math.pi / 2, color, stroke, fill=True)


def _triangle_down(d, cx, cy, r, color, stroke):
    _ngon(d, cx, cy, r, 3, math.pi / 2, color, stroke, fill=True)


def _square(d, cx, cy, r, color, stroke):
    _ngon(d, cx, cy, r, 4, math.pi / 4, color, stroke, fill=True)


def _diamond(d, cx, cy, r, color, stroke):
    _ngon(d, cx, cy, r, 4, 0, color, stroke, fill=True)


def _hexagon(d, cx, cy, r, color, stroke):
    _ngon(d, cx, cy, r, 6, 0, color, stroke, fill=True)


def _pentagon(d, cx, cy, r, color, stroke):
    _ngon(d, cx, cy, r, 5, -math.pi / 2, color, stroke, fill=True)


def _star(d, cx, cy, r, n_points, color, stroke, rotation=-math.pi / 2):
    pts = []
    for i in range(2 * n_points):
        a = rotation + math.pi * i / n_points
        rad = r if (i % 2 == 0) else r * 0.45
        pts.append((cx + rad * math.cos(a), cy + rad * math.sin(a)))
    d.polygon(pts, fill=color)


def _star5(d, cx, cy, r, color, stroke):
    _star(d, cx, cy, r, 5, color, stroke)


def _star6(d, cx, cy, r, color, stroke):
    _star(d, cx, cy, r, 6, color, stroke)


def _cross(d, cx, cy, r, color, stroke):
    w = max(2, int(r * 0.45))
    d.rectangle((cx - r, cy - w / 2, cx + r, cy + w / 2), fill=color)
    d.rectangle((cx - w / 2, cy - r, cx + w / 2, cy + r), fill=color)


def _x(d, cx, cy, r, color, stroke):
    w = max(2, int(r * 0.4))
    # diagonal 1
    pts1 = [
        (cx - r, cy - r + w),
        (cx - r + w, cy - r),
        (cx + r, cy + r - w),
        (cx + r - w, cy + r),
    ]
    pts2 = [
        (cx + r, cy - r + w),
        (cx + r - w, cy - r),
        (cx - r, cy + r - w),
        (cx - r + w, cy + r),
    ]
    d.polygon(pts1, fill=color)
    d.polygon(pts2, fill=color)


def _ring(d, cx, cy, r, color, stroke):
    w = max(2, int(r * 0.35))
    d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=color, width=w)


# Index by symbol value 0..12, matching Whitepaper II §3.2.
GLYPHS = [
    _circle_full,   # 0  Obsidienne
    _circle_empty,  # 1  Indigo
    _triangle_up,   # 2  Cobalt
    _triangle_down, # 3  Cyan
    _square,        # 4  Emeraude
    _diamond,       # 5  Lime
    _hexagon,       # 6  Or
    _pentagon,      # 7  Ambre
    _star5,         # 8  Vermillon
    _star6,         # 9  Magenta
    _cross,         # 10 Violet
    _x,             # 11 Ardoise
    _ring,          # 12 Albatre
]

assert len(GLYPHS) == 13


def draw_glyph(d: ImageDraw.ImageDraw,
               symbol: int,
               cx: float, cy: float, r: float,
               color: Tuple[int, int, int],
               stroke: int = 2) -> None:
    """Draw the glyph for `symbol` on draw context `d` at (cx, cy)."""
    if not (0 <= symbol < 13):
        raise ValueError(f"symbol {symbol} out of F_13")
    GLYPHS[symbol](d, cx, cy, r, color, stroke)
