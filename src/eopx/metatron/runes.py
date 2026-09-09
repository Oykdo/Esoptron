"""EPX-R §3 — the sixteen runes, and how to draw one.

A *rune* is a glyph state, not a symbol of the code. EPX-R decouples the two on
purpose (§1): sixteen visual states are easy to discriminate under a camera,
while the error-correcting code lives in a field chosen for long blocks. This
module owns the visual half — the bijection ``R[i] <-> i in F_16`` and a
renderer for it — and knows nothing about Reed-Solomon.

The strokes below are the set whose confusion matrix was measured in
``scripts/rune_channel.py`` (per-cell error rate under blur, tilt, JPEG and
noise). That measurement is only meaningful while the glyphs it measured are
the glyphs that ship, so the study now imports this table rather than carrying
its own copy: there is one alphabet, and changing a coordinate here invalidates
a measurement rather than silently diverging from it.

Coordinates are stroke endpoints ``(x0, y0, x1, y1)`` in the unit square, y
down, so a cell can be drawn at any size. Glyphs were chosen for distinct
stroke *topology* — stave present or absent, branch count, branch side — rather
than for weight, because blur destroys weight long before it destroys topology.
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

from PIL import Image, ImageDraw

Stroke = Tuple[float, float, float, float]

#: The vertical stave, shared by most glyphs. Its presence or absence is the
#: first bit a blurred read still recovers.
_STAVE: Stroke = (0.5, 0.10, 0.5, 0.90)

#: ``RUNES[i]`` are the strokes of the rune carrying ``i in F_16``. FROZEN
#: alongside the confusion matrix that measured them.
RUNES: Dict[int, List[Stroke]] = {
    0:  [_STAVE],                                                # Isa
    1:  [_STAVE, (0.5, 0.20, 0.85, 0.35), (0.5, 0.45, 0.85, 0.60)],  # Fehu
    2:  [(0.25, 0.16, 0.80, 0.50), (0.80, 0.50, 0.25, 0.84)],    # Kenaz
    3:  [(0.20, 0.10, 0.80, 0.90), _STAVE],                      # Eihwaz
    4:  [(0.20, 0.20, 0.80, 0.80), (0.80, 0.20, 0.20, 0.80)],    # Gebo
    5:  [_STAVE, (0.5, 0.30, 0.82, 0.50), (0.82, 0.50, 0.5, 0.70)],  # Thurisaz
    6:  [(0.5, 0.20, 0.82, 0.50), (0.82, 0.50, 0.5, 0.80),
         (0.5, 0.80, 0.18, 0.50), (0.18, 0.50, 0.5, 0.20)],      # Ingwaz
    7:  [_STAVE, (0.5, 0.30, 0.82, 0.10), (0.5, 0.30, 0.18, 0.10)],  # Algiz
    8:  [(0.82, 0.15, 0.40, 0.40), (0.40, 0.40, 0.82, 0.60),
         (0.82, 0.60, 0.40, 0.85)],                              # Sowilo
    9:  [_STAVE, (0.20, 0.50, 0.80, 0.50)],                      # Nauthiz
    10: [_STAVE, (0.5, 0.10, 0.82, 0.30), (0.82, 0.30, 0.5, 0.50),
         (0.5, 0.50, 0.82, 0.90)],                               # Raido
    11: [_STAVE, (0.5, 0.10, 0.80, 0.25), (0.80, 0.25, 0.5, 0.40),
         (0.5, 0.50, 0.80, 0.65), (0.80, 0.65, 0.5, 0.80)],      # Berkanan
    12: [_STAVE, (0.5, 0.10, 0.82, 0.32)],                       # Laguz
    13: [_STAVE, (0.5, 0.10, 0.80, 0.25), (0.80, 0.25, 0.5, 0.40)],  # Wunjo
    14: [_STAVE, (0.5, 0.10, 0.82, 0.30), (0.5, 0.10, 0.18, 0.30)],  # Tiwaz
    15: [(0.5, 0.12, 0.74, 0.34), (0.74, 0.34, 0.5, 0.56),
         (0.5, 0.56, 0.26, 0.34), (0.26, 0.34, 0.5, 0.12),
         (0.5, 0.56, 0.30, 0.90), (0.5, 0.56, 0.70, 0.90)],      # Othala
}

#: Names, in ``RUNES`` order. Latinised Younger-Futhark labels; two glyphs are
#: geometric rather than historical and take the nearest traditional name.
RUNE_NAMES: List[str] = [
    "Isa", "Fehu", "Kenaz", "Eihwaz", "Gebo", "Thurisaz", "Ingwaz", "Algiz",
    "Sowilo", "Nauthiz", "Raido", "Berkanan", "Laguz", "Wunjo", "Tiwaz",
    "Othala",
]

#: Cells per rune. One rune carries one F_16 symbol — four bits.
RUNE_BITS = 4
NUM_RUNES = 16

assert len(RUNES) == NUM_RUNES
assert len(RUNE_NAMES) == NUM_RUNES

#: Stroke width as a fraction of the cell side. Thin enough that adjacent
#: strokes of Berkanan stay separate, thick enough to survive downsampling.
STROKE_FRACTION = 0.085

#: Fraction of the cell left blank on every side. Runes that touch their cell
#: border blur into their neighbours before they blur into illegibility.
CELL_PADDING = 0.12


def rune_strokes(value: int) -> List[Stroke]:
    """The strokes of the rune carrying ``value``, in the unit square."""
    if not 0 <= value < NUM_RUNES:
        raise ValueError(f"rune value {value} outside F_{NUM_RUNES}")
    return list(RUNES[value])


def draw_rune(draw: ImageDraw.ImageDraw, value: int,
              x: float, y: float, size: float,
              fill: Tuple[int, int, int] = (0, 0, 0),
              width: int | None = None) -> None:
    """Draw one rune into the ``size``-sided cell whose top-left is (x, y)."""
    inner = size * (1.0 - 2.0 * CELL_PADDING)
    ox = x + size * CELL_PADDING
    oy = y + size * CELL_PADDING
    w = width if width is not None else max(1, round(size * STROKE_FRACTION))
    for x0, y0, x1, y1 in rune_strokes(value):
        draw.line((ox + x0 * inner, oy + y0 * inner,
                   ox + x1 * inner, oy + y1 * inner),
                  fill=fill, width=w)


def rune_image(value: int, size: int,
               fill: Tuple[int, int, int] = (0, 0, 0),
               bg: Tuple[int, int, int] = (255, 255, 255),
               supersample: int = 4) -> Image.Image:
    """A single rune on its own square canvas, antialiased by supersampling.

    PIL draws hard-edged lines; at print-plate cell sizes an aliased stave
    reads as a ladder. Drawing large and resampling down is cheaper than a
    polygon renderer and is what the plate renderer does too.
    """
    if size <= 0:
        raise ValueError("size must be positive")
    big = size * max(1, supersample)
    img = Image.new("RGB", (big, big), bg)
    draw_rune(ImageDraw.Draw(img), value, 0, 0, big, fill)
    if big != size:
        img = img.resize((size, size), Image.LANCZOS)
    return img


def rune_row(values: Sequence[int], sep: str = " ") -> str:
    """Debug helper: the values of a row as hex digits, not glyphs."""
    return sep.join(f"{v:x}" for v in values)


__all__ = [
    "RUNES", "RUNE_NAMES", "RUNE_BITS", "NUM_RUNES",
    "STROKE_FRACTION", "CELL_PADDING",
    "rune_strokes", "draw_rune", "rune_image", "rune_row",
]
