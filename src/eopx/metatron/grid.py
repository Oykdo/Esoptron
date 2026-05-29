"""Chromatic grid: 6 ultra-contrast colors for phone-camera scanning.

The Metatron K_13 cube uses 13 perceptually-close colors that are hard to
classify from phone photos. This module provides an alternative "scan layer":
a 6-color grid that encodes the same 91 F_13 symbols using pairs of base-6
digits. Each color is maximally distinguishable even under white-balance
shift and JPEG compression.

Encoding:
    91 F_13 symbols → 7 RS blocks × 13 symbols → pairs of base-6 digits
    (since 6^2 = 36 > 13, each F_13 symbol maps to a unique base-6 pair)
    Grid layout: 6 rows × 16 columns = 96 cells (91 data + 5 padding)

The grid is rendered alongside the K_13 cube on the A4 sheet. The phone
camera detects the numbered row/column headers and reads the colors.
"""

from __future__ import annotations

import math
from typing import List, Tuple

# 6 ultra-contrast colors in OKLCH.
# Chosen for maximum inter-color distance and robustness to WB shift:
#   - High chroma (C ≥ 0.20) so colors stay saturated under any lighting
#   - Moderate lightness (L 0.50-0.60) so they're visible on white background
#   - Evenly spaced hues (60° apart) for maximum hue separation
GRID_OKLCH: List[Tuple[float, float, float]] = [
    (0.55, 0.28,  25.0),   # 0 = Vermillon  (red-orange)
    (0.58, 0.25,  85.0),   # 1 = Or          (yellow-orange)
    (0.55, 0.26, 160.0),   # 2 = Emeraude    (green)
    (0.50, 0.22, 220.0),   # 3 = Cobalt      (blue)
    (0.45, 0.28, 290.0),   # 4 = Violet      (purple)
    (0.50, 0.26, 340.0),   # 5 = Magenta     (pink)
]

GRID_NAMES = ["Vermillon", "Or", "Emeraude", "Cobalt", "Violet", "Magenta"]

# --- Encoding: F_13 symbol (0-12) -> base-6 pair (hi, lo) ---
# 13 symbols, each mapped to a unique pair (a, b) with a in {0..2}, b in {0..5}
# Using base-6 with hi digit 0-2 (3 values) × lo digit 0-5 (6 values) = 18 ≥ 13
_F13_TO_B6: List[Tuple[int, int]] = []
_B6_TO_F13: dict = {}
for s in range(13):
    hi = s // 6   # 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2
    lo = s % 6    # 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0
    _F13_TO_B6.append((hi, lo))
    _B6_TO_F13[(hi, lo)] = s


GRID_ROWS = 12
GRID_COLS = 16


def f13_to_grid_pair(symbol: int) -> Tuple[int, int]:
    """Map an F_13 symbol (0-12) to a base-6 pair (hi_color, lo_color)."""
    if not (0 <= symbol < 13):
        raise ValueError(f"symbol {symbol} out of F_13")
    return _F13_TO_B6[symbol]


def grid_pair_to_f13(hi: int, lo: int) -> int:
    """Map a base-6 pair back to F_13 symbol. Returns -1 if invalid."""
    return _B6_TO_F13.get((hi, lo), -1)


def encode_grid(symbols: List[int]) -> List[Tuple[int, int]]:
    """Encode 91 F_13 symbols into a 6×16 grid of (row_color, col_color) pairs.

    Each F_13 symbol becomes two cells: the row index encodes the hi digit,
    the column encodes the lo digit. Actually, simpler approach: each cell
    stores one base-6 digit, and adjacent pairs (cell 2k, cell 2k+1) encode
    one F_13 symbol.

    Grid layout: 6 rows × 16 columns = 96 cells.
    91 symbols → 182 base-6 digits. But that's too many for 96 cells.

    Better: each cell holds ONE F_13 symbol encoded as a single color
    chosen from 6 "row colors", with the column position encoding the
    value within that row. Actually the simplest robust encoding:

    Each cell = one base-6 digit (one of 6 colors).
    Pairs of consecutive cells = one F_13 symbol.
    91 symbols × 2 digits = 182 cells needed.
    Grid 12×16 = 192 cells (182 data + 10 padding).
    Or grid 6×32 = 192 cells.
    """
    if len(symbols) != 91:
        raise ValueError(f"expected 91 symbols, got {len(symbols)}")

    digits: List[int] = []
    for s in symbols:
        hi, lo = f13_to_grid_pair(s)
        digits.append(hi)
        digits.append(lo)
    # 182 digits. Pad to 192 (12×16) with zeros.
    while len(digits) < 192:
        digits.append(0)
    return [(digits[2 * k], digits[2 * k + 1]) for k in range(96)]


def decode_grid(colors: List[int]) -> List[int]:
    """Decode a list of 96 grid-color indices (0-5) back to 91 F_13 symbols.

    Each pair of consecutive colors encodes one F_13 symbol via base-6.
    """
    if len(colors) < 182:
        raise ValueError(f"need at least 182 color indices, got {len(colors)}")

    symbols: List[int] = []
    for k in range(91):
        hi = colors[2 * k]
        lo = colors[2 * k + 1]
        s = grid_pair_to_f13(hi, lo)
        if s < 0:
            raise ValueError(f"invalid base-6 pair ({hi}, {lo}) at position {k}")
        symbols.append(s)
    return symbols


# --- Color conversion (reuse from palette.py) ---

def _oklch_to_oklab(L: float, C: float, h_deg: float) -> Tuple[float, float, float]:
    h = math.radians(h_deg)
    return (L, C * math.cos(h), C * math.sin(h))


def _oklab_to_linear_srgb(L: float, a: float, b: float) -> Tuple[float, float, float]:
    l_ = L + 0.3963377774 * a + 0.2158037573 * b
    m_ = L - 0.1055613458 * a - 0.0638541728 * b
    s_ = L - 0.0894841775 * a - 1.2914855480 * b
    l = l_ ** 3
    m = m_ ** 3
    s = s_ ** 3
    r = +4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s
    g = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s
    bl = -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s
    return (r, g, bl)


def _gamma_encode(c: float) -> float:
    c = max(0.0, min(1.0, c))
    if c <= 0.0031308:
        return 12.92 * c
    return 1.055 * (c ** (1.0 / 2.4)) - 0.055


def grid_srgb(index: int) -> Tuple[int, int, int]:
    """Return 8-bit sRGB for grid color index (0-5)."""
    if not (0 <= index < 6):
        raise ValueError(f"grid color index {index} out of range 0-5")
    L, C, h = GRID_OKLCH[index]
    r, g, b = _oklab_to_linear_srgb(*_oklch_to_oklab(L, C, h))
    return (
        max(0, min(255, round(_gamma_encode(r) * 255))),
        max(0, min(255, round(_gamma_encode(g) * 255))),
        max(0, min(255, round(_gamma_encode(b) * 255))),
    )


def grid_palette_srgb() -> List[Tuple[int, int, int]]:
    """Return all 6 grid colors as sRGB triples."""
    return [grid_srgb(i) for i in range(6)]


def classify_grid_color(r: int, g: int, b: int) -> Tuple[int, float]:
    """Classify an sRGB triple as one of 6 grid colors.

    Returns (index, oklab_distance). More robust than the 13-color
    classifier because the 6 colors have much larger inter-color gaps.
    """
    from .palette import srgb255_to_oklab
    target = srgb255_to_oklab(r, g, b)

    # Precompute grid palette in Oklab
    if not hasattr(classify_grid_color, '_cache'):
        classify_grid_color._cache = [
            srgb255_to_oklab(*grid_srgb(i)) for i in range(6)
        ]

    best = 0
    best_d2 = float('inf')
    for idx, pal in enumerate(classify_grid_color._cache):
        d2 = sum((t - p) ** 2 for t, p in zip(target, pal))
        if d2 < best_d2:
            best_d2 = d2
            best = idx
    return best, best_d2 ** 0.5
