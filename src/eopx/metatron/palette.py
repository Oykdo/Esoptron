"""OKLCH -> sRGB conversion and the 13-symbol palette `metatron_oklch_v1`.

Whitepaper II, section 3.2.

OKLCH (Björn Ottosson, 2020) is a perceptually uniform polar variant of
OKLab. Using it for the 13 F_13 symbols guarantees that adjacent symbol
values are perceptually distinguishable with roughly equal magnitude.

The conversion below follows the public reference at
https://bottosson.github.io/posts/oklab/ -- no external dependency.
"""

from __future__ import annotations

import math
from typing import List, Tuple

# ---------------------------------------------------------------------------
# OKLCH -> Oklab -> linear sRGB -> sRGB
# ---------------------------------------------------------------------------

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


def oklch_to_srgb255(L: float, C: float, h_deg: float) -> Tuple[int, int, int]:
    Lab = _oklch_to_oklab(L, C, h_deg)
    r, g, b = _oklab_to_linear_srgb(*Lab)
    r8 = round(_gamma_encode(r) * 255.0)
    g8 = round(_gamma_encode(g) * 255.0)
    b8 = round(_gamma_encode(b) * 255.0)
    return (
        max(0, min(255, r8)),
        max(0, min(255, g8)),
        max(0, min(255, b8)),
    )


# ---------------------------------------------------------------------------
# `metatron_oklch_v1` -- 13 symbols, each (L, C, h) tuple
# ---------------------------------------------------------------------------

# `metatron_oklch_v2` -- 13 symbols for WHITE background
# Derived from v1 by capping L at 0.65 and boosting chroma for the
# previously-pale symbols. All hues preserved for continuity.
OKLCH_TABLE: List[Tuple[float, float, float]] = [
    (0.18, 0.02, 280.0),  # 0  Obsidienne
    (0.30, 0.18, 270.0),  # 1  Indigo
    (0.40, 0.20, 245.0),  # 2  Cobalt
    (0.52, 0.18, 220.0),  # 3  Cyan
    (0.48, 0.22, 160.0),  # 4  Emeraude
    (0.58, 0.24, 130.0),  # 5  Lime (was 0.78/0.20)
    (0.60, 0.20,  95.0),  # 6  Or (was 0.82/0.16)
    (0.55, 0.22,  70.0),  # 7  Ambre
    (0.50, 0.26,  30.0),  # 8  Vermillon
    (0.48, 0.26, 350.0),  # 9  Magenta
    (0.40, 0.26, 320.0),  # 10 Violet
    (0.42, 0.06, 240.0),  # 11 Ardoise
    (0.65, 0.03,  90.0),  # 12 Albâtre (was 0.92/0.02 -- too white)
]

SYMBOL_NAMES: List[str] = [
    "Obsidienne", "Indigo", "Cobalt", "Cyan", "Emeraude",
    "Lime", "Or", "Ambre", "Vermillon", "Magenta",
    "Violet", "Ardoise", "Albatre",
]

assert len(OKLCH_TABLE) == 13
assert len(SYMBOL_NAMES) == 13


def srgb_for_symbol(symbol: int) -> Tuple[int, int, int]:
    """Look up the 8-bit sRGB triple for an F_13 symbol."""
    if not (0 <= symbol < 13):
        raise ValueError(f"symbol {symbol} out of F_13")
    L, C, h = OKLCH_TABLE[symbol]
    return oklch_to_srgb255(L, C, h)


def palette_srgb() -> List[Tuple[int, int, int]]:
    """Return the full 13-entry sRGB palette."""
    return [srgb_for_symbol(s) for s in range(13)]


# ---------------------------------------------------------------------------
# Inverse direction: sRGB -> Oklab (for color classification during detection)
# ---------------------------------------------------------------------------

def _gamma_decode(c: float) -> float:
    """sRGB component in [0, 1] -> linear sRGB component."""
    if c <= 0.04045:
        return c / 12.92
    return ((c + 0.055) / 1.055) ** 2.4


def srgb255_to_oklab(r: int, g: int, b: int) -> Tuple[float, float, float]:
    """8-bit sRGB triple -> Oklab (L, a, b)."""
    rl = _gamma_decode(r / 255.0)
    gl = _gamma_decode(g / 255.0)
    bl = _gamma_decode(b / 255.0)

    # Linear sRGB -> LMS (Ottosson)
    l = 0.4122214708 * rl + 0.5363325363 * gl + 0.0514459929 * bl
    m = 0.2119034982 * rl + 0.6806995451 * gl + 0.1073969566 * bl
    s = 0.0883024619 * rl + 0.2817188376 * gl + 0.6299787005 * bl

    l_ = l ** (1.0 / 3.0) if l >= 0 else -((-l) ** (1.0 / 3.0))
    m_ = m ** (1.0 / 3.0) if m >= 0 else -((-m) ** (1.0 / 3.0))
    s_ = s ** (1.0 / 3.0) if s >= 0 else -((-s) ** (1.0 / 3.0))

    L = 0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_
    a = 1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_
    b_ = 0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_
    return (L, a, b_)


# Precomputed Oklab coordinates for each F_13 symbol -- used at every
# classification step. Cache once at import time.
_PALETTE_OKLAB: List[Tuple[float, float, float]] = [
    srgb255_to_oklab(*srgb_for_symbol(s)) for s in range(13)
]


def classify_color(r: int, g: int, b: int) -> Tuple[int, float]:
    """Classify an sRGB triple as one of the 13 F_13 symbols.

    Returns (symbol, distance_to_nearest). Distance is in Oklab units;
    typical inter-symbol spacing in the palette is around 0.15-0.30, so
    a classification with distance > 0.10 should be flagged as uncertain.

    Special: if the pixel is near-white (background), returns (12, 0.50)
    as a sentinel — the caller should treat this as an erasure.
    """
    target = srgb255_to_oklab(r, g, b)
    # Reject near-white/achromatic pixels (background).
    # In Oklab, white ≈ (1, 0, 0). If L > 0.80 and chroma < 0.03,
    # this is background, not a colored symbol.
    L, a, b_ = target
    chroma = (a ** 2 + b_ ** 2) ** 0.5
    if L > 0.80 and chroma < 0.05:
        return 12, 0.50  # sentinel: near-white → erasure candidate
    best_sym = 0
    best_d2 = float("inf")
    for sym, pal in enumerate(_PALETTE_OKLAB):
        d2 = (target[0] - pal[0]) ** 2 \
             + (target[1] - pal[1]) ** 2 \
             + (target[2] - pal[2]) ** 2
        if d2 < best_d2:
            best_d2 = d2
            best_sym = sym
    return best_sym, best_d2 ** 0.5


def palette_oklab() -> List[Tuple[float, float, float]]:
    """Expose the cached Oklab palette (read-only)."""
    return list(_PALETTE_OKLAB)
