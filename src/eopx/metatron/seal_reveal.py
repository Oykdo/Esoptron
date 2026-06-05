"""Seal Revealed — Cryptographic Hexagram Modulation (EPX-H).

Renders a Metatron Cube in which the 78 structural lines are drawn at
**variable opacity** derived from the vault's cryptographic identity.
The Seal of Solomon (hexagram) **emerges** from the pre-existing
geometry: the vault fingerprint selects *which* genuine hexagram of
K_13 to reveal (discrete selection, EPX-H §2.4), and the spinor hash
colours its two triangles.

Three properties make the badge robust to *current mobile-phone
cameras* (EPX-H §5):

  A. **Exclusion mask** — seal/near/dim line pixels are never drawn
     inside the colour-sampling window the decoder uses around each of
     the 91 symbol carriers. The decoder locates carriers by "most
     colorful cluster"; keeping the seal out of those windows means it
     can never be mistaken for a symbol disk, even for the near-grey
     symbols (Obsidienne / Ardoise / Albâtre) that a saturation cap
     alone could not protect.

  B. **Saturation cap** — the seal's chroma is bounded below the bulk
     of the 13-symbol palette, so colour that bleeds *just outside* the
     mask under camera blur / JPEG chroma subsampling stays weaker than
     a real symbol.

  D. **Discrete star selection** — there is no continuous "rotation".
     K_13 contains exactly two regular hexagrams on real edges (inner
     ring → points at 0 deg, outer ring → points at 30 deg). The vault
     picks one; a second bit swaps the fire/water colour roles. Visual
     uniqueness is *reproduced* from the decoded data, never *measured*
     off the photo.

The 91 F_13 symbols, the fiducial markers, and every existing protocol
function are untouched. This is a *rendering mode*, not a protocol
addition.

Normative spec: ``docs/specs/EPX-H_seal_reveal.md``.
"""

from __future__ import annotations

import hashlib
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from PIL import Image, ImageChops, ImageDraw

from .graph import EDGES, NUM_EDGES, NUM_VERTICES, VERTICES, carrier_count
from .palette import srgb_for_symbol
from .render import (
    BACKGROUND,
    EDGE_TAG_RADIUS_FRAC,
    GLYPH_RADIUS_FRAC,
    VERTEX_RADIUS_FRAC,
    _project,
    edge_tag_position,
)
from .glyphs import draw_glyph

# ---------------------------------------------------------------------------
# EPX-H constants — frozen at v1
# ---------------------------------------------------------------------------

#: Domain separator for the star-selection KDF.
SEAL_DOMAIN = b"epx-h.seal_select.v1"

SEAL_EDGE_WIDTH = 4
NEAR_EDGE_WIDTH = 2
DIM_EDGE_WIDTH = 2

SEAL_ALPHA = 0.90
NEAR_ALPHA = 0.30
DIM_ALPHA = 0.08

DEFAULT_SEAL_SIZE = 1024

# Lightness values per tier (HSL L%).
L_SEAL_FIRE = 45
L_SEAL_WATER = 55
L_NEAR = 65
L_DIM = 80

# --- Mesure B: saturation cap -------------------------------------------------
# Seal chroma stays below the bulk of the OKLCH symbol palette so that any
# colour bleeding past the exclusion mask (camera blur, JPEG 4:2:0) is weaker
# than a genuine symbol disk. Derived saturation lands in [45, 60] %.
SEAL_SAT_BASE = 45
SEAL_SAT_SPAN = 16          # → max 60 %
SEAL_MAX_SATURATION = SEAL_SAT_BASE + SEAL_SAT_SPAN - 1  # 60

# --- Mesure A: exclusion mask -------------------------------------------------
# The decoder samples each edge tag inside a window of (r_tag + 8) px and each
# vertex out to r_v * 3 (sanity-bounded to r_v * 2). We punch the seal layer's
# alpha to 0 inside these radii so no line pixel can contaminate a sample.
TAG_CLEAR_PAD_FRAC = 0.014   # added to r_tag → ≈27 px at size 1024 (search ≈21 px)
VERTEX_CLEAR_MULT = 2.0      # × r_v → matches the refinement sanity bound

# ---------------------------------------------------------------------------
# Mesure D: discrete hexagram catalog
# ---------------------------------------------------------------------------
# K_13's two equal-radius rings each carry exactly one regular hexagram built
# from REAL edges (two interleaved equilateral triangles). These are the only
# clean Stars of Solomon embeddable in the cube; a continuous rotation would
# put the triangle points between vertices, off the existing edge set.
#
# Each entry: (name, fire_triangle, water_triangle, pointing_degrees)
STAR_CONFIGS: List[Tuple[str, Tuple[int, int, int], Tuple[int, int, int], int]] = [
    ("inner", (1, 3, 5), (2, 4, 6), 0),    # inner hexagon, radius 1, points at 0°
    ("outer", (7, 9, 11), (8, 10, 12), 30),  # outer hexagon, radius √3, points at 30°
]


def _digest(vault_fp: bytes) -> bytes:
    if len(vault_fp) != 32:
        raise ValueError("vault_fp must be 32 bytes")
    return hashlib.sha3_256(SEAL_DOMAIN + vault_fp).digest()


def select_star(vault_fp: bytes) -> int:
    """Derive the hexagram index (0..len(STAR_CONFIGS)-1) from the vault."""
    return _digest(vault_fp)[0] % len(STAR_CONFIGS)


def seal_color_swap(vault_fp: bytes) -> bool:
    """Derive whether the fire/water colour roles are swapped for this vault."""
    return bool(_digest(vault_fp)[1] & 1)


def star_pointing_degrees(star_index: int) -> int:
    """Nominal pointing angle of the revealed star, for the 'mon sceau pointe
    à X°' recognition channel."""
    return STAR_CONFIGS[star_index][3]


# ---------------------------------------------------------------------------
# Geometry: hexagram edges from the selected star
# ---------------------------------------------------------------------------

def _triangle_edges(corners: Tuple[int, int, int]) -> List[Tuple[int, int]]:
    """Return the 3 edges of a triangle in canonical (min, max) order."""
    edges = []
    for k in range(3):
        i, j = corners[k], corners[(k + 1) % 3]
        edges.append((min(i, j), max(i, j)))
    return edges


def fire_water_edges(
    star_index: int,
) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Return (fire_edges, water_edges), 3 each, for the selected star."""
    _name, fire_tri, water_tri, _deg = STAR_CONFIGS[star_index]
    return _triangle_edges(fire_tri), _triangle_edges(water_tri)


def seal_edges(star_index: int) -> List[Tuple[int, int]]:
    """Return the 6 hexagram edges of the selected star.

    Deterministic order: 3 fire-triangle edges followed by 3 water-triangle
    edges. Every edge is a genuine member of K_13's 78 edges.
    """
    fire, water = fire_water_edges(star_index)
    return fire + water


def classify_edges(
    seal_edge_list: List[Tuple[int, int]],
) -> Tuple[FrozenSet[Tuple[int, int]], FrozenSet[Tuple[int, int]]]:
    """Classify all 78 edges into (seal_set, near_set).

    Dim edges are implicit: any edge not in seal or near. "Near" = shares at
    least one vertex with a seal edge → a luminous halo around the star.
    """
    seal_set = frozenset(seal_edge_list)
    seal_vertices = set()
    for i, j in seal_edge_list:
        seal_vertices.add(i)
        seal_vertices.add(j)
    near_set = frozenset(
        (i, j) for i, j in EDGES
        if (i, j) not in seal_set and (i in seal_vertices or j in seal_vertices)
    )
    return seal_set, near_set


# ---------------------------------------------------------------------------
# Colour derivation from spinor_hash
# ---------------------------------------------------------------------------

def _hsl_to_rgb(h: int, s: int, l: int) -> Tuple[int, int, int]:
    """Convert HSL (h in [0,360), s in [0,100], l in [0,100]) to sRGB."""
    hn = h / 360.0
    sn = s / 100.0
    ln = l / 100.0

    if sn == 0:
        v = int(ln * 255)
        return (v, v, v)

    def _hue_to_rgb(p, q, t):
        if t < 0:
            t += 1
        if t > 1:
            t -= 1
        if t < 1 / 6:
            return p + (q - p) * 6 * t
        if t < 1 / 2:
            return q
        if t < 2 / 3:
            return p + (q - p) * (2 / 3 - t) * 6
        return p

    q = ln * (1 + sn) / 2 if ln < 0.5 else (ln + sn - ln * sn)
    p = 2 * ln - q
    r = _hue_to_rgb(p, q, hn + 1 / 3)
    g = _hue_to_rgb(p, q, hn)
    b = _hue_to_rgb(p, q, hn - 1 / 3)
    return (int(r * 255), int(g * 255), int(b * 255))


def derive_palette(
    spinor_hash: bytes, swap: bool = False
) -> Dict[str, Tuple[int, int, int]]:
    """Derive the seal colour palette from spinor_hash.

    Returns a dict with keys fire / water / near / dim. Saturation is capped
    (Mesure B) to keep the seal subordinate to the symbol palette. ``swap``
    exchanges the fire and water hues (a 1-bit vault-derived variation).
    """
    if len(spinor_hash) < 3:
        raise ValueError("spinor_hash must be at least 3 bytes")

    hue_a = int.from_bytes(spinor_hash[0:2], "big") % 360
    hue_b = (hue_a + 180) % 360
    hue_fire, hue_water = (hue_b, hue_a) if swap else (hue_a, hue_b)
    saturation = SEAL_SAT_BASE + (spinor_hash[2] % SEAL_SAT_SPAN)  # [45, 60]

    return {
        "fire": _hsl_to_rgb(hue_fire, saturation, L_SEAL_FIRE),
        "water": _hsl_to_rgb(hue_water, saturation, L_SEAL_WATER),
        "near": _hsl_to_rgb(hue_fire, max(0, saturation - 10), L_NEAR),
        "dim": _hsl_to_rgb(0, 0, L_DIM),  # neutral grey
    }


# ---------------------------------------------------------------------------
# Mesure A: build the alpha-punch mask for the symbol sampling windows
# ---------------------------------------------------------------------------

def _build_protection_mask(size: int) -> Image.Image:
    """Return an 'L' mask: 255 where seal lines may show, 0 over every symbol
    sampling window (13 vertices + 78 edge tags)."""
    r_v = size * VERTEX_RADIUS_FRAC
    r_tag = max(4, int(round(size * EDGE_TAG_RADIUS_FRAC)))
    tag_clear = r_tag + int(round(size * TAG_CLEAR_PAD_FRAC))
    vtx_clear = r_v * VERTEX_CLEAR_MULT

    mask = Image.new("L", (size, size), 255)
    md = ImageDraw.Draw(mask)

    for coord in VERTICES:
        cx, cy = _project(coord, size)
        md.ellipse(
            (cx - vtx_clear, cy - vtx_clear, cx + vtx_clear, cy + vtx_clear),
            fill=0,
        )
    for (vi, vj) in EDGES:
        p1 = _project(VERTICES[vi], size)
        p2 = _project(VERTICES[vj], size)
        cx, cy = edge_tag_position(p1, p2, size)
        md.ellipse(
            (cx - tag_clear, cy - tag_clear, cx + tag_clear, cy + tag_clear),
            fill=0,
        )
    return mask


# ---------------------------------------------------------------------------
# Main rendering function
# ---------------------------------------------------------------------------

def render_seal_revealed(
    symbols: Sequence[int],
    vault_fp: bytes,
    spinor_hash: bytes,
    size: int = DEFAULT_SEAL_SIZE,
    star_override: Optional[int] = None,
) -> Image.Image:
    """Render a Metatron Cube with the Seal of Solomon revealed.

    Parameters
    ----------
    symbols:
        91 F_13 symbols (same as ``render()``).
    vault_fp:
        32-byte vault fingerprint; selects the hexagram and the colour swap.
    spinor_hash:
        Spinor hash (≥3 bytes); determines the colour palette. For PRIVATE
        sheets where spinor_hash is unavailable, pass the seed's SHA3-512.
    size:
        Canvas size in pixels (square).
    star_override:
        Force a star index (0..len(STAR_CONFIGS)-1) for testing.

    Returns
    -------
    PIL.Image.Image
        RGB image. The 13 vertex disks and 78 edge tags are byte-for-byte the
        same pixels ``render()`` would draw; only the structural lines differ.
    """
    if len(symbols) != carrier_count():
        raise ValueError(f"expected {carrier_count()} symbols, got {len(symbols)}")
    for s in symbols:
        if not (0 <= s < 13):
            raise ValueError(f"symbol {s} out of F_13")

    star = star_override if star_override is not None else select_star(vault_fp)
    swap = seal_color_swap(vault_fp)
    seal_edge_list = seal_edges(star)
    seal_set, near_set = classify_edges(seal_edge_list)
    fire_edges, _ = fire_water_edges(star)
    fire_set = frozenset(fire_edges)
    palette = derive_palette(spinor_hash, swap=swap)

    # --- Mesure A: draw all structural lines onto a separate RGBA layer, then
    #     punch out the symbol sampling windows before compositing. ---
    seal_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    sd = ImageDraw.Draw(seal_layer)
    for (vi, vj) in EDGES:
        p1 = _project(VERTICES[vi], size)
        p2 = _project(VERTICES[vj], size)
        edge_key = (vi, vj)
        if edge_key in seal_set:
            colour = palette["fire"] if edge_key in fire_set else palette["water"]
            alpha = SEAL_ALPHA
            width = SEAL_EDGE_WIDTH
        elif edge_key in near_set:
            colour = palette["near"]
            alpha = NEAR_ALPHA
            width = NEAR_EDGE_WIDTH
        else:
            colour = palette["dim"]
            alpha = DIM_ALPHA
            width = DIM_EDGE_WIDTH
        sd.line((p1, p2), fill=colour + (int(alpha * 255),), width=width)

    mask = _build_protection_mask(size)
    seal_layer.putalpha(ImageChops.multiply(seal_layer.getchannel("A"), mask))

    img = Image.new("RGB", (size, size), BACKGROUND)
    img = Image.alpha_composite(img.convert("RGBA"), seal_layer).convert("RGB")
    d = ImageDraw.Draw(img)

    # --- Symbol layers: identical draw calls to render.render() ---
    edge_symbols = symbols[NUM_VERTICES:NUM_VERTICES + NUM_EDGES]
    vertex_symbols = symbols[:NUM_VERTICES]
    r_v = size * VERTEX_RADIUS_FRAC
    r_g = r_v * GLYPH_RADIUS_FRAC
    r_tag = max(4, int(round(size * EDGE_TAG_RADIUS_FRAC)))

    for sym, (vi, vj) in zip(edge_symbols, EDGES):
        p1 = _project(VERTICES[vi], size)
        p2 = _project(VERTICES[vj], size)
        cx, cy = edge_tag_position(p1, p2, size)
        color = srgb_for_symbol(sym)
        d.ellipse(
            (cx - r_tag, cy - r_tag, cx + r_tag, cy + r_tag),
            fill=color, outline=(0, 0, 0), width=max(1, r_tag // 6),
        )

    for sym, coord in zip(vertex_symbols, VERTICES):
        color = srgb_for_symbol(sym)
        cx, cy = _project(coord, size)
        d.ellipse(
            (cx - r_v, cy - r_v, cx + r_v, cy + r_v),
            fill=color, outline=(0, 0, 0), width=max(1, int(r_v * 0.08)),
        )
        r_inner_disk = r_v * 0.48
        d.ellipse(
            (cx - r_inner_disk, cy - r_inner_disk,
             cx + r_inner_disk, cy + r_inner_disk),
            fill=(255, 255, 255), outline=None,
        )
        draw_glyph(d, sym, cx, cy, r_g, (0, 0, 0), stroke=2)

    return img


__all__ = [
    "SEAL_DOMAIN",
    "SEAL_ALPHA",
    "NEAR_ALPHA",
    "DIM_ALPHA",
    "SEAL_MAX_SATURATION",
    "DEFAULT_SEAL_SIZE",
    "STAR_CONFIGS",
    "render_seal_revealed",
    "select_star",
    "seal_color_swap",
    "star_pointing_degrees",
    "seal_edges",
    "fire_water_edges",
    "classify_edges",
    "derive_palette",
    "_hsl_to_rgb",
]
