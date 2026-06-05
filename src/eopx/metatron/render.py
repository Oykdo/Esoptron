"""Deterministic PNG renderer for a 91-symbol Metatron canvas.

Whitepaper I §4.1, Whitepaper II §5.6.

Mapping of carriers to symbols (canonical):
    symbol[0 .. 12]     -> 13 vertex disks (color + glyph)
    symbol[13 .. 90]    -> 78 edge strokes (color + style)

6 mini-ArUco markers (DICT_4X4_50, IDs 20..25) are rendered outside the
outer hexagon at V[7]..V[12]. These provide local reference points for
rectification: the phone camera detects them and computes a homography
directly on the cube, bypassing the error-prone page-level warp.

The rendering is fully deterministic given (symbols, canvas_size).
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

import numpy as np
from PIL import Image, ImageDraw

from .graph import VERTICES, EDGES, NUM_VERTICES, NUM_EDGES, carrier_count
from .palette import srgb_for_symbol
from .glyphs import draw_glyph

# ArUco integration
try:
    import cv2
    _HAS_CV2 = True
except Exception:
    _HAS_CV2 = False

ARUCO_DICT_NAME = "DICT_4X4_50"
# IDs 20-25 for the 6 outer hexagon vertices (V[7]..V[12])
ARUCO_INNER_IDS = {7: 20, 8: 21, 9: 22, 10: 23, 11: 24, 12: 25}

DEFAULT_CANVAS = 512
MARGIN_FRAC = 0.10
VERTEX_RADIUS_FRAC = 0.032
EDGE_LINE_WIDTH = 2
EDGE_TAG_RADIUS_FRAC = 0.013
EDGE_TAG_T = 0.27
EDGE_TAG_PERP_FRAC = 0.018
GLYPH_RADIUS_FRAC = 0.55

BACKGROUND = (255, 255, 255)
EDGE_LINE_COLOR = (200, 200, 200)

# Inner ArUco marker constants (used by local_rectify.py, not currently rendered)
INNER_ARUCO_FRAC = 0.038    # large enough for OpenCV detection at 1024 px
INNER_ARUCO_OFFSET = 1.50   # well outside the hexagon


def _project(coord: Tuple[float, float], size: int) -> Tuple[float, float]:
    """Map a vertex coord from the canonical [-sqrt(3), +sqrt(3)] R^2 frame
    into pixel coordinates centered on the canvas."""
    margin = int(size * MARGIN_FRAC)
    radius_px = (size - 2 * margin) / 2.0
    scale = radius_px / (3 ** 0.5)  # outer hexagon has radius sqrt(3)
    cx = size / 2.0
    cy = size / 2.0
    return (cx + coord[0] * scale, cy - coord[1] * scale)


def edge_tag_position(p1: Tuple[float, float],
                       p2: Tuple[float, float],
                       size: int) -> Tuple[float, float]:
    """Return the (cx, cy) pixel position of the colored tag of an edge.

    The tag sits along the edge at fraction EDGE_TAG_T from p1, offset
    perpendicularly (CCW rotation of the edge direction) by EDGE_TAG_PERP_FRAC
    of the canvas size. This places each of the 78 tags at a distinct,
    isolated location away from the dense central crossings of K_13.
    """
    dx = p2[0] - p1[0]
    dy = p2[1] - p1[1]
    length = (dx * dx + dy * dy) ** 0.5
    if length == 0:
        return p1
    bx = p1[0] + EDGE_TAG_T * dx
    by = p1[1] + EDGE_TAG_T * dy
    # Perpendicular unit vector via CCW rotation: (x, y) -> (-y, x)
    nx = -dy / length
    ny = dx / length
    perp = size * EDGE_TAG_PERP_FRAC
    return (bx + perp * nx, by + perp * ny)


def _contrasting_glyph_color(bg: Tuple[int, int, int]) -> Tuple[int, int, int]:
    """Pick white or near-black depending on perceived luminance of bg."""
    # ITU-R BT.601 luma approximation, sufficient for binary choice.
    y = 0.299 * bg[0] + 0.587 * bg[1] + 0.114 * bg[2]
    return (20, 20, 24) if y > 128 else (240, 240, 232)


def render(symbols: Sequence[int],
           size: int = DEFAULT_CANVAS,
           background: Tuple[int, int, int] = BACKGROUND) -> Image.Image:
    """Render 91 F_13 symbols onto a square PNG canvas.

    The output is RGB (no alpha) so that byte-level equality across runs
    is meaningful for determinism tests.
    """
    if len(symbols) != carrier_count():
        raise ValueError(
            f"expected {carrier_count()} symbols, got {len(symbols)}"
        )
    for s in symbols:
        if not (0 <= s < 13):
            raise ValueError(f"symbol {s} out of F_13")

    img = Image.new("RGB", (size, size), background)
    d = ImageDraw.Draw(img)

    edge_symbols = symbols[NUM_VERTICES:NUM_VERTICES + NUM_EDGES]
    vertex_symbols = symbols[:NUM_VERTICES]
    r_v = size * VERTEX_RADIUS_FRAC
    r_g = r_v * GLYPH_RADIUS_FRAC
    r_tag = max(4, int(round(size * EDGE_TAG_RADIUS_FRAC)))

    # Layer 1: neutral structural edges (no information, pure aesthetic).
    for (vi, vj) in EDGES:
        p1 = _project(VERTICES[vi], size)
        p2 = _project(VERTICES[vj], size)
        d.line((p1, p2), fill=EDGE_LINE_COLOR, width=EDGE_LINE_WIDTH)

    # Layer 2: colored edge tags (the information layer for edges).
    # Each tag is a colored disk with a black outline for visibility on white bg.
    for sym, (vi, vj) in zip(edge_symbols, EDGES):
        p1 = _project(VERTICES[vi], size)
        p2 = _project(VERTICES[vj], size)
        cx, cy = edge_tag_position(p1, p2, size)
        color = srgb_for_symbol(sym)
        d.ellipse(
            (cx - r_tag, cy - r_tag, cx + r_tag, cy + r_tag),
            fill=color, outline=(0, 0, 0), width=max(1, r_tag // 6),
        )

    # Layer 3: vertex rings + black glyphs (drawn LAST so they sit on top).
    ring_inner = r_v * 0.50
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

    # Layer 4: (inner ArUco markers are on the A4 sheet, not in the cube)

    return img


def _render_inner_aruco(img: Image.Image, size: int) -> None:
    """Render 6 small ArUco markers (IDs 20-25) outside the outer hexagon.

    Each marker is centered at the position of V[7]..V[12] but pushed
    radially outward by INNER_ARUCO_OFFSET so it sits outside the colored
    ring of the vertex disk, in the white margin area.
    """
    if not _HAS_CV2:
        return  # no cv2 → skip ArUco (detection will also fail)
    aruco = cv2.aruco  # pyright: ignore  # guarded by _HAS_CV2 above
    dictionary = aruco.getPredefinedDictionary(getattr(aruco, ARUCO_DICT_NAME))
    marker_side = max(8, int(round(size * INNER_ARUCO_FRAC)))

    center = size / 2.0
    margin = int(size * MARGIN_FRAC)
    radius_px = (size - 2 * margin) / 2.0
    scale = radius_px / (3 ** 0.5)

    for vertex_idx, aruco_id in ARUCO_INNER_IDS.items():
        vx, vy = VERTICES[vertex_idx]
        # Position at vertex, pushed outward radially
        r = (vx ** 2 + vy ** 2) ** 0.5
        if r == 0:
            continue
        # Push the marker center to INNER_ARUCO_OFFSET * hex_radius
        target_r = INNER_ARUCO_OFFSET * (3 ** 0.5)  # hex radius = sqrt(3)
        factor = target_r / r
        mx = vx * factor
        my = vy * factor
        px = center + mx * scale
        py = center - my * scale

        # Generate the ArUco marker image
        marker = aruco.generateImageMarker(
            dictionary, aruco_id, marker_side, borderBits=1
        )
        arr = np.stack([marker, marker, marker], axis=-1)
        pil_marker = Image.fromarray(arr, mode="RGB")

        # Paste centered at (px, py)
        x0 = int(round(px - marker_side / 2))
        y0 = int(round(py - marker_side / 2))
        img.paste(pil_marker, (x0, y0))


def render_to_bytes(symbols: Sequence[int], size: int = DEFAULT_CANVAS) -> bytes:
    """Convenience: render then return deterministic PNG bytes (no metadata)."""
    img = render(symbols, size=size)
    import io
    buf = io.BytesIO()
    # optimize=False to avoid compressor heuristics that change with Pillow version;
    # the bytes will still be deterministic for a fixed Pillow build.
    img.save(buf, format="PNG", optimize=False, compress_level=6)
    return buf.getvalue()
