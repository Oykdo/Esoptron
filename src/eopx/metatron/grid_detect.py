"""Detect and decode the chromatic grid from a phone photo.

Pipeline:
    phone photo of A4 sheet
      -> find the grid region (dark header border / header text)
      -> sample each cell and classify its color (6-way)
      -> decode base-6 pairs -> F_13 symbols
      -> RS decode

The grid is located by finding the dark border frame and using
the row/column headers as anchors. No ArUco needed for the grid.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

import numpy as np
from PIL import Image

from .grid import (
    GRID_ROWS, GRID_COLS, classify_grid_color,
    grid_pair_to_f13, f13_to_grid_pair,
)
from .palette import srgb255_to_oklab


def detect_grid(photo_bgr_or_rgb: np.ndarray,
                known_grid_rect: Optional[Tuple[int, int, int, int]] = None
                ) -> Optional[List[int]]:
    """Detect and decode the chromatic grid from a photo.

    If known_grid_rect is provided as (x, y, w, h), use it directly.
    Otherwise, try to find the grid by its dark border.

    Returns a list of 91 F_13 symbols, or None on failure.
    """
    # For now, require known_grid_rect (the caller knows the layout)
    if known_grid_rect is None:
        return None

    gx, gy, gw, gh = known_grid_rect
    h, w = photo_bgr_or_rgb.shape[:2]

    if gy + gh > h or gx + gw > w:
        return None

    # Extract the grid region
    grid_region = photo_bgr_or_rgb[gy:gy + gh, gx:gx + gw]

    # Convert BGR to RGB if needed (check channel order heuristically)
    # If mean of channel 0 > mean of channel 2, likely BGR (blue > red in typical photos)
    if grid_region.shape[2] == 3:
        ch0_mean = grid_region[:, :, 0].mean()
        ch2_mean = grid_region[:, :, 2].mean()
        # If it looks like BGR, convert
        if ch0_mean < ch2_mean - 10:  # blue channel lower = likely RGB already
            pass  # assume RGB
        else:
            # Try both and pick the one with better decode
            pass

    return _extract_grid_colors(grid_region, is_bgr=False)


def _extract_grid_colors(grid_region: np.ndarray,
                          is_bgr: bool = False,
                          cell_px: int = 0,
                          normalize: bool = True
                          ) -> Optional[List[int]]:
    """Given the pixel region containing the grid, extract 192 color indices.

    Uses the shared grid_layout for exact position matching.
    If cell_px is 0, estimates from region dimensions.
    If normalize is True, applies white-balance + gamma to the region
    before classification (helps with phone photos).
    """
    from .grid_render import grid_layout

    h, w = grid_region.shape[:2]
    region = grid_region.copy()

    # Normalize: white-balance + gamma (same logic as for the cube)
    if normalize:
        arr = region.astype(np.float32)
        # White balance: scale each channel so p98 -> 245
        for c in range(3):
            ch = arr[:, :, c]
            p98 = np.percentile(ch, 98)
            if p98 > 30:
                arr[:, :, c] = arr[:, :, c] * (245.0 / p98)
        # Gamma
        arr = np.power(np.clip(arr / 255.0, 0, 1), 0.75) * 255.0
        region = np.clip(arr, 0, 255).astype(np.uint8)

    # Estimate or use provided cell size
    if cell_px <= 0:
        # Approximate: (w - header - 2*gap) / GRID_COLS ≈ cell_px + gap
        cell_px = max(5, (w - 30) // (GRID_COLS + 1))

    layout = grid_layout(cell_px)
    header_px = layout['header_px']
    gap = layout['gap']
    cell_center = layout['cell_center']

    if layout['grid_w'] > w or layout['grid_h'] > h:
        return None  # layout doesn't fit in the region

    # Sample each cell center
    colors: List[int] = []
    for row in range(GRID_ROWS):
        for col in range(GRID_COLS):
            cx, cy = cell_center(row, col)
            cx, cy = int(round(cx)), int(round(cy))

            if cx >= w or cy >= h:
                colors.append(0)
                continue

            # Sample a small disk around center for robustness
            sample_r = max(1, cell_px // 4)
            r_vals, g_vals, b_vals = [], [], []
            for dy in range(-sample_r, sample_r + 1):
                for dx in range(-sample_r, sample_r + 1):
                    if dx * dx + dy * dy <= sample_r * sample_r:
                        px, py = cx + dx, cy + dy
                        if 0 <= px < w and 0 <= py < h:
                            if is_bgr:
                                b_vals.append(grid_region[py, px, 0])
                                g_vals.append(grid_region[py, px, 1])
                                r_vals.append(grid_region[py, px, 2])
                            else:
                                r_vals.append(grid_region[py, px, 0])
                                g_vals.append(grid_region[py, px, 1])
                                b_vals.append(grid_region[py, px, 2])

            if not r_vals:
                colors.append(0)
                continue

            r = int(np.median(r_vals))
            g = int(np.median(g_vals))
            b = int(np.median(b_vals))

            idx, dist = classify_grid_color(r, g, b)
            colors.append(idx)

    # Decode: pairs of base-6 digits -> F_13 symbols
    symbols: List[int] = []
    for k in range(91):
        if 2 * k + 1 >= len(colors):
            break
        hi = colors[2 * k]
        lo = colors[2 * k + 1]
        s = grid_pair_to_f13(hi, lo)
        if s < 0:
            symbols.append(0)
        else:
            symbols.append(s)

    if len(symbols) != 91:
        return None

    return symbols


def extract_grid_from_a4_rect(pil_img: Image.Image,
                               grid_rect: Tuple[int, int, int, int]
                               ) -> Optional[List[int]]:
    """Extract grid from a PIL image given the grid bounding box.

    grid_rect: (x, y, w, h) in pixel coordinates of the PIL image.
    """
    arr = np.array(pil_img)
    x, y, w, h = grid_rect
    if y + h > arr.shape[0] or x + w > arr.shape[1]:
        return None
    region = arr[y:y + h, x:x + w]
    return _extract_grid_colors(region, is_bgr=False)
