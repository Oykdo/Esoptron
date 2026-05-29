"""Render the chromatic grid as a scan layer on the A4 sheet.

The grid is a 12×16 array of colored cells (6 ultra-contrast colors).
It sits below the K_13 cube on the A4 sheet, with numbered row/column
headers for position identification. The phone camera reads the grid
instead of the cube for robust decoding.

Layout on A4:
    ┌─────────────────────────────────┐
    │  [ArUco 0]            [ArUco 1] │
    │  PRIVATE INSCRIPTION - DO NOT... │
    │  ┌───────────────────────┐      │
    │  │                       │      │
    │  │    K₁₃ Metatron Cube   │      │
    │  │                       │      │
    │  └───────────────────────┘      │
    │  ┌───┬──┬──┬──...──┬──┬──┐     │
    │  │   │ 0│ 1│ 2...  │15│16│     │
    │  ├───┼──┼──┼──...──┼──┼──┤     │
    │  │ 0 │██│██│██...  │██│██│     │
    │  │ 1 │██│██│██...  │██│██│     │
    │  │...│██│██│██...  │██│██│     │
    │  │11 │██│██│██...  │██│██│     │
    │  └───┴──┴──┴──...──┴──┴──┘     │
    │  [ArUco 3]            [ArUco 2] │
    └─────────────────────────────────┘
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from PIL import Image, ImageDraw, ImageFont

from .grid import (
    GRID_OKLCH, GRID_NAMES, grid_srgb, grid_palette_srgb,
    encode_grid, f13_to_grid_pair, classify_grid_color,
)
from .palette import srgb_for_symbol

# Grid dimensions: 12 rows × 16 columns = 192 cells
# 91 symbols × 2 base-6 digits = 182 digits, padded to 192
GRID_ROWS = 12
GRID_COLS = 16

# Layout constants (in mm, for A4 at 300 DPI)
CELL_MM = 8.0        # cell size
CELL_GAP_MM = 1.0    # gap between cells
HEADER_MM = 5.0      # row/column header size

# Colors
BG = (255, 255, 255)
HEADER_BG = (40, 40, 50)
HEADER_FG = (220, 220, 230)
GRID_BORDER = (60, 60, 70)


def grid_layout(cell_px: int) -> dict:
    """Compute the exact pixel layout of the grid.

    Returns a dict with keys: header_px, gap, cell_px, grid_w, grid_h,
    and a function cell_pos(row, col) -> (x, y) for the top-left of each cell.
    """
    gap = max(2, cell_px // 10)
    header_px = max(12, cell_px // 2)

    grid_w = header_px + gap + GRID_COLS * (cell_px + gap) + gap
    grid_h = header_px + gap + GRID_ROWS * (cell_px + gap) + gap

    def cell_pos(row: int, col: int) -> Tuple[int, int]:
        x = header_px + gap + col * (cell_px + gap) + gap // 2
        y = header_px + gap + row * (cell_px + gap) + gap // 2
        return x, y

    def cell_center(row: int, col: int) -> Tuple[float, float]:
        x, y = cell_pos(row, col)
        return x + cell_px / 2.0, y + cell_px / 2.0

    return {
        'header_px': header_px,
        'gap': gap,
        'cell_px': cell_px,
        'grid_w': grid_w,
        'grid_h': grid_h,
        'cell_pos': cell_pos,
        'cell_center': cell_center,
    }


def render_grid(symbols: Sequence[int],
                cell_px: int = 30,
                header_px: int = 18) -> Image.Image:
    """Render the chromatic grid as a PIL image.

    Returns an image of size:
        (GRID_COLS * (cell_px + gap) + header_px + gap + border,
         GRID_ROWS * (cell_px + gap) + header_px + gap + border)
    """
    if len(symbols) != 91:
        raise ValueError(f"expected 91 symbols, got {len(symbols)}")

    gap = max(2, cell_px // 10)

    # Encode symbols into grid color indices
    digits: List[int] = []
    for s in symbols:
        hi, lo = f13_to_grid_pair(s)
        digits.append(hi)
        digits.append(lo)
    while len(digits) < GRID_ROWS * GRID_COLS:
        digits.append(0)

    # Image dimensions
    w = header_px + gap + GRID_COLS * (cell_px + gap) + gap
    h = header_px + gap + GRID_ROWS * (cell_px + gap) + gap

    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)

    # Border
    d.rectangle((0, 0, w - 1, h - 1), outline=GRID_BORDER, width=2)

    # Column headers (0-15)
    for col in range(GRID_COLS):
        x = header_px + gap + col * (cell_px + gap) + gap // 2
        d.rectangle(
            (x, gap, x + cell_px, gap + header_px),
            fill=HEADER_BG, outline=GRID_BORDER, width=1,
        )
        txt = str(col)
        d.text((x + cell_px // 2 - len(txt) * 3, gap + 2),
               txt, fill=HEADER_FG)

    # Row headers (0-11)
    for row in range(GRID_ROWS):
        y = header_px + gap + row * (cell_px + gap) + gap // 2
        d.rectangle(
            (gap, y, gap + header_px, y + cell_px),
            fill=HEADER_BG, outline=GRID_BORDER, width=1,
        )
        txt = str(row)
        d.text((gap + header_px // 2 - len(txt) * 3, y + 2),
               txt, fill=HEADER_FG)

    # Grid cells
    for row in range(GRID_ROWS):
        for col in range(GRID_COLS):
            idx = row * GRID_COLS + col
            if idx >= len(digits):
                break
            color_idx = digits[idx]
            color = grid_srgb(color_idx)

            x = header_px + gap + col * (cell_px + gap) + gap // 2
            y = header_px + gap + row * (cell_px + gap) + gap // 2

            d.rectangle(
                (x, y, x + cell_px, y + cell_px),
                fill=color, outline=(0, 0, 0), width=1,
            )

    return img


def render_grid_on_a4(a4_img: Image.Image,
                       symbols: Sequence[int],
                       grid_top_y: int,
                       grid_left_x: int,
                       cell_px: int) -> Image.Image:
    """Render the chromatic grid directly onto an A4 PIL image.

    Places the grid at (grid_left_x, grid_top_y) with the given cell size.
    Modifies a4_img in-place and returns it.
    """
    if len(symbols) != 91:
        raise ValueError(f"expected 91 symbols, got {len(symbols)}")

    gap = max(2, cell_px // 10)
    header_px = max(14, cell_px // 2)
    d = ImageDraw.Draw(a4_img)

    # Encode symbols
    digits: List[int] = []
    for s in symbols:
        hi, lo = f13_to_grid_pair(s)
        digits.append(hi)
        digits.append(lo)
    while len(digits) < GRID_ROWS * GRID_COLS:
        digits.append(0)

    # Column headers
    for col in range(GRID_COLS):
        x = grid_left_x + header_px + gap + col * (cell_px + gap) + gap // 2
        y = grid_top_y
        d.rectangle(
            (x, y, x + cell_px, y + header_px),
            fill=HEADER_BG, outline=GRID_BORDER, width=1,
        )
        d.text((x + cell_px // 2 - 3, y + 2), str(col), fill=HEADER_FG)

    # Row headers
    for row in range(GRID_ROWS):
        x = grid_left_x
        y = grid_top_y + header_px + gap + row * (cell_px + gap) + gap // 2
        d.rectangle(
            (x, y, x + header_px, y + cell_px),
            fill=HEADER_BG, outline=GRID_BORDER, width=1,
        )
        d.text((x + header_px // 2 - 3, y + 2), str(row), fill=HEADER_FG)

    # Grid cells
    for row in range(GRID_ROWS):
        for col in range(GRID_COLS):
            idx = row * GRID_COLS + col
            if idx >= len(digits):
                break
            color_idx = digits[idx]
            color = grid_srgb(color_idx)

            x = grid_left_x + header_px + gap + col * (cell_px + gap) + gap // 2
            y = grid_top_y + header_px + gap + row * (cell_px + gap) + gap // 2

            d.rectangle(
                (x, y, x + cell_px, y + cell_px),
                fill=color, outline=(0, 0, 0), width=1,
            )

    # Outer border around the entire grid
    grid_w = header_px + gap + GRID_COLS * (cell_px + gap) + gap
    grid_h = header_px + gap + GRID_ROWS * (cell_px + gap) + gap
    d.rectangle(
        (grid_left_x, grid_top_y,
         grid_left_x + grid_w, grid_top_y + grid_h),
        outline=GRID_BORDER, width=2,
    )

    # Label
    label = "SCAN GRID — 6-color base-6 encoding"
    d.text((grid_left_x, grid_top_y + grid_h + 4),
           label, fill=(100, 100, 120))

    return a4_img
