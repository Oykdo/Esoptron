"""EPX-F §6 on the EPX-R canvas — the artifact's face, drawn in runes.

:mod:`eopx.figure_plate` frames an EPX-F grid for a terminal. This module
frames the same grid for *paper*: sixteen levels per cell, sixteen runes
(:mod:`eopx.metatron.runes`), one rune per cell. The fit is not a coincidence —
EPX-F froze 4 bits per cell and EPX-R chose 16 glyph states for the same
reason, that four bits is what a camera reliably separates.

What this plate is not
----------------------
It is **not an EPX-R data plate**. It carries no fiducials, no timing track, no
format block and no Reed-Solomon: there is nothing here to scan, and adding the
furniture that would make it scannable would advertise a channel that does not
exist. A reader verifies a face by recomputing ``F(merkle_root,
dilithium_pk_fp)`` from the `.eopx` and comparing the eight-character tag
printed beneath it — never by photographing the plate (EPX-F §7).

It is also **brand, not security** (POSITIONING). The plate adds no entropy,
proves no possession, and moves no trust: all of that is the 91 symbols, the
signature and the registry.

Where it may be drawn
---------------------
Nowhere near the cube. Ink close to the 91 carriers or to the ArUco fiducials
is paid for out of the measured decode envelope, and the geometry axis is
already the weak link — EPX-H learned this and answered with an exclusion mask.
The plate's answer is simpler: it is a separate rectangle on the page, and
``scripts/print_sheet.py`` refuses to place it anywhere that touches a reserved
region.

Frozen versus living
--------------------
The rule from EPX-F §6 is enforced here in pixels exactly as
:mod:`eopx.figure_plate` enforces it in text. A **frozen** plate gets a solid
frame and prints its tag, because the tag is what a reader may compare. A
**living** plate gets a dashed frame and prints **no tag** — the omission is
the safety property: nothing on a moving face may be mistakable for something
to check.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from PIL import Image, ImageDraw, ImageFont

from .artifact_figure import (
    CONTENT_ROWS,
    GRID_H,
    GRID_W,
    LEVELS,
    epoch_id,
    figure_grid,
    figure_tag,
)
from .figure_plate import LIVING_CELL_CAP, living_rows
from .metatron.runes import NUM_RUNES, draw_rune

# The alphabet and the grid have to agree on how many states a cell has. They
# were chosen independently and happen to match; assert it rather than trust it.
assert LEVELS == NUM_RUNES

INK = (20, 20, 26)
PAPER = (255, 255, 255)
FRAME = (90, 90, 100)
CAPTION = (110, 110, 122)

#: Frame thickness and the blank margin between frame and runes, both as a
#: fraction of the cell side.
FRAME_FRACTION = 0.10
MARGIN_FRACTION = 0.45

#: Dash geometry for a living frame, in cell fractions: on, then off.
_DASH_ON = 0.55
_DASH_OFF = 0.40

#: Supersampling used for the strokes. Runes are thin diagonals; aliasing at
#: plate scale reads as a ladder rather than a line.
SUPERSAMPLE = 4


def plate_pixel_size(cell_px: int, *, caption: bool = True) -> Tuple[int, int]:
    """(width, height) in pixels of a plate drawn with ``cell_px`` cells.

    Callers lay out a page before they have an image, so this must agree with
    :func:`render_figure_plate` exactly.
    """
    if cell_px <= 0:
        raise ValueError("cell_px must be positive")
    frame = _frame_px(cell_px)
    margin = _margin_px(cell_px)
    w = GRID_W * cell_px + 2 * (frame + margin)
    h = GRID_H * cell_px + 2 * (frame + margin) + (
        _caption_px(cell_px) if caption else 0)
    return w, h


def grid_origin(cell_px: int) -> Tuple[int, int]:
    """Pixel position of cell (0, 0) inside a plate drawn at ``cell_px``."""
    edge = _frame_px(cell_px) + _margin_px(cell_px)
    return edge, edge


def band_split_y(cell_px: int) -> int:
    """The y where the content band ends and the epoch band begins.

    Exposed because it is the one horizontal line on the plate that means
    something: everything above it is the artifact for life, everything below
    it moves when the issuing key rotates (EPX-F §3.1).
    """
    return grid_origin(cell_px)[1] + CONTENT_ROWS * cell_px


def _frame_px(cell_px: int) -> int:
    return max(1, round(cell_px * FRAME_FRACTION))


def _margin_px(cell_px: int) -> int:
    return max(2, round(cell_px * MARGIN_FRACTION))


def _caption_px(cell_px: int) -> int:
    return max(10, round(cell_px * 0.95))


def _font(size_px: int) -> "ImageFont.FreeTypeFont | ImageFont.ImageFont":
    """A monospace face if the host has one, else PIL's bitmap default.

    The caption is a hex tag that a reader compares character by character, so
    a fixed pitch is worth asking for; it is not worth failing over.
    """
    for path in ("C:/Windows/Fonts/consola.ttf",
                 "C:/Windows/Fonts/cour.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                 "/System/Library/Fonts/Menlo.ttc"):
        try:
            return ImageFont.truetype(path, size=size_px)
        except OSError:
            continue
    return ImageFont.load_default()


def _dashed_rect(draw: ImageDraw.ImageDraw, box: Tuple[int, int, int, int],
                 width: int, cell_px: int, fill: Tuple[int, int, int]) -> None:
    on = max(2, round(cell_px * _DASH_ON))
    off = max(2, round(cell_px * _DASH_OFF))
    x0, y0, x1, y1 = box
    # Horizontal runs (top, bottom), then vertical runs (left, right).
    for y in (y0, y1):
        x = x0
        while x < x1:
            draw.line((x, y, min(x + on, x1), y), fill=fill, width=width)
            x += on + off
    for x in (x0, x1):
        y = y0
        while y < y1:
            draw.line((x, y, x, min(y + on, y1)), fill=fill, width=width)
            y += on + off


def render_figure_plate(grid: Sequence[Sequence[int]], *,
                        cell_px: int = 32,
                        tag: Optional[str] = None,
                        epoch: str = "",
                        title: str = "",
                        living: bool = False,
                        ink: Tuple[int, int, int] = INK,
                        bg: Tuple[int, int, int] = PAPER) -> Image.Image:
    """Draw ``grid`` as a runic plate.

    ``tag`` is the eight-character EPX-F tag to print underneath. A living
    plate must not carry one: passing both ``living=True`` and a ``tag`` is a
    :class:`ValueError`, not a preference, because the whole point of the
    dashed frame is that there is nothing beneath it to compare.
    """
    if len(grid) != GRID_H or any(len(row) != GRID_W for row in grid):
        raise ValueError(f"grid must be {GRID_H}x{GRID_W}")
    if any(not 0 <= c < LEVELS for row in grid for c in row):
        raise ValueError(f"cell levels must be in [0, {LEVELS})")
    if living and tag:
        raise ValueError(
            "a living plate must not print a tag (EPX-F §6): a moving face "
            "must not be mistakable for the artifact's frozen identity")

    caption = _caption_line(title, epoch, tag, living)
    w, h = plate_pixel_size(cell_px, caption=bool(caption))

    ss = SUPERSAMPLE
    img = Image.new("RGB", (w * ss, h * ss), bg)
    draw = ImageDraw.Draw(img)

    frame = _frame_px(cell_px) * ss
    margin = _margin_px(cell_px) * ss
    cell = cell_px * ss
    grid_h_px = GRID_H * cell + 2 * margin

    box = (frame // 2, frame // 2,
           w * ss - 1 - frame // 2, grid_h_px + frame + frame // 2)
    if living:
        _dashed_rect(draw, box, max(1, frame), cell, FRAME)
    else:
        draw.rectangle(box, outline=FRAME, width=max(1, frame))

    origin = frame + margin
    for r, row in enumerate(grid):
        for c, value in enumerate(row):
            draw_rune(draw, value,
                      origin + c * cell, origin + r * cell, cell, ink)

    img = img.resize((w, h), Image.LANCZOS)

    if caption:
        _draw_caption(img, caption, cell_px, w,
                      grid_h_px // ss + 2 * _frame_px(cell_px))
    return img


def _caption_line(title: str, epoch: str, tag: Optional[str],
                  living: bool) -> str:
    parts: List[str] = []
    if title:
        parts.append(title)
    if epoch:
        parts.append(f"epoch {epoch}")
    if living:
        parts.append("living")
    elif tag:
        parts.append(tag)
    return "  ·  ".join(parts)


def _draw_caption(img: Image.Image, text: str, cell_px: int,
                  width: int, top: int) -> None:
    draw = ImageDraw.Draw(img)
    size = max(8, round(cell_px * 0.60))
    font = _font(size)
    try:
        tw = draw.textlength(text, font=font)
    except (AttributeError, TypeError):  # very old Pillow / bitmap font
        tw = size * 0.6 * len(text)
    draw.text(((width - tw) / 2.0, top + max(2, cell_px * 0.10)),
              text, font=font, fill=CAPTION)


def render_artifact_plate(merkle_root: bytes, dilithium_pk_fp: bytes, *,
                          cell_px: int = 32, title: str = "",
                          **kwargs) -> Image.Image:
    """The frozen face of a `.eopx`, from the two manifest fields themselves.

    Deriving the grid, the epoch and the tag from one pair of inputs is the
    point: a caller cannot hand this function a grid and a tag that disagree,
    which is exactly the mistake that would make a printed plate lie.
    """
    grid = figure_grid(merkle_root, dilithium_pk_fp)
    return render_figure_plate(
        grid, cell_px=cell_px, title=title,
        epoch=epoch_id(dilithium_pk_fp), tag=figure_tag(grid), **kwargs)


def render_living_plate(grid: Sequence[Sequence[int]], *, state_bytes: bytes,
                        activity: int = LIVING_CELL_CAP, cell_px: int = 32,
                        title: str = "", epoch: str = "",
                        **kwargs) -> Image.Image:
    """The artifact *now*: dashed frame, drifting cells, and no tag."""
    return render_figure_plate(
        living_rows(grid, state_bytes, activity),
        cell_px=cell_px, title=title, epoch=epoch, living=True, **kwargs)


__all__ = [
    "INK", "PAPER", "FRAME", "CAPTION", "SUPERSAMPLE",
    "plate_pixel_size", "grid_origin", "band_split_y",
    "render_figure_plate", "render_artifact_plate",
    "render_living_plate",
]
