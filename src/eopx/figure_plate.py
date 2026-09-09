"""EPX-F §6 — presentation: Unicode plates, galleries, and a face that moves.

Everything here is *reading* an EPX-F grid, never defining one. The grid and
its digest live in :mod:`eopx.artifact_figure` and do not know this module
exists; swapping a ramp, framing a plate or animating a display changes what a
person sees and nothing a verifier checks.

One guard is deliberate and load-bearing. A **frozen** plate is drawn with a
solid frame and prints its tag, because the tag is exactly what a reader may
compare against a recomputation. A **living** plate — one whose cells drift
with ledger state — is drawn with a dashed frame and **prints no tag at all**.
A moving face must never be mistakable for the artifact's identity, and the
cheapest way to guarantee that is to make it impossible to compare.
"""

from __future__ import annotations

import hashlib
from typing import List, Optional, Sequence, Tuple

from .artifact_figure import (
    ASCII_RAMP,
    GRID_H,
    GRID_W,
    LEVELS,
    figure_tag,
    render_rows,
)

#: Block-element ramp, ordered by ink coverage: space, then 25%, 50%, 75%,
#: 87.5% and full. Ties are broken by *shape* rather than weight, which gives
#: the face texture instead of a flat gradient.
#:
#: Perceptual, not metric: terminals disagree on the exact rendering of these
#: code points, and several are East-Asian *ambiguous* width. Use
#: :data:`~eopx.artifact_figure.ASCII_RAMP` when byte-exact column alignment
#: matters more than looks.
UNICODE_RAMP = " ░▖▗▘▝▒▚▞▌▐▀▄▓▉█"

#: Max cells a living rendering may perturb, mirroring the bound in
#: ``collection.figure``. The drift is a hint for the eye; it is not part of
#: the artifact's face and never enters a digest.
LIVING_CELL_CAP = 5

#: corners, edges, and the tees that separate the grid from its caption
_FRAMES = {
    "solid": ("┌", "┐", "└", "┘", "─", "│", "├", "┤"),
    "dashed": ("┌", "┐", "└", "┘", "╌", "╎", "├", "┤"),
    "ascii": ("+", "+", "+", "+", "-", "|", "+", "+"),
}


def _frame(rows: Sequence[str], style: str, caption: Sequence[str]) -> str:
    tl, tr, bl, br, h, v, ml, mr = _FRAMES[style]
    width = max([len(r) for r in rows] + [len(c) for c in caption])
    out = [tl + h * (width + 2) + tr]
    # The grid is centred rather than left-aligned: a long caption widens the
    # frame, and a figure pinned to the left edge of that frame reads as a
    # layout accident.
    out += [f"{v} {r.center(width)} {v}" for r in rows]
    if caption:
        out.append(ml + h * (width + 2) + mr)
        out += [f"{v} {c.center(width)} {v}" for c in caption]
    out.append(bl + h * (width + 2) + br)
    return "\n".join(out)


def plate(grid: Sequence[Sequence[int]], *, title: str = "",
          epoch: str = "", ramp: str = UNICODE_RAMP,
          ascii_frame: bool = False) -> str:
    """The artifact's frozen face, framed, with its tag printed underneath.

    The tag is the whole point of the caption: a reader recomputes
    ``F(merkle_root, dilithium_pk_fp)`` from the `.eopx` and compares those
    eight characters. Looking at the picture proves nothing.
    """
    rows = render_rows(grid, ramp)
    caption = [c for c in (title, _epoch_line(epoch, figure_tag(grid))) if c]
    return _frame(rows, "ascii" if ascii_frame else "solid", caption)


def _epoch_line(epoch: str, tag: str) -> str:
    if epoch and tag:
        return f"epoch {epoch} · {tag}"
    return tag or (f"epoch {epoch}" if epoch else "")


def living_rows(grid: Sequence[Sequence[int]], state_bytes: bytes,
                activity: int, *, cap: int = LIVING_CELL_CAP) -> List[List[int]]:
    """``grid`` with at most ``min(activity, cap)`` cells perturbed by state.

    Deterministic in ``state_bytes``, so two viewers of the same ledger state
    see the same shimmer. The result is **not** the artifact's face: it has no
    tag, and feeding it to :func:`~eopx.artifact_figure.figure_digest` is a
    category error.
    """
    out = [list(row) for row in grid]
    n = min(cap, max(0, activity))
    if n == 0:
        return out
    tail = hashlib.sha3_256(state_bytes).digest()
    cells = GRID_W * GRID_H
    for k in range(n):
        idx = tail[k] % cells
        out[idx // GRID_W][idx % GRID_W] = tail[k + 8] % LEVELS
    return out


def living_plate(grid: Sequence[Sequence[int]], *, state_bytes: bytes,
                 activity: int, title: str = "", epoch: str = "",
                 ramp: str = UNICODE_RAMP, ascii_frame: bool = False) -> str:
    """The artifact *now*: dashed frame, and deliberately **no tag**.

    The missing tag is the safety property, not an omission — there is nothing
    here a reader could mistake for something to compare.
    """
    rows = render_rows(living_rows(grid, state_bytes, activity), ramp)
    caption = [c for c in (title, f"epoch {epoch} · living" if epoch
                           else "living") if c]
    return _frame(rows, "ascii" if ascii_frame else "dashed", caption)


def frames(grid: Sequence[Sequence[int]], state_bytes: bytes, *,
           count: int = 8, activity: int = LIVING_CELL_CAP,
           ramp: str = UNICODE_RAMP) -> List[List[str]]:
    """``count`` successive living renderings, for an animated display.

    Frame *i* is driven by ``state_bytes`` plus the frame index, so the whole
    sequence is reproducible from the same ledger state — an animation, not a
    random walk. Frames live entirely outside the signature envelope: a moving
    face changes pixels, and ``image_sha3_512`` covers pixels.
    """
    return [render_rows(
                living_rows(grid, state_bytes + i.to_bytes(4, "big"), activity),
                ramp)
            for i in range(count)]


def gallery(plates: Sequence[str], *, gap: int = 2) -> str:
    """Lay finished plates side by side, top-aligned, padded to equal height.

    Column alignment is computed in code points. With :data:`UNICODE_RAMP` in a
    terminal that renders block elements as double-width, the columns will
    drift — pass ``ascii_frame=True`` and ``ramp=ASCII_RAMP`` to
    :func:`plate` when alignment must be exact.
    """
    if not plates:
        return ""
    blocks = [p.split("\n") for p in plates]
    height = max(len(b) for b in blocks)
    padded: List[List[str]] = []
    for block in blocks:
        width = max(len(line) for line in block)
        padded.append([line.ljust(width) for line in block]
                      + [" " * width] * (height - len(block)))
    sep = " " * gap
    return "\n".join(sep.join(col[i] for col in padded)
                     for i in range(height))


def plate_size(*, title: str = "", epoch: str = "",
               tag: str = "") -> Tuple[int, int]:
    """(columns, rows) a framed plate occupies — for laying out a page.

    The caption widens the frame when it is longer than the grid, so the
    caption has to be part of the question. Code points, not display columns
    (see :func:`gallery`).
    """
    caption = [c for c in (title, _epoch_line(epoch, tag)) if c]
    width = max([GRID_W] + [len(c) for c in caption]) + 4
    height = GRID_H + 2 + (len(caption) + 1 if caption else 0)
    return width, height


def check_ramp(ramp: str) -> Optional[str]:
    """Return why ``ramp`` is unusable, or ``None`` if it is fine."""
    if len(ramp) != LEVELS:
        return f"ramp must have exactly {LEVELS} glyphs, got {len(ramp)}"
    if len(set(ramp)) != LEVELS:
        return "ramp glyphs must be distinct (two levels would look alike)"
    return None


__all__ = [
    "ASCII_RAMP", "UNICODE_RAMP", "LIVING_CELL_CAP",
    "plate", "living_plate", "living_rows", "frames", "gallery",
    "plate_size", "check_ramp",
]
