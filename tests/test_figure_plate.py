"""EPX-F §6 — presentation. Glyphs may move; the grid and its digest may not."""

import pytest

from eopx.artifact_figure import (
    ASCII_RAMP,
    GRID_H,
    GRID_W,
    LEVELS,
    figure_digest,
    figure_grid,
    figure_tag,
)
from eopx.figure_plate import (
    LIVING_CELL_CAP,
    UNICODE_RAMP,
    check_ramp,
    frames,
    gallery,
    living_plate,
    living_rows,
    plate,
    plate_size,
)

MR = bytes(range(32))
FP = bytes(range(0x80, 0xA0))
STATE = b"controller=abc;seq=7"


@pytest.fixture
def grid():
    return figure_grid(MR, FP)


# --- ramps -----------------------------------------------------------------

def test_unicode_ramp_is_a_usable_ramp():
    assert check_ramp(UNICODE_RAMP) is None
    assert check_ramp(ASCII_RAMP) is None


def test_check_ramp_catches_the_two_ways_a_ramp_breaks():
    assert "exactly" in check_ramp("short")
    assert "distinct" in check_ramp("a" * LEVELS)


def test_ramp_choice_never_touches_the_digest(grid):
    before = figure_digest(grid)
    plate(grid, ramp=UNICODE_RAMP)
    plate(grid, ramp=ASCII_RAMP)
    assert figure_digest(grid) == before


# --- frozen plate ----------------------------------------------------------

def test_plate_is_rectangular_and_framed(grid):
    out = plate(grid, title="Speculum Primum", epoch="80818283")
    lines = out.split("\n")
    assert len({len(ln) for ln in lines}) == 1, "plate must be rectangular"
    assert lines[0].startswith("┌") and lines[0].endswith("┐")
    assert lines[-1].startswith("└") and lines[-1].endswith("┘")


def test_frozen_plate_prints_the_tag(grid):
    """The tag is what a reader compares against a recomputation."""
    assert figure_tag(grid) in plate(grid, epoch="80818283")


def test_ascii_frame_stays_ascii(grid):
    out = plate(grid, title="relic", ramp=ASCII_RAMP, ascii_frame=True)
    out.encode("ascii")  # raises if anything slipped in


@pytest.mark.parametrize("title, epoch", [
    ("Speculum Primum", "80818283"),   # caption wider than the grid
    ("r", "80818283"),
    ("", ""),                          # no caption at all
])
def test_plate_size_matches_reality(grid, title, epoch):
    out = plate(grid, title=title, epoch=epoch)
    lines = out.split("\n")
    # plate() always prints the tag — that is the caption's whole purpose.
    expected = plate_size(title=title, epoch=epoch, tag=figure_tag(grid))
    assert (len(lines[0]), len(lines)) == expected


# --- living face -----------------------------------------------------------

def test_living_drift_is_bounded(grid):
    live = living_rows(grid, STATE, activity=99)
    drifted = sum(a != b
                  for ra, rb in zip(grid, live)
                  for a, b in zip(ra, rb))
    assert 0 < drifted <= LIVING_CELL_CAP


def test_no_activity_means_no_drift(grid):
    assert living_rows(grid, STATE, activity=0) == [list(r) for r in grid]


def test_living_drift_is_deterministic(grid):
    assert living_rows(grid, STATE, 3) == living_rows(grid, STATE, 3)
    assert living_rows(grid, STATE, 3) != living_rows(grid, b"other", 3)


def test_living_cells_stay_in_range(grid):
    live = living_rows(grid, STATE, activity=LIVING_CELL_CAP)
    assert all(0 <= c < LEVELS for row in live for c in row)
    assert len(live) == GRID_H and all(len(r) == GRID_W for r in live)


def test_living_plate_hides_the_tag_and_dashes_its_frame(grid):
    """The safety property: a moving face offers nothing to compare."""
    out = living_plate(grid, state_bytes=STATE, activity=4,
                       title="relic", epoch="80818283")
    assert figure_tag(grid) not in out
    assert "living" in out
    assert "╌" in out.split("\n")[0]


def test_living_plate_differs_from_the_frozen_one(grid):
    frozen = plate(grid, title="relic", epoch="80818283")
    live = living_plate(grid, state_bytes=STATE, activity=4,
                        title="relic", epoch="80818283")
    assert frozen != live


# --- animation -------------------------------------------------------------

def test_frames_are_reproducible_and_distinct(grid):
    a = frames(grid, STATE, count=6)
    b = frames(grid, STATE, count=6)
    assert a == b
    assert len(a) == 6
    assert len({tuple(f) for f in a}) > 1, "an animation that never moves"


def test_every_frame_has_the_grid_shape(grid):
    for f in frames(grid, STATE, count=4):
        assert len(f) == GRID_H
        assert all(len(row) == GRID_W for row in f)


# --- gallery ---------------------------------------------------------------

def test_gallery_aligns_plates_of_equal_height(grid):
    other = figure_grid(bytes(range(32, 64)), FP)
    out = gallery([plate(grid, title="one", ramp=ASCII_RAMP, ascii_frame=True),
                   plate(other, title="two", ramp=ASCII_RAMP,
                         ascii_frame=True)])
    lines = out.split("\n")
    assert len({len(ln) for ln in lines}) == 1


def test_gallery_pads_a_shorter_block(grid):
    tall = plate(grid, title="t", epoch="80818283", ramp=ASCII_RAMP,
                 ascii_frame=True)
    short = "+--+\n|  |\n+--+"
    out = gallery([tall, short])
    lines = out.split("\n")
    assert len(lines) == len(tall.split("\n"))
    assert len({len(ln) for ln in lines}) == 1


def test_empty_gallery_is_empty():
    assert gallery([]) == ""
