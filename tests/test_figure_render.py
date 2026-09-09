"""EPX-F on paper: the runic plate, and the ink it is forbidden to lay down.

Two properties carry the weight here. The **two-band** property of EPX-F §3.1
has to survive all the way to pixels — rotating the issuing key must move the
bottom two rows of the drawing and nothing above them — and the **cube must not
notice** that a plate was added, byte for byte.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from eopx.artifact_figure import CONTENT_ROWS, GRID_H, figure_grid
from eopx.figure_render import (
    band_split_y,
    plate_pixel_size,
    render_artifact_plate,
    render_figure_plate,
    render_living_plate,
)
from eopx.metatron.runes import NUM_RUNES, rune_image, rune_strokes

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

# EPX-F §9 vectors.
MR_A = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
FP_A = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
FP_B = bytes.fromhex(
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")


# --------------------------------------------------------------------------- #
# The rune alphabet
# --------------------------------------------------------------------------- #

def test_sixteen_runes_are_visually_distinct():
    """A cell state that renders like another is a decode error by design."""
    seen = {}
    for value in range(NUM_RUNES):
        key = rune_image(value, 48).tobytes()
        assert key not in seen, (
            f"rune {value} renders identically to rune {seen[key]}")
        seen[key] = value


def test_rune_value_outside_the_field_is_refused():
    with pytest.raises(ValueError):
        rune_strokes(NUM_RUNES)
    with pytest.raises(ValueError):
        rune_strokes(-1)


# --------------------------------------------------------------------------- #
# Plate geometry
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cell_px", [12, 24, 32, 40])
def test_declared_size_matches_the_rendered_image(cell_px):
    """Page layout happens before the image exists; the two must agree."""
    grid = figure_grid(MR_A, FP_A)
    img = render_figure_plate(grid, cell_px=cell_px, tag="b0401fcd")
    assert img.size == plate_pixel_size(cell_px, caption=True)

    bare = render_figure_plate(grid, cell_px=cell_px)
    assert bare.size == plate_pixel_size(cell_px, caption=False)


def test_rendering_is_deterministic():
    a = render_artifact_plate(MR_A, FP_A, cell_px=20)
    b = render_artifact_plate(MR_A, FP_A, cell_px=20)
    assert a.tobytes() == b.tobytes()


def test_malformed_grids_are_refused():
    grid = figure_grid(MR_A, FP_A)
    with pytest.raises(ValueError):
        render_figure_plate(grid[:-1], cell_px=16)
    bad = [list(r) for r in grid]
    bad[0][0] = NUM_RUNES
    with pytest.raises(ValueError):
        render_figure_plate(bad, cell_px=16)


# --------------------------------------------------------------------------- #
# EPX-F §3.1 — the two bands, in ink
# --------------------------------------------------------------------------- #

def test_key_rotation_moves_only_the_epoch_band_of_the_drawing():
    """The whole point of two bands: a rotation must not redraw the parc.

    Same artifact, next issuing key. Above the band split the pixels have to be
    identical, below it they have to differ — otherwise the epoch is either
    invisible or contagious.
    """
    cell = 24
    a = render_artifact_plate(MR_A, FP_A, cell_px=cell)
    b = render_artifact_plate(MR_A, FP_B, cell_px=cell)
    assert a.size == b.size

    split = band_split_y(cell)
    assert (a.crop((0, 0, a.width, split)).tobytes()
            == b.crop((0, 0, b.width, split)).tobytes()), \
        "content band moved when only the issuing key changed"

    end = split + (GRID_H - CONTENT_ROWS) * cell
    assert (a.crop((0, split, a.width, end)).tobytes()
            != b.crop((0, split, b.width, end)).tobytes()), \
        "epoch band did not move across a key rotation"


def test_a_different_artifact_moves_both_bands():
    a = render_artifact_plate(MR_A, FP_A, cell_px=20)
    other = bytes(31) + b"\x01"
    b = render_artifact_plate(other, FP_A, cell_px=20)
    assert a.tobytes() != b.tobytes()


# --------------------------------------------------------------------------- #
# EPX-F §6 — a moving face must carry nothing to compare
# --------------------------------------------------------------------------- #

def test_a_living_plate_may_not_print_a_tag():
    grid = figure_grid(MR_A, FP_A)
    with pytest.raises(ValueError, match="living"):
        render_figure_plate(grid, cell_px=16, tag="b0401fcd", living=True)
    with pytest.raises(ValueError, match="living"):
        render_living_plate(grid, state_bytes=b"s", cell_px=16,
                            tag="b0401fcd")


def test_living_and_frozen_plates_are_visibly_different():
    grid = figure_grid(MR_A, FP_A)
    frozen = render_figure_plate(grid, cell_px=20, tag="b0401fcd")
    alive = render_living_plate(grid, state_bytes=b"ledger", activity=0,
                                cell_px=20)
    # Same cells (activity 0), so any difference is the frame and the caption —
    # which is exactly the signal a reader is meant to catch.
    assert frozen.tobytes() != alive.tobytes()


def test_living_drift_is_deterministic_in_the_state():
    grid = figure_grid(MR_A, FP_A)
    kw = dict(state_bytes=b"block-900001", activity=5, cell_px=16)
    assert (render_living_plate(grid, **kw).tobytes()
            == render_living_plate(grid, **kw).tobytes())


# --------------------------------------------------------------------------- #
# Placement: the plate may not touch anything that is read
# --------------------------------------------------------------------------- #

def test_reserved_regions_reject_a_plate_on_the_cube():
    from print_sheet import assert_clear, cube_rect_in_page  # type: ignore

    cube_x, cube_y, cube_px = cube_rect_in_page()
    centre = (cube_x + cube_px // 3, cube_y + cube_px // 3,
              cube_x + 2 * cube_px // 3, cube_y + 2 * cube_px // 3)
    with pytest.raises(ValueError, match="cube"):
        assert_clear(centre, "test plate")


def test_the_real_slot_clears_the_cube_the_fiducials_and_the_scan_grid():
    from print_sheet import (  # type: ignore
        assert_clear, figure_plate_slot, mm,
    )
    from eopx.figure_render import plate_pixel_size as size

    # A plausible footer end, matching what `make_sheet` computes.
    foot_y = mm(190.0)
    slot = figure_plate_slot(foot_y)
    assert slot is not None, "the plate no longer fits the page"
    x, y, cell_px = slot
    w, h = size(cell_px)
    assert_clear((x, y, x + w, y + h), "EPX-F figure plate", foot_y)


def test_the_slot_shrinks_rather_than_collides():
    """Cell size is derived, not hard-coded: a tighter page yields smaller runes."""
    from print_sheet import figure_plate_slot, mm  # type: ignore

    roomy = figure_plate_slot(mm(190.0))
    assert roomy is not None
    # Push the footer far enough down and the plate must decline, not overlap.
    assert figure_plate_slot(mm(280.0)) is None


# --------------------------------------------------------------------------- #
# The constraint that actually matters: the cube does not notice
# --------------------------------------------------------------------------- #

def test_adding_the_plate_leaves_the_cube_byte_identical():
    """The hard rule, checked where it can fail: on the composed page.

    Not "the plate looks far away" but "the carriers are the same bytes". This
    is what makes re-running `scripts/detect_envelope.py` unnecessary as a
    regression gate — a decode envelope cannot change if the pixels do not.
    """
    from print_sheet import cube_rect_in_page, make_sheet, mm  # type: ignore
    from eopx.metatron import encode_private

    symbols = encode_private(bytes(range(32)))
    common = dict(role="private", label="test", hash_hex="00" * 32)

    without = make_sheet(symbols, **common)
    with_plate = make_sheet(symbols, **common, figure=(MR_A, FP_A))

    cube_x, cube_y, cube_px = cube_rect_in_page()
    pad = mm(4.0)
    box = (cube_x - pad, cube_y - pad, cube_x + cube_px + pad,
           cube_y + cube_px + pad)
    assert (without.crop(box).tobytes() == with_plate.crop(box).tobytes()), \
        "the figure plate changed pixels inside the cube's quiet zone"

    # And the page did change somewhere, or the assertion above is vacuous.
    assert without.tobytes() != with_plate.tobytes()


def test_the_scan_grid_is_byte_identical_too():
    """The 6-colour channel is read as well, and pays the same protection."""
    from print_sheet import make_sheet  # type: ignore
    from eopx.metatron import encode_private

    symbols = encode_private(bytes(range(32)))
    common = dict(role="public", label="test", hash_hex="11" * 32)
    without = make_sheet(symbols, **common)
    with_plate = make_sheet(symbols, **common, figure=(MR_A, FP_A))

    # `make_sheet` centres the grid; compare the whole band it occupies.
    from print_sheet import chroma_grid_rect, mm  # type: ignore
    foot_y = _footer_end(common["role"])
    gx, gy, gw, gh = chroma_grid_rect(foot_y)
    pad = mm(2.0)
    box = (gx - pad, gy - pad, gx + gw + pad, gy + gh + pad)
    assert without.crop(box).tobytes() == with_plate.crop(box).tobytes()


def _footer_end(role: str) -> int:
    """Reproduce `make_sheet`'s footer cursor for a sheet with no extra lines."""
    from print_sheet import (  # type: ignore
        CUBE_SIDE_MM, FIDUCIAL_INSET_MM, FIDUCIAL_MM, FIDUCIAL_QUIET_MM, mm,
    )
    inset = mm(FIDUCIAL_INSET_MM)
    banner_y = inset + mm(FIDUCIAL_MM) + mm(FIDUCIAL_QUIET_MM) + mm(8.0)
    cube_y = banner_y + mm(14.0) + mm(10.0)
    scale_y = cube_y + mm(CUBE_SIDE_MM) + mm(5.0)
    return scale_y + mm(4.0) + 2 * mm(3.0)
