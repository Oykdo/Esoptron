"""EPX-F — frozen vectors and invariants for the artifact figure.

The vectors below are **normative**. Once a badge is printed, ``F`` can never
change: a failure here means either a real regression or a deliberate version
bump (new ``FIGURE_VERSION``, new domain strings, new spec section), never a
"fix the expected value" edit.
"""

import hashlib

import pytest

from eopx.artifact_figure import (
    ASCII_RAMP,
    CONTENT_ROWS,
    GRID_H,
    GRID_W,
    LEVELS,
    canonical_text,
    epoch_id,
    figure_digest,
    figure_grid,
    figure_tag,
    render_rows,
)

# --- test inputs (retypable by a port; no hidden state) --------------------
MR_A = bytes(range(32))                       # 000102...1f
FP_A = bytes(range(0x80, 0xA0))               # 8081...9f  — epoch N
FP_B = bytes(range(0xC0, 0xE0))               # c0c1...df  — epoch N+1
MR_B = hashlib.sha3_256(b"esoptron.epxf.testvector.B").digest()

VECTOR_A_A = (
    "49ae329b8b747b01\n"
    "ad04a51176f99b0e\n"
    "06ee014df09645a7\n"
    "749d394a34656097\n"
    "1d38ef49a89713dd\n"
    "55ab8c746369a81c\n"
    "1c56695457db99c4\n"
    "653882ef9bc627a8"
)

VECTOR_A_B = (
    "49ae329b8b747b01\n"
    "ad04a51176f99b0e\n"
    "06ee014df09645a7\n"
    "749d394a34656097\n"
    "1d38ef49a89713dd\n"
    "55ab8c746369a81c\n"
    "2c00cf5c5f9aecdc\n"
    "5d033f23dc4a2604"
)

VECTOR_B_A = (
    "2f9f56b3a3800600\n"
    "f4b4820ea5d1011d\n"
    "ee6f57889853c1a0\n"
    "ea52a2ace46aac27\n"
    "af617dbf1747fe22\n"
    "0edac7f63c5a5572\n"
    "84d0783b74d124f0\n"
    "c2e5de046ed70768"
)


# --- frozen vectors --------------------------------------------------------

@pytest.mark.parametrize("mr, fp, expected, tag", [
    (MR_A, FP_A, VECTOR_A_A, "b0401fcd"),
    (MR_A, FP_B, VECTOR_A_B, "ab02f2e7"),
    (MR_B, FP_A, VECTOR_B_A, "d67ea63a"),
])
def test_frozen_vectors(mr, fp, expected, tag):
    grid = figure_grid(mr, fp)
    assert canonical_text(grid) == expected
    assert figure_tag(grid) == tag


def test_test_input_is_what_it_claims():
    assert MR_B.hex() == (
        "d7cbece511de55e5b18a277abad1ddfb72e81f5f7f9c1ca042482eda41e49520")


def test_epoch_id_is_the_key_fingerprint_head():
    assert epoch_id(FP_A) == "80818283"
    assert epoch_id(FP_B) == "c0c1c2c3"


# --- the two-band contract -------------------------------------------------

def test_content_band_survives_key_rotation():
    """The artifact keeps its face when the issuing key rotates."""
    a = figure_grid(MR_A, FP_A)
    b = figure_grid(MR_A, FP_B)
    assert a[:CONTENT_ROWS] == b[:CONTENT_ROWS]


def test_epoch_band_moves_with_the_key():
    """...and the rotation is visible."""
    a = figure_grid(MR_A, FP_A)
    b = figure_grid(MR_A, FP_B)
    assert a[CONTENT_ROWS:] != b[CONTENT_ROWS:]
    assert figure_digest(a) != figure_digest(b)


def test_content_band_separates_artifacts():
    a = figure_grid(MR_A, FP_A)
    b = figure_grid(MR_B, FP_A)
    assert a[:CONTENT_ROWS] != b[:CONTENT_ROWS]


def test_deterministic():
    assert figure_grid(MR_A, FP_A) == figure_grid(MR_A, FP_A)


# --- shape and validation --------------------------------------------------

def test_grid_shape_and_levels():
    grid = figure_grid(MR_A, FP_A)
    assert len(grid) == GRID_H
    assert all(len(row) == GRID_W for row in grid)
    assert all(0 <= c < LEVELS for row in grid for c in row)


@pytest.mark.parametrize("mr, fp", [
    (b"\x00" * 31, FP_A),
    (b"\x00" * 33, FP_A),
    (MR_A, b"\x00" * 31),
    (MR_A, b""),
])
def test_rejects_wrong_length_inputs(mr, fp):
    with pytest.raises(ValueError):
        figure_grid(mr, fp)


def test_canonical_text_rejects_malformed_grid():
    grid = figure_grid(MR_A, FP_A)
    with pytest.raises(ValueError):
        canonical_text(grid[:-1])
    bad = [list(row) for row in grid]
    bad[0][0] = LEVELS
    with pytest.raises(ValueError):
        canonical_text(bad)


# --- glyphs are presentation, levels are the object ------------------------

def test_glyph_ramp_does_not_touch_the_digest():
    grid = figure_grid(MR_A, FP_A)
    unicode_ramp = " ░░▒▒▓▓██▚▚▞▞▛▜▟"
    assert len(unicode_ramp) == LEVELS
    assert render_rows(grid, unicode_ramp) != render_rows(grid, ASCII_RAMP)
    assert figure_digest(grid) == figure_digest(figure_grid(MR_A, FP_A))


def test_render_rows_shape_and_ramp_validation():
    grid = figure_grid(MR_A, FP_A)
    rows = render_rows(grid)
    assert len(rows) == GRID_H
    assert all(len(r) == GRID_W for r in rows)
    with pytest.raises(ValueError):
        render_rows(grid, "too short")
