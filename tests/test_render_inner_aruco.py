"""The six inner ArUco markers must land somewhere they can actually be seen.

``INNER_ARUCO_OFFSET`` was 1.50, which places every marker past the canvas
edge: the drawable radius *is* the half-width of the drawable area, so 1.5x it
is outside by half again. ``_render_inner_aruco`` ran and painted nothing
visible, which is why the markers were recorded as "not currently rendered"
and why ``metatron/local_rectify.py`` — the rectifier that expects to find
them — was never wired up and shows 0% coverage.

The window is narrow: below ~1.13 the marker overlaps the vertex's coloured
ring, which would cover a carrier; above ~1.20 it runs off the canvas. These
tests pin both walls, so the constant cannot go quietly wrong a second time.
"""

from __future__ import annotations

import pytest

from eopx.metatron.render import (
    ARUCO_INNER_IDS,
    INNER_ARUCO_FRAC,
    INNER_ARUCO_OFFSET,
    VERTEX_RADIUS_FRAC,
    inner_aruco_centers,
)

SIZES = (512, 1024, 2048)


def _marker_side(size: int) -> int:
    return max(8, round(size * INNER_ARUCO_FRAC))


@pytest.mark.parametrize("size", SIZES)
def test_every_marker_is_inside_the_canvas(size):
    """The wall the old value fell off, at three scales.

    The geometry is scale-invariant, so a value that fits at one size fits at
    all of them — which also means a value that does not fit, fits nowhere.
    """
    half = _marker_side(size) / 2.0
    centres = inner_aruco_centers(size)
    assert len(centres) == len(ARUCO_INNER_IDS)
    for marker_id, (x, y) in centres.items():
        assert half <= x <= size - half, f"marker {marker_id} off canvas in x"
        assert half <= y <= size - half, f"marker {marker_id} off canvas in y"


@pytest.mark.parametrize("size", SIZES)
def test_no_marker_covers_a_carrier(size):
    """The other wall: ink on a vertex disk is ink on one of the 91 carriers.

    The markers are meant to sit in the white margin *outside* the coloured
    ring. Pushing them inward to gain rectification accuracy would start
    paying in decode margin, which is the trade this constant must not make
    silently.
    """
    side = _marker_side(size)
    ring_r = size * VERTEX_RADIUS_FRAC
    margin = int(size * VERTEX_RADIUS_FRAC * 0)  # kept explicit: no slack
    radius_px = (size - 2 * int(size * 0.10)) / 2.0
    gap_to_vertex = (INNER_ARUCO_OFFSET - 1.0) * radius_px
    clearance = gap_to_vertex - ring_r - side / 2.0 - margin
    assert clearance > 0, (
        f"at size {size} the marker overlaps the vertex ring by "
        f"{-clearance:.1f} px"
    )


def test_the_offset_sits_between_the_two_walls():
    """A regression guard on the constant itself, not on a rendering.

    Someone tuning this will reach for the constant, not for the geometry.
    The bounds are what the two tests above measure; naming them here means a
    wrong value fails with the reason rather than with a pixel comparison.
    """
    assert 1.13 < INNER_ARUCO_OFFSET < 1.20, (
        "below ~1.13 the marker covers a carrier, above ~1.20 it leaves the "
        f"canvas; got {INNER_ARUCO_OFFSET}"
    )


def test_geometry_is_scale_invariant():
    """Doubling the canvas doubles every offset from centre, exactly."""
    a = inner_aruco_centers(1024)
    b = inner_aruco_centers(2048)
    for marker_id, (x, y) in a.items():
        bx, by = b[marker_id]
        assert bx - 1024 == pytest.approx(2 * (x - 512), rel=1e-9)
        assert by - 1024 == pytest.approx(2 * (y - 512), rel=1e-9)


def test_markers_render_and_are_detected():
    """End to end: paint them and ask OpenCV to find them.

    The unit tests above check arithmetic; this one checks that the arithmetic
    describes something a detector can actually see. Skipped without cv2,
    which is a real absence rather than a tolerance — the markers exist only
    to be detected.
    """
    cv2 = pytest.importorskip("cv2")
    import random

    import numpy as np

    from eopx.metatron import encode_private, render
    from eopx.metatron.render import ARUCO_DICT_NAME, _render_inner_aruco

    size = 1024
    rng = random.Random(2026)
    img = render(encode_private(bytes(rng.randrange(256) for _ in range(32))),
                 size=size)
    _render_inner_aruco(img, size)

    arr = cv2.cvtColor(np.asarray(img.convert("RGB")), cv2.COLOR_RGB2BGR)
    dictionary = cv2.aruco.getPredefinedDictionary(
        getattr(cv2.aruco, ARUCO_DICT_NAME))
    corners, ids, _ = cv2.aruco.ArucoDetector(
        dictionary, cv2.aruco.DetectorParameters()).detectMarkers(arr)

    assert ids is not None, "no marker detected at all"
    found = {int(i) for i in ids.flatten()}
    assert found == set(ARUCO_INNER_IDS.values()), found

    # Detected centres must agree with the geometry that placed them. The
    # tolerance covers the integer paste rounding in the renderer, not
    # detector error.
    expected = inner_aruco_centers(size)
    for quad, marker_id in zip(corners, ids.flatten()):
        cx, cy = quad[0].mean(axis=0)
        ex, ey = expected[int(marker_id)]
        assert ((cx - ex) ** 2 + (cy - ey) ** 2) ** 0.5 < 3.0
