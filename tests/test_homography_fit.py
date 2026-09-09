"""The homography fit, and the property whose absence nobody noticed.

``detect._compute_homography`` claimed "normalized DLT + SVD" in its docstring
and did no normalisation. That is not a documentation slip: the DLT minimises
an *algebraic* residual, and on raw pixel coordinates — 0..1024, every point
hundreds of units from the origin — that residual weights each correspondence
by its distance from the origin. The fit was dominated by where the frame
happened to be.

It is in the shipping path (``detect.rectify``, so every photograph), not only
in the bench. Measured on the six-fiducial fit this codebase uses, it
accounted for roughly four fifths of the residual, and it narrowed the
differential fiducial-localisation envelope by more than tenfold.

The test that matters is the second one. Exactness on consistent points passes
with or without normalisation — it is the *inconsistent* case, which is every
real photograph, where the two diverge.
"""

from __future__ import annotations

import numpy as np
import pytest

from eopx.metatron.detect import _compute_homography, _similarity_normalisation

# A projective map with real perspective terms, and six points spread across a
# 1024 canvas the way the fiducials are.
M = np.array([
    [1.2, 0.1, 30.0],
    [-0.05, 0.9, -20.0],
    [1e-4, -8e-5, 1.0],
])
SRC = [(100.0, 120.0), (900.0, 140.0), (880.0, 910.0),
       (130.0, 870.0), (500.0, 100.0), (500.0, 950.0)]


def apply_h(h: np.ndarray, point) -> tuple:
    v = h @ np.array([point[0], point[1], 1.0])
    return float(v[0] / v[2]), float(v[1] / v[2])


@pytest.fixture(scope="module")
def consistent():
    return [apply_h(M, p) for p in SRC]


def test_exact_on_projectively_consistent_points(consistent):
    """The easy property, which the un-normalised fit also had."""
    fit = _compute_homography(SRC, consistent)
    worst = max(np.hypot(*(np.array(apply_h(fit, p)) - np.array(d)))
                for p, d in zip(SRC, consistent))
    assert worst < 1e-6, worst


def test_the_fit_does_not_depend_on_where_the_frame_is(consistent):
    """The property that was missing, on the case that actually occurs.

    Translate and scale both point sets, refit, map back: a well-conditioned
    fit returns the same homography. The un-normalised version differed by
    ~1.0 in matrix entries here — twelve orders of magnitude worse than the
    normalised one — because it was minimising a residual that grows with
    distance from the origin.

    Real correspondences are never projectively consistent: six detected
    fiducials carry independent localisation error. So this is not a corner
    case, it is the operating regime.
    """
    rng = np.random.default_rng(7)
    noisy = [(x + rng.normal(0, 8), y + rng.normal(0, 8)) for x, y in consistent]

    direct = _compute_homography(SRC, noisy)

    similarity = np.array([[0.25, 0.0, -700.0],
                           [0.0, 0.25, 400.0],
                           [0.0, 0.0, 1.0]])
    moved = _compute_homography([apply_h(similarity, p) for p in SRC],
                                [apply_h(similarity, p) for p in noisy])
    mapped = np.linalg.inv(similarity) @ moved @ similarity
    mapped /= mapped[2, 2]

    assert np.abs(direct - mapped).max() < 1e-6, np.abs(direct - mapped).max()


def test_normalisation_puts_the_centroid_at_the_origin():
    """Hartley's conditions, asserted rather than assumed."""
    T, normalised = _similarity_normalisation(SRC)
    arr = np.asarray(normalised)
    assert np.allclose(arr.mean(axis=0), 0.0, atol=1e-12)
    assert np.sqrt((arr ** 2).sum(axis=1)).mean() == pytest.approx(2 ** 0.5)

    # T must be the map that produced them, or the denormalisation is wrong.
    for p, n in zip(SRC, normalised):
        assert apply_h(T, p) == pytest.approx(n, abs=1e-9)


def test_degenerate_input_is_refused():
    with pytest.raises(ValueError, match="equal length"):
        _compute_homography(SRC, SRC[:5])
    with pytest.raises(ValueError, match="at least 4"):
        _compute_homography(SRC[:3], SRC[:3])


def test_coincident_points_do_not_divide_by_zero():
    """Mean distance zero is a real input: a detector can report one point six
    times. It must not produce a NaN matrix that silently poisons a decode."""
    same = [(500.0, 500.0)] * 6
    T, normalised = _similarity_normalisation(same)
    assert np.isfinite(T).all()
    assert np.isfinite(np.asarray(normalised)).all()
