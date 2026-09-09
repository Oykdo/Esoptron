"""Detection pipeline: round-trip encode -> render -> detect -> decode."""

import os
import random

from PIL import Image
import numpy as np

from eopx.metatron import (
    encode_public, encode_private, decode_private, render, is_in_code,
    extract_canonical, extract_from_photo, rectify, erasures_from_confidences,
)
from eopx.metatron.graph import VERTICES
from eopx.metatron.render import _project


def test_canonical_extraction_public():
    """Public symbols survive render + detect round-trip.

    Deterministic on purpose. This test used to draw ``os.urandom(64)`` and
    assert ``max(dists) < 0.10``, which fails for roughly one spinor in
    fourteen — always on an edge tag, always for palette entries 8 or 11,
    whose rendered disks sit closest to their neighbours. The symbols were
    never wrong (0 mismatches in 60 random draws); only the confidence ceiling
    was too tight for those two colours. A test that fails 7% of the time
    teaches a team to re-run CI, which is worse than no test.

    The contract asserted here is the real one — a pristine render must decode
    exactly — plus a ceiling measured over 40 fixed spinors (observed maximum
    0.1431).
    """
    rng = random.Random(0)
    spinor = bytes(rng.randrange(256) for _ in range(64))
    syms = encode_public(spinor)
    img = render(syms, size=512)
    recovered, dists = extract_canonical(img)
    assert recovered == syms, f"{sum(1 for a,b in zip(recovered, syms) if a!=b)} symbol mismatches"
    assert max(dists) < 0.20, f"max distance {max(dists):.3f} unexpectedly large"


def test_canonical_extraction_public_is_exact_across_spinors():
    """The contract that must never bend: pristine renders decode exactly."""
    for seed in range(12):
        rng = random.Random(seed)
        spinor = bytes(rng.randrange(256) for _ in range(64))
        syms = encode_public(spinor)
        recovered, _dists = extract_canonical(render(syms, size=512))
        assert recovered == syms, f"spinor seed {seed} misread"


def test_canonical_extraction_private():
    """Private symbols survive render + detect, and the test algebraic
    indicator confirms membership in C."""
    seed = os.urandom(32)
    syms = encode_private(seed)
    img = render(syms, size=1024)  # private cubes render at higher res
    recovered, _dists = extract_canonical(img)
    assert recovered == syms
    assert is_in_code(recovered)


def test_decode_after_render_round_trip():
    """The full functional contract: take a seed, render it as a cube,
    sample the cube as if photographed, decode -- should recover the seed."""
    seed = bytes(range(32))
    cw = encode_private(seed)
    img = render(cw, size=1024)
    syms, _ = extract_canonical(img)
    rec, ver = decode_private(syms)
    assert rec == seed
    assert ver == 1


def test_rectify_identity():
    """Rectifying a canonical image with its own fiducials is a near-identity."""
    seed = os.urandom(32)
    cw = encode_private(seed)
    img = render(cw, size=512)
    # Fiducials = pixel positions of the 6 outer hexagon vertices in the
    # canonical render. With src == dst, rectify must be visually unchanged
    # (modulo BICUBIC interpolation noise).
    fiducials = [_project(VERTICES[i], 512) for i in range(7, 13)]
    rect = rectify(img, fiducials, dst_size=512)
    syms_orig, _ = extract_canonical(img)
    syms_rect, _ = extract_canonical(rect)
    # Allow up to a few symbol changes due to resampling noise.
    diffs = sum(1 for a, b in zip(syms_orig, syms_rect) if a != b)
    assert diffs <= 3, f"identity rectification altered {diffs} symbols"


def test_rectify_with_perspective_distortion():
    """Apply a known modest perspective distortion to a rendered cube,
    then ask rectify() to undo it and check we recover the original
    symbols within the RS decoder's correction budget.

    Offsets here (4-8 px on a 1024-canvas with outer-hex radius ~410 px)
    simulate a roughly steady handheld photo (~1-2% of figure radius).
    """
    rng = random.Random(2026)
    seed = bytes(rng.randrange(256) for _ in range(32))
    cw = encode_private(seed)
    canvas = 1024
    img = render(cw, size=canvas)

    src_canonical = [_project(VERTICES[i], canvas) for i in range(7, 13)]
    offsets = [(6, -4), (-5, 3), (8, 6), (-2, 8), (4, -7), (-6, -2)]
    src_distorted = [(x + dx, y + dy) for (x, y), (dx, dy) in zip(src_canonical, offsets)]

    from eopx.metatron.detect import _compute_homography
    H = _compute_homography(src_canonical, src_distorted)
    H_inv = np.linalg.inv(H)
    H_inv = H_inv / H_inv[2, 2]
    coeffs = tuple(H_inv.flatten()[:8])
    distorted = img.transform(
        (canvas, canvas), Image.Transform.PERSPECTIVE, coeffs,
        resample=Image.Resampling.BICUBIC, fillcolor=(16, 16, 22),
    )

    rect_syms, rect_dists, _ = extract_from_photo(
        distorted, src_distorted, dst_size=canvas,
    )
    # Measured: this distortion costs 0 misread carriers (see
    # scripts/detect_envelope.py). The bound leaves room for resampling
    # differences between platforms and nothing more — the previous bound of
    # 21 was the theoretical erasure ceiling and would have passed through a
    # total collapse of the pipeline.
    diffs = sum(1 for a, b in zip(rect_syms, cw) if a != b)
    assert diffs <= 2, (
        f"too many symbol mismatches after perspective recovery: {diffs}"
    )

    # The RS layer must recover the seed, using the confidence signal to flag
    # uncertain carriers as erasures. A failure here is a regression in the
    # camera path and must fail the suite — never skip it.
    erasures = erasures_from_confidences(rect_dists, threshold=0.12)
    recovered, _ = decode_private(rect_syms, erasures=erasures)
    assert recovered == seed


def test_confidence_distance_is_low_for_pristine_render():
    """A pristine render should classify with very small Oklab distance."""
    seed = b"\x00" * 32
    cw = encode_private(seed)
    img = render(cw, size=1024)
    _syms, dists = extract_canonical(img)
    # Strict bound: pristine render should be near-zero distance everywhere.
    assert max(dists) < 0.05, (
        f"unexpected classification noise on pristine render: max d = {max(dists):.4f}"
    )
