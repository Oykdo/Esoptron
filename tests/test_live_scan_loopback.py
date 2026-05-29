"""Loopback test of the live-scan pipeline against a perfect virtual scan.

We render the print sheet, simulate a "perfect camera" by treating the
PNG as the BGR frame, run ArUco detection + homography + cube crop +
extract_canonical, and confirm that the resulting symbols match what
encode_private produced.
"""

from __future__ import annotations

import hashlib

import cv2
import numpy as np
from PIL import Image

from eopx.metatron import encode_private, render

# Re-use the live_scan helpers without launching the camera loop.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from print_sheet import make_sheet  # type: ignore  # noqa: E402
from live_scan import (  # type: ignore  # noqa: E402
    make_aruco_detector,
    detect_aruco_corners,
    homography_to_a4,
    rectify_a4,
    crop_cube,
)
from eopx.metatron import extract_canonical  # noqa: E402


def test_loopback_through_aruco_pipeline():
    seed = hashlib.sha3_256(b"live_scan.loopback").digest()
    cw = encode_private(seed)
    sheet_pil = make_sheet(cw, role="private",
                            label="loopback",
                            hash_hex=seed.hex())
    sheet_bgr = cv2.cvtColor(np.array(sheet_pil), cv2.COLOR_RGB2BGR)

    detector = make_aruco_detector()
    found = detect_aruco_corners(detector, sheet_bgr)
    assert found is not None, "ArUco markers not detected on the canonical sheet"
    assert set(found.keys()) == {0, 1, 2, 3}

    H = homography_to_a4(found)
    rectified = rectify_a4(sheet_bgr, H)
    cube_img = crop_cube(rectified, size_out=1024)
    symbols, dists = extract_canonical(cube_img)

    assert len(symbols) == 91
    # On a perfect virtual capture we expect zero misclassifications.
    n_mismatch = sum(1 for a, b in zip(symbols, cw) if a != b)
    assert n_mismatch == 0, f"{n_mismatch}/91 symbols differ on virtual capture"
