"""Phase 1 integration tests: end-to-end ArUco auto-detection + decode.

Builds an A4 print sheet with known seed, optionally applies a synthetic
perspective warp, then verifies that ``autodetect_cube`` followed by
``extract_canonical`` + ``decode_private`` recovers the original seed.

These tests cover the regression risk introduced by extracting ArUco
logic from ``server/app.py`` into ``src/eopx/metatron/aruco.py``.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import cv2
import numpy as np
import pytest
from PIL import Image

from eopx.metatron import (
    encode_private, encode_public, decode_private, extract_canonical, is_in_code,
    erasures_from_confidences,
)
from eopx.metatron.aruco import (
    autodetect_cube, detect_page_aruco, detect_cube_aruco,
    rectify_a4, to_bgr,
)

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from print_sheet import make_sheet, PAGE_W, PAGE_H  # type: ignore  # noqa: E402


KNOWN_PASSPHRASE = b"metatron.aruco_autodetect.v1"


@pytest.fixture(scope="module")
def known_seed() -> bytes:
    return hashlib.sha3_256(KNOWN_PASSPHRASE).digest()


@pytest.fixture(scope="module")
def a4_sheet(known_seed: bytes) -> Image.Image:
    cw = encode_private(known_seed)
    return make_sheet(
        cw, role="private",
        label=f"test passphrase {KNOWN_PASSPHRASE.decode()!r}",
        hash_hex=known_seed.hex(),
    )


@pytest.fixture(scope="module")
def public_a4_sheet() -> Image.Image:
    spinor = hashlib.sha3_512(KNOWN_PASSPHRASE + b".public").digest()
    cw = encode_public(spinor)
    return make_sheet(
        cw, role="public",
        label=f"test passphrase {KNOWN_PASSPHRASE.decode()!r}",
        hash_hex=spinor.hex(),
    )


def _decode(symbols, dists, threshold: float = 0.13) -> bytes:
    assert is_in_code(symbols), "extracted symbols must lie in code C"
    erasures = erasures_from_confidences(dists, threshold=threshold)
    seed, _version = decode_private(symbols, erasures=erasures)
    return seed


# ---------------------------------------------------------------------------
# Detection-only sanity checks
# ---------------------------------------------------------------------------

def test_page_aruco_detected_on_clean_sheet(a4_sheet: Image.Image) -> None:
    frame = to_bgr(a4_sheet)
    found = detect_page_aruco(frame)
    assert found is not None, "expected all 4 page ArUco markers on clean A4"
    assert set(found.keys()) == {0, 1, 2, 3}


def test_cube_aruco_optional(a4_sheet: Image.Image) -> None:
    # Cube-adjacent markers are currently disabled in print_sheet.py.
    # The detector must return None gracefully, never raise.
    frame = to_bgr(a4_sheet)
    result = detect_cube_aruco(frame)
    assert result is None or len(result) >= 3


# ---------------------------------------------------------------------------
# End-to-end auto-detect + decode (no perspective)
# ---------------------------------------------------------------------------

def test_autodetect_clean_sheet_recovers_seed(a4_sheet: Image.Image,
                                                known_seed: bytes) -> None:
    det = autodetect_cube(a4_sheet, prefer="page")
    assert det.method in ("page_aruco", "cube_aruco")
    syms, dists = extract_canonical(det.cube_image)
    recovered = _decode(syms, dists)
    assert recovered == known_seed


# ---------------------------------------------------------------------------
# End-to-end with synthetic perspective warp (simulates a phone photo)
# ---------------------------------------------------------------------------

def _warp_with_perspective(pil: Image.Image,
                            corner_offsets: tuple,
                            ) -> np.ndarray:
    """Apply a perspective warp to simulate a hand-held photo of the sheet.

    ``corner_offsets`` = (tl, tr, br, bl) tuples of (dx, dy) pixel offsets
    applied to each canonical page corner before computing the homography.
    Output canvas is PAGE_W x PAGE_H so the markers remain on-screen.
    """
    src = np.array([
        [0, 0],
        [PAGE_W - 1, 0],
        [PAGE_W - 1, PAGE_H - 1],
        [0, PAGE_H - 1],
    ], dtype=np.float32)
    dst = np.array([
        [corner_offsets[0][0],            corner_offsets[0][1]],
        [PAGE_W - 1 + corner_offsets[1][0], corner_offsets[1][1]],
        [PAGE_W - 1 + corner_offsets[2][0], PAGE_H - 1 + corner_offsets[2][1]],
        [corner_offsets[3][0],            PAGE_H - 1 + corner_offsets[3][1]],
    ], dtype=np.float32)
    H = cv2.getPerspectiveTransform(src, dst)
    bgr = to_bgr(pil)
    warped = cv2.warpPerspective(bgr, H, (PAGE_W, PAGE_H),
                                  borderValue=(255, 255, 255))
    return warped


@pytest.mark.parametrize("offsets", [
    # Mild tilt: top compressed inward, bottom pushed outward (typical phone)
    ((60, 40), (-60, 40), (-30, -30), (30, -30)),
    # Slight rotation + skew
    ((30, 80), (-50, 20), (-30, -40), (40, -20)),
    # No warp baseline
    ((0, 0), (0, 0), (0, 0), (0, 0)),
])
def test_autodetect_with_perspective_warp(a4_sheet: Image.Image,
                                            known_seed: bytes,
                                            offsets) -> None:
    warped_bgr = _warp_with_perspective(a4_sheet, offsets)
    det = autodetect_cube(warped_bgr, prefer="page")
    syms, dists = extract_canonical(det.cube_image)
    recovered = _decode(syms, dists)
    assert recovered == known_seed, (
        f"seed mismatch under perspective offsets={offsets} "
        f"(method={det.method}, markers={det.markers_used})"
    )


def test_autodetect_fails_gracefully_on_blank_image() -> None:
    blank = Image.new("RGB", (1024, 1024), (255, 255, 255))
    with pytest.raises(ValueError):
        autodetect_cube(blank)


def test_open_vault_cli_auto_detects_private_sheet(tmp_path: Path,
                                                    a4_sheet: Image.Image) -> None:
    from scripts.open_vault_from_photo import main as open_vault_main

    photo = tmp_path / "private_sheet.png"
    a4_sheet.save(photo, format="PNG")

    rc = open_vault_main([
        "open_vault_from_photo", str(photo),
        "--mode", "private",
        "--prefer", "page",
    ])
    assert rc == 0


def test_enroll_cli_auto_detects_public_sheet(tmp_path: Path,
                                               public_a4_sheet: Image.Image) -> None:
    from scripts.enroll_from_card import main as enroll_main

    photo = tmp_path / "public_sheet.png"
    out = tmp_path / "hologram.png"
    public_a4_sheet.save(photo, format="PNG")

    rc = enroll_main([
        "enroll_from_card", str(photo),
        "--prefer", "page",
        "--device-entropy", "01" * 32,
        "--out", str(out),
    ])
    assert rc == 0
    assert out.is_file()
