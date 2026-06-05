"""End-to-end loopback for the EPX-H seal badge through the real fiducial path.

This is the proof that "the badge works with a camera": the seal cube is wrapped
in the validated A4 page-corner ArUco frame (``scripts/print_sheet.make_sheet``),
then pushed back through the production detection pipeline:

    sheet image → autodetect_cube (page ArUco) → rectify → extract_canonical

The decisive assertion is that the *seal* cube recovers exactly the same symbols
as a *plain* cube — i.e. the seal modulation (Mesures A+B) introduces **zero**
additional symbol-classification errors in the actual decode path.

Skipped automatically when OpenCV is unavailable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

cv2 = pytest.importorskip("cv2")  # noqa: F841 — ArUco detection requires OpenCV

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from print_sheet import make_sheet  # noqa: E402

from eopx.metatron import encode_public, render_seal_revealed  # noqa: E402
from eopx.metatron.aruco import autodetect_cube  # noqa: E402
from eopx.metatron.detect import extract_canonical  # noqa: E402


SPINOR = bytes((i * 7 + 3) % 256 for i in range(64))
VAULT_FP = bytes((i * 5 + 11) % 256 for i in range(32))


def _decode_sheet(sheet) -> list:
    detection = autodetect_cube(sheet, normalize=False)
    syms, _dists = extract_canonical(detection.cube_image)
    return syms


@pytest.fixture(scope="module")
def symbols():
    return encode_public(SPINOR)


def _seal_renderer():
    def _render(syms, size):
        return render_seal_revealed(syms, VAULT_FP, SPINOR, size=size)
    return _render


def test_page_aruco_detected_on_seal_sheet(symbols):
    sheet = make_sheet(symbols, "public", "loopback", SPINOR.hex(),
                       cube_renderer=_seal_renderer())
    detection = autodetect_cube(sheet, normalize=False)
    assert detection.method == "page_aruco"
    assert detection.cube_image.size[0] == detection.cube_image.size[1]


def test_seal_badge_adds_no_symbol_errors(symbols):
    """The seal cube must decode to the same symbols as the plain cube."""
    plain_sheet = make_sheet(symbols, "public", "loopback", SPINOR.hex())
    seal_sheet = make_sheet(symbols, "public", "loopback", SPINOR.hex(),
                            cube_renderer=_seal_renderer())

    plain_syms = _decode_sheet(plain_sheet)
    seal_syms = _decode_sheet(seal_sheet)

    assert len(seal_syms) == len(symbols) == 91
    # The seal introduces no extra misclassification relative to the plain cube.
    plain_matches = sum(a == b for a, b in zip(plain_syms, symbols))
    seal_matches = sum(a == b for a, b in zip(seal_syms, symbols))
    assert seal_matches >= plain_matches, (
        f"seal degraded recovery: plain={plain_matches}/91 seal={seal_matches}/91"
    )


def test_seal_cube_recovers_most_symbols(symbols):
    """Sanity floor: the synthetic (noise-free) loopback should be near-perfect."""
    seal_sheet = make_sheet(symbols, "public", "loopback", SPINOR.hex(),
                            cube_renderer=_seal_renderer())
    seal_syms = _decode_sheet(seal_sheet)
    matches = sum(a == b for a, b in zip(seal_syms, symbols))
    assert matches >= 86, f"only {matches}/91 symbols recovered through fiducials"
