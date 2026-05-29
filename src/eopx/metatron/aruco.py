"""ArUco-based auto-detection and rectification for Metatron sheets.

This module factorizes the detection logic previously embedded in
`server/app.py` so it can be reused by CLI tools (decode_from_photo,
eopx_pack/verify, future SDK) without depending on Flask.

Two marker families are supported, both rendered by ``scripts/print_sheet.py``:

* **Page-corner ArUco** — IDs ``{0, 1, 2, 3}`` near the A4 page corners.
  Coarse but always present. Used to rectify the full A4 page first,
  then crop the cube area via ``cube_rect_in_page()``.
* **Cube-adjacent ArUco** — IDs ``{10, 11, 12, 13}`` framing the cube
  itself. Much more precise: produces a direct cube rectification.

The high-level entry point is :func:`autodetect_cube` which accepts a
PIL image or a BGR numpy array, tries both strategies (cube-adjacent
first, page-corner second), and returns the canonical cube image ready
for :func:`eopx.metatron.extract_canonical`.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import numpy as np
from PIL import Image

try:
    import cv2  # OpenCV is required for ArUco detection
except Exception as exc:  # pragma: no cover - import-time fail
    raise RuntimeError(
        "opencv-python is required for ArUco auto-detection; "
        "install with `pip install opencv-contrib-python`"
    ) from exc

# ---------------------------------------------------------------------------
# Layout constants — re-exported from scripts/print_sheet.py
# ---------------------------------------------------------------------------
# We share the page geometry with the print generator to keep a single
# source of truth. The print module lives under ``scripts/`` for historical
# reasons (it predates package layout); we add it to sys.path lazily.

_SCRIPTS_DIR = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from print_sheet import (  # type: ignore  # noqa: E402
    PAGE_W,
    PAGE_H,
    ARUCO_DICT_NAME,
    CUBE_SIDE_MM,
    FIDUCIAL_INSET_MM,
    FIDUCIAL_MM,
    aruco_outer_corners,
    cube_aruco_corners,
    cube_rect_in_page,
    mm,
)

__all__ = [
    "CUBE_DST_SIZE",
    "ArucoDetection",
    "make_aruco_detector",
    "preprocess_for_aruco",
    "detect_page_aruco",
    "detect_cube_aruco",
    "rectify_a4",
    "rectify_cube_via_cube_aruco",
    "rectify_cube_via_page_aruco",
    "autodetect_cube",
    "to_bgr",
]

CUBE_DST_SIZE = 1024
PAGE_IDS = (0, 1, 2, 3)
CUBE_IDS = (10, 11, 12, 13)


# ---------------------------------------------------------------------------
# Detector construction
# ---------------------------------------------------------------------------

def make_aruco_detector() -> "cv2.aruco.ArucoDetector":
    """Return an ArUco detector tuned for phone photographs of A4 sheets.

    Threshold ranges and refinement parameters are lifted verbatim from
    ``server/app.py`` so behavior is unchanged.
    """
    aruco = cv2.aruco
    dictionary = aruco.getPredefinedDictionary(getattr(aruco, ARUCO_DICT_NAME))
    params = aruco.DetectorParameters()
    params.cornerRefinementMethod = aruco.CORNER_REFINE_SUBPIX
    params.adaptiveThreshWinSizeMin = 3
    params.adaptiveThreshWinSizeMax = 23
    params.adaptiveThreshWinSizeStep = 4
    params.adaptiveThreshConstant = 7.0
    params.minMarkerPerimeterRate = 0.02
    params.maxMarkerPerimeterRate = 0.5
    return aruco.ArucoDetector(dictionary, params)


_DETECTOR: Optional["cv2.aruco.ArucoDetector"] = None


def _detector() -> "cv2.aruco.ArucoDetector":
    global _DETECTOR
    if _DETECTOR is None:
        _DETECTOR = make_aruco_detector()
    return _DETECTOR


def preprocess_for_aruco(frame_bgr: np.ndarray) -> np.ndarray:
    """Unsharp-mask + CLAHE for better detection on blurry phone photos."""
    blurred = cv2.GaussianBlur(frame_bgr, (0, 0), 3)
    sharpened = cv2.addWeighted(frame_bgr, 1.5, blurred, -0.5, 0)
    lab = cv2.cvtColor(sharpened, cv2.COLOR_BGR2LAB)
    l, a, b = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    l = clahe.apply(l)
    return cv2.cvtColor(cv2.merge([l, a, b]), cv2.COLOR_LAB2BGR)


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------

ImageInput = Union[Image.Image, np.ndarray]


def to_bgr(img: ImageInput) -> np.ndarray:
    """Coerce a PIL image or numpy array into a BGR uint8 array."""
    if isinstance(img, Image.Image):
        if img.mode != "RGB":
            img = img.convert("RGB")
        return cv2.cvtColor(np.asarray(img), cv2.COLOR_RGB2BGR)
    arr = np.asarray(img)
    if arr.ndim != 3 or arr.shape[2] != 3:
        raise ValueError("expected an HxWx3 image array")
    return arr


# ---------------------------------------------------------------------------
# Marker detection
# ---------------------------------------------------------------------------

def detect_page_aruco(frame_bgr: np.ndarray) -> Optional[Dict[int, Tuple[float, float]]]:
    """Detect the 4 page-corner ArUco markers (IDs 0..3).

    Returns ``{id: outer_corner_xy}`` for all four markers, or ``None``
    if any is missing (even after preprocessing).
    """
    needed = set(PAGE_IDS)
    for img in (frame_bgr, preprocess_for_aruco(frame_bgr)):
        corners, ids, _ = _detector().detectMarkers(img)
        if ids is None:
            continue
        ids_list = ids.flatten().tolist()
        found: Dict[int, Tuple[float, float]] = {}
        for marker_corners, mid in zip(corners, ids_list):
            if mid not in needed:
                continue
            c = marker_corners.reshape(4, 2)
            # Outer corner = the corner with the same index as the marker ID
            # (matches the convention used by aruco_outer_corners()).
            found[mid] = (float(c[mid][0]), float(c[mid][1]))
        if needed.issubset(found.keys()):
            return found
    return None


def detect_cube_aruco(frame_bgr: np.ndarray) -> Optional[Dict[int, Tuple[float, float]]]:
    """Detect the 4 cube-adjacent ArUco markers (IDs 10..13).

    Returns ``{id: center_xy}`` for at least 3 of the 4 markers, or ``None``
    if fewer than 3 are detected.
    """
    needed = set(CUBE_IDS)
    for img in (frame_bgr, preprocess_for_aruco(frame_bgr)):
        corners, ids, _ = _detector().detectMarkers(img)
        if ids is None:
            continue
        ids_list = ids.flatten().tolist()
        found: Dict[int, Tuple[float, float]] = {}
        for marker_corners, mid in zip(corners, ids_list):
            if mid not in needed:
                continue
            c = marker_corners.reshape(4, 2)
            cx = float(c[:, 0].mean())
            cy = float(c[:, 1].mean())
            found[mid] = (cx, cy)
        if len(found) >= 3:
            return found
    return None


# ---------------------------------------------------------------------------
# Rectification
# ---------------------------------------------------------------------------

def _normalize_cube_crop(pil: Image.Image) -> Image.Image:
    """Brightness/white-balance normalization for phone-shot cube crops."""
    arr = np.array(pil, dtype=np.float32)
    h, w = arr.shape[:2]
    cy, cx = h // 2, w // 2
    quarter = min(h, w) // 4
    center_mean = arr[cy - quarter:cy + quarter,
                       cx - quarter:cx + quarter].mean()
    if center_mean > 160:
        return pil
    for c in range(3):
        ch = arr[:, :, c]
        p98 = np.percentile(ch, 98)
        if p98 > 30:
            arr[:, :, c] = arr[:, :, c] * (245.0 / p98)
    gamma = 0.70
    arr = np.power(np.clip(arr / 255.0, 0, 1), gamma) * 255.0
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), mode="RGB")


def rectify_a4(frame_bgr: np.ndarray,
               page_corners: Dict[int, Tuple[float, float]]
               ) -> np.ndarray:
    """Homography from photo to canonical A4 frame via 4 page-corner markers."""
    dst_outer = aruco_outer_corners()
    src = np.array([page_corners[i] for i in PAGE_IDS], dtype=np.float32)
    dst = np.array([dst_outer[i] for i in PAGE_IDS], dtype=np.float32)
    H, _ = cv2.findHomography(src, dst, method=0)
    if H is None:
        raise ValueError("page ArUco homography failed")
    return cv2.warpPerspective(frame_bgr, H, (PAGE_W, PAGE_H),
                                borderValue=(255, 255, 255))


def rectify_cube_via_page_aruco(frame_bgr: np.ndarray,
                                 page_corners: Dict[int, Tuple[float, float]],
                                 dst_size: int = CUBE_DST_SIZE,
                                 normalize: bool = True,
                                 ) -> Image.Image:
    """Rectify and crop the cube area using the page-corner markers."""
    rect_a4 = rectify_a4(frame_bgr, page_corners)
    x, y, side = cube_rect_in_page()
    sub = rect_a4[y:y + side, x:x + side]
    if sub.size == 0:
        raise ValueError("cube crop empty")
    pil = Image.fromarray(cv2.cvtColor(sub, cv2.COLOR_BGR2RGB))
    if pil.size != (dst_size, dst_size):
        pil = pil.resize((dst_size, dst_size), Image.Resampling.BICUBIC)
    if normalize:
        pil = _normalize_cube_crop(pil)
    return pil


def rectify_cube_via_cube_aruco(frame_bgr: np.ndarray,
                                 cube_corners: Dict[int, Tuple[float, float]],
                                 dst_size: int = CUBE_DST_SIZE,
                                 normalize: bool = True,
                                 ) -> Image.Image:
    """Rectify the cube via the 4 cube-adjacent markers (precise path)."""
    dst_centers = cube_aruco_corners()
    src_pts, dst_pts = [], []
    for mid, src_pos in cube_corners.items():
        if mid in dst_centers:
            src_pts.append(src_pos)
            dst_pts.append(dst_centers[mid])
    if len(src_pts) < 3:
        raise ValueError(f"need >= 3 correspondences, got {len(src_pts)}")

    src_arr = np.array(src_pts, dtype=np.float32)
    dst_arr = np.array(dst_pts, dtype=np.float32)
    method = 0 if len(src_pts) == 4 else cv2.RANSAC
    H, _mask = cv2.findHomography(src_arr, dst_arr, method=method)
    if H is None:
        raise ValueError("cube-ArUco homography failed")

    rect_a4 = cv2.warpPerspective(frame_bgr, H, (PAGE_W, PAGE_H),
                                   borderValue=(255, 255, 255))
    x, y, side = cube_rect_in_page()
    sub = rect_a4[y:y + side, x:x + side]
    if sub.size == 0:
        raise ValueError("cube crop empty")
    pil = Image.fromarray(cv2.cvtColor(sub, cv2.COLOR_BGR2RGB))
    if pil.size != (dst_size, dst_size):
        pil = pil.resize((dst_size, dst_size), Image.Resampling.BICUBIC)
    if normalize:
        pil = _normalize_cube_crop(pil)
    return pil


# ---------------------------------------------------------------------------
# High-level auto-detection
# ---------------------------------------------------------------------------

@dataclass
class ArucoDetection:
    """Result of :func:`autodetect_cube`.

    Attributes
    ----------
    cube_image:
        Rectified cube as a square PIL image at ``dst_size`` resolution.
        Ready to be passed to ``extract_canonical``.
    method:
        ``"cube_aruco"`` or ``"page_aruco"`` depending on which marker
        family produced the rectification.
    markers_used:
        Number of markers used for the homography.
    rectified_a4:
        Full rectified A4 page (BGR), for diagnostic display. ``None`` when
        the cube path was taken without an intermediate A4 step.
    """
    cube_image: Image.Image
    method: str
    markers_used: int
    rectified_a4: Optional[np.ndarray] = None


def autodetect_cube(img: ImageInput,
                    dst_size: int = CUBE_DST_SIZE,
                    normalize: bool = True,
                    prefer: str = "cube",
                    ) -> ArucoDetection:
    """Detect markers and return a rectified canonical cube image.

    Parameters
    ----------
    img:
        Input photograph (PIL or BGR numpy array).
    dst_size:
        Output square size, must match what ``extract_canonical`` expects
        in its sampling math (default 1024).
    normalize:
        Apply brightness/white-balance normalization to the cube crop.
    prefer:
        ``"cube"`` (default) tries the precise cube-adjacent markers first,
        then falls back to page-corner. ``"page"`` reverses the order.

    Raises
    ------
    ValueError
        If neither marker family yields a valid rectification.
    """
    frame_bgr = to_bgr(img)

    order = (("cube", "page") if prefer == "cube" else ("page", "cube"))
    errors: list[str] = []
    last_a4: Optional[np.ndarray] = None

    for strategy in order:
        if strategy == "cube":
            cube_corners = detect_cube_aruco(frame_bgr)
            if cube_corners is None:
                errors.append("cube ArUco not found")
                continue
            try:
                pil = rectify_cube_via_cube_aruco(
                    frame_bgr, cube_corners, dst_size=dst_size,
                    normalize=normalize)
                return ArucoDetection(
                    cube_image=pil, method="cube_aruco",
                    markers_used=len(cube_corners), rectified_a4=None)
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(f"cube ArUco rectify failed: {exc}")
        else:
            page_corners = detect_page_aruco(frame_bgr)
            if page_corners is None:
                errors.append("page ArUco not found")
                continue
            try:
                last_a4 = rectify_a4(frame_bgr, page_corners)
                pil = rectify_cube_via_page_aruco(
                    frame_bgr, page_corners, dst_size=dst_size,
                    normalize=normalize)
                return ArucoDetection(
                    cube_image=pil, method="page_aruco",
                    markers_used=len(page_corners), rectified_a4=last_a4)
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(f"page ArUco rectify failed: {exc}")

    raise ValueError("ArUco auto-detection failed: " + "; ".join(errors))
