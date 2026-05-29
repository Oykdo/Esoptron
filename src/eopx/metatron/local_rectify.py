"""Local rectification using 6 inner ArUco markers (IDs 20-25).

Instead of relying on 4 page-corner ArUco markers (which are far from the
cube and introduce homography error), this module detects 6 small ArUco
markers that are rendered directly into the cube image at V[7]..V[12]
positions. These travel with the cube and give a precise local warp.

Pipeline:
    phone photo
      -> detect inner ArUco IDs 20-25 (6 markers)
      -> compute homography: photo -> canonical cube frame
      -> warp + extract_canonical
      -> decode

Fallback: if < 6 inner markers found, fall back to the page-corner
ArUco method (IDs 0-3).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import cv2
import numpy as np
from PIL import Image

from .graph import VERTICES
from .render import (
    ARUCO_DICT_NAME, ARUCO_INNER_IDS, INNER_ARUCO_OFFSET,
    MARGIN_FRAC, _project,
)
from .detect import extract_canonical, erasures_from_confidences
from .aruco import detect_page_aruco, rectify_cube_via_page_aruco

CANONICAL_SIZE = 1024


def _inner_aruco_canonical_positions(size: int = CANONICAL_SIZE) -> Dict[int, Tuple[float, float]]:
    """Return the canonical pixel position of each inner ArUco center
    in the rendered cube image."""
    center = size / 2.0
    margin = int(size * MARGIN_FRAC)
    radius_px = (size - 2 * margin) / 2.0
    scale = radius_px / (3 ** 0.5)

    positions = {}
    for vertex_idx, aruco_id in ARUCO_INNER_IDS.items():
        vx, vy = VERTICES[vertex_idx]
        r = (vx ** 2 + vy ** 2) ** 0.5
        if r == 0:
            continue
        target_r = INNER_ARUCO_OFFSET * (3 ** 0.5)
        factor = target_r / r
        mx = vx * factor
        my = vy * factor
        px = center + mx * scale
        py = center - my * scale
        positions[aruco_id] = (px, py)
    return positions


def make_inner_detector():
    """Create an ArUco detector tuned for the inner markers."""
    aruco = cv2.aruco
    dictionary = aruco.getPredefinedDictionary(getattr(aruco, ARUCO_DICT_NAME))
    params = aruco.DetectorParameters()
    params.cornerRefinementMethod = aruco.CORNER_REFINE_SUBPIX
    params.adaptiveThreshWinSizeMin = 3
    params.adaptiveThreshWinSizeMax = 23
    params.adaptiveThreshWinSizeStep = 4
    params.minMarkerPerimeterRate = 0.01
    return aruco.ArucoDetector(dictionary, params)


def detect_inner_markers(detector, frame_bgr: np.ndarray) -> Optional[Dict[int, Tuple[float, float]]]:
    """Detect inner ArUco markers (IDs 20-25) in a photo.

    Returns {aruco_id: (cx, cy)} using the marker centroid, or None
    if fewer than 4 are found (need at least 4 for homography).
    """
    corners, ids, _ = detector.detectMarkers(frame_bgr)
    if ids is None:
        return None
    ids_list = ids.flatten().tolist()
    needed = set(ARUCO_INNER_IDS.values())
    found = {}
    for marker_corners, mid in zip(corners, ids_list):
        if mid not in needed:
            continue
        c = marker_corners.reshape(4, 2)
        cx = c[:, 0].mean()
        cy = c[:, 1].mean()
        found[mid] = (float(cx), float(cy))
    # Need at least 4 for a homography
    return found if len(found) >= 4 else None


def rectify_cube_from_inner(photo_bgr: np.ndarray,
                             found: Dict[int, Tuple[float, float]],
                             dst_size: int = CANONICAL_SIZE) -> Image.Image:
    """Warp a photo so the cube fills a canonical square using inner markers.

    found: {aruco_id: (cx, cy)} from detect_inner_markers.
    Uses all available markers (4-6) for the homography.
    """
    dst_positions = _inner_aruco_canonical_positions(dst_size)
    src_pts = []
    dst_pts = []
    for aruco_id, src_pos in found.items():
        if aruco_id in dst_positions:
            src_pts.append(src_pos)
            dst_pts.append(dst_positions[aruco_id])

    if len(src_pts) < 4:
        raise ValueError(f"need >= 4 correspondences, got {len(src_pts)}")

    src_arr = np.array(src_pts, dtype=np.float32)
    dst_arr = np.array(dst_pts, dtype=np.float32)

    method = 0 if len(src_pts) == 4 else cv2.RANSAC
    H, _mask = cv2.findHomography(src_arr, dst_arr, method=method)

    if H is None:
        raise ValueError("homography computation failed")

    warped = cv2.warpPerspective(photo_bgr, H, (dst_size, dst_size),
                                  borderValue=(255, 255, 255))
    rgb = cv2.cvtColor(warped, cv2.COLOR_BGR2RGB)
    return Image.fromarray(rgb)


def extract_from_inner_aruco(photo_bgr: np.ndarray,
                              dst_size: int = CANONICAL_SIZE
                              ) -> Tuple[Optional[List[int]], Optional[List[float]], Optional[Image.Image], str]:
    """Full pipeline: photo -> inner ArUco detect -> rectify -> extract.

    Returns (symbols, distances, rectified_image, method_used).
    method_used is 'inner_aruco' or 'fallback'.
    Returns (None, None, None, 'failed') if nothing works.
    """
    detector = make_inner_detector()

    # Try inner markers first
    found_inner = detect_inner_markers(detector, photo_bgr)
    if found_inner is not None and len(found_inner) >= 4:
        try:
            rect = rectify_cube_from_inner(photo_bgr, found_inner, dst_size)
            syms, dists = extract_canonical(rect)
            return syms, dists, rect, "inner_aruco"
        except Exception:
            pass

    # Fallback: try page-corner ArUco (IDs 0-3)
    try:
        found_page = detect_page_aruco(photo_bgr)
        if found_page is not None:
            pil = rectify_cube_via_page_aruco(
                photo_bgr, found_page, dst_size=dst_size)
            syms, dists = extract_canonical(pil)
            return syms, dists, pil, "page_aruco"
    except Exception:
        pass

    return None, None, None, "failed"
