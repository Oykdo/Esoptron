"""Detection pipeline: image (canonical or photographed) -> 91 F_13 symbols.

Two layers are exposed:

1. `extract_canonical(img)`: assumes the image is already in canonical
   frame (square, cube centered, no perspective). Suitable as a round-trip
   sanity check on PNGs produced by `render.render()`.

2. `rectify(img, src_pts, dst_size)`: given 6 source points corresponding
   to the 6 outer hexagon vertices (in canonical index order 7..12), warps
   a photograph into the canonical frame so that layer 1 can then run.

3. `extract_from_photo(img, src_pts)`: chains rectify + extract_canonical.

This module deliberately avoids OpenCV. Homography is computed via numpy
SVD and applied via PIL's PERSPECTIVE transform. Suitable for prototyping
on desktop. A future production module will swap in OpenCV for automatic
fiducial detection.
"""

from __future__ import annotations

from collections import Counter
from typing import List, Optional, Sequence, Tuple

import numpy as np
from PIL import Image

from .graph import VERTICES, EDGES, NUM_VERTICES, NUM_EDGES
from .palette import classify_color, classify_margin
from .render import (
    DEFAULT_CANVAS, MARGIN_FRAC, VERTEX_RADIUS_FRAC,
    EDGE_TAG_RADIUS_FRAC, _project, edge_tag_position,
)

# Confidence threshold above which a classification is treated as an
# erasure (the RS layer is then asked to recover the carrier).
# Set high: only flag extreme outliers. The PGZ error-correcting decoder
# handles moderate misclassifications without needing them flagged.
# Only carriers with Oklab distance > threshold are erased.
ERASURE_THRESHOLD_OKLAB = 0.25


# ---------------------------------------------------------------------------
# Color sampling at canonical positions
# ---------------------------------------------------------------------------

def _sample_ring_color(arr: np.ndarray, cx: float, cy: float,
                        r_inner: float, r_outer: float
                       ) -> Tuple[int, int, int]:
    """Median RGB inside an annulus r_inner..r_outer centered at (cx, cy).

    Median (not mean) is robust against the few pixels of the disk outline
    stroke that happen to lie inside the ring.
    """
    h, w, _ = arr.shape
    x0 = max(0, int(cx - r_outer))
    x1 = min(w, int(cx + r_outer + 1))
    y0 = max(0, int(cy - r_outer))
    y1 = min(h, int(cy + r_outer + 1))
    if x1 <= x0 or y1 <= y0:
        return (0, 0, 0)
    sub = arr[y0:y1, x0:x1, :]
    ys, xs = np.ogrid[y0:y1, x0:x1]
    d2 = (xs - cx) ** 2 + (ys - cy) ** 2
    mask = (d2 >= r_inner ** 2) & (d2 <= r_outer ** 2)
    if mask.sum() == 0:
        return (0, 0, 0)
    pix = sub[mask]
    med = np.median(pix, axis=0)
    return (int(round(med[0])), int(round(med[1])), int(round(med[2])))


def _classify_edge_tag(arr: np.ndarray,
                       p1: Tuple[float, float],
                       p2: Tuple[float, float],
                       canvas_size: int) -> Tuple[int, float, float]:
    """Sample the colored disk attached to an edge and classify its color.

    Returns ``(symbol, distance, margin)``; see
    :func:`~eopx.metatron.palette.classify_margin` for what the margin buys.

    Uses local search: scan a small window around the canonical tag
    position to find the pixel cluster with the highest saturation
    (most likely the tag center, even if the homography was slightly off),
    then classify the median RGB of that cluster.
    """
    cx, cy = edge_tag_position(p1, p2, canvas_size)
    r_tag = max(4, int(round(canvas_size * EDGE_TAG_RADIUS_FRAC)))
    h, w, _ = arr.shape

    # Search window: ±(r_tag + 8) pixels around the canonical center.
    search_r = r_tag + 8
    x0 = max(0, int(cx - search_r))
    x1 = min(w, int(cx + search_r + 1))
    y0 = max(0, int(cy - search_r))
    y1 = min(h, int(cy + search_r + 1))
    if x1 <= x0 or y1 <= y0:
        return classify_margin(0, 0, 0)

    sub = arr[y0:y1, x0:x1, :].astype(np.float32)
    ys, xs = np.ogrid[y0:y1, x0:x1]

    # Compute per-pixel "colorfulness" (distance from grey).
    grey = sub.mean(axis=2, keepdims=True)
    colorfulness = np.sqrt(((sub - grey) ** 2).sum(axis=2))

    # Mask to only consider pixels within search_r of the canonical center.
    d2 = (xs - cx) ** 2 + (ys - cy) ** 2
    mask = d2 <= search_r ** 2

    # Find the most colorful cluster: pick the top-25% most colorful pixels
    # within the mask, compute their spatial centroid, then sample a disk
    # around that centroid.
    if mask.sum() == 0:
        return classify_margin(0, 0, 0)

    cf_masked = np.where(mask, colorfulness, 0)
    threshold = np.percentile(cf_masked[mask], 75)
    bright_mask = mask & (cf_masked >= threshold)

    if bright_mask.sum() < 2:
        # Fallback: just sample at the canonical center
        sample_r = max(3.0, r_tag * 0.60)
        rgb = _sample_disk_color_inner(arr, cx, cy, sample_r)
        return classify_margin(*rgb)

    # Centroid of the most-colorful pixels = refined tag center.
    sub_ys, sub_xs = np.where(bright_mask)
    refined_cx = float(sub_xs.mean()) + x0
    refined_cy = float(sub_ys.mean()) + y0

    # Sample a disk around the refined center.
    sample_r = max(3.0, r_tag * 0.55)
    rgb = _sample_disk_color_inner(arr, refined_cx, refined_cy, sample_r)
    sym, d, m = classify_margin(*rgb)

    # Also classify at the canonical center and take majority if they disagree.
    rgb2 = _sample_disk_color_inner(arr, cx, cy, sample_r)
    sym2, d2, m2 = classify_margin(*rgb2)
    if sym != sym2:
        # Disagreement: two samples read different symbols, so neither is
        # decided. Keep the closer one, but report the *disagreement* as the
        # doubt: the margin between them is what the erasure logic should see.
        if d < d2:
            return sym, d, min(m, abs(d - d2))
        return sym2, d2, min(m2, abs(d - d2))
    return sym, d, m


def _refine_vertex_position(arr: np.ndarray, cx: float, cy: float,
                             r_v: float, search_r: float,
                             canvas_size: int) -> Tuple[float, float]:
    """Find the center of the most-colorful cluster near a vertex.

    Like the edge tag local search, but optimized for vertex rings:
    the colored ring should be the most saturated feature in the vicinity.
    Returns (refined_cx, refined_cy).
    """
    h, w, _ = arr.shape
    # Search window
    x0 = max(0, int(cx - search_r))
    x1 = min(w, int(cx + search_r + 1))
    y0 = max(0, int(cy - search_r))
    y1 = min(h, int(cy + search_r + 1))
    if x1 <= x0 or y1 <= y0:
        return cx, cy

    sub = arr[y0:y1, x0:x1, :].astype(np.float32)
    grey = sub.mean(axis=2, keepdims=True)
    colorfulness = np.sqrt(((sub - grey) ** 2).sum(axis=2))

    ys, xs = np.ogrid[y0:y1, x0:x1]
    d2 = (xs - cx) ** 2 + (ys - cy) ** 2
    mask = d2 <= search_r ** 2

    if mask.sum() == 0:
        return cx, cy

    cf_masked = np.where(mask, colorfulness, 0)
    threshold = np.percentile(cf_masked[mask], 70)
    bright_mask = mask & (cf_masked >= threshold)

    if bright_mask.sum() < 3:
        return cx, cy

    sub_ys, sub_xs = np.where(bright_mask)
    refined_cx = float(sub_xs.mean()) + x0
    refined_cy = float(sub_ys.mean()) + y0

    # Sanity: if the refined position is too far from canonical, discard
    dist = ((refined_cx - cx) ** 2 + (refined_cy - cy) ** 2) ** 0.5
    if dist > r_v * 2:
        return cx, cy

    return refined_cx, refined_cy


def _sample_disk_color_inner(arr: np.ndarray, cx: float, cy: float, r: float
                             ) -> Tuple[int, int, int]:
    """Median RGB inside a filled disk of radius r at (cx, cy)."""
    h, w, _ = arr.shape
    x0 = max(0, int(cx - r))
    x1 = min(w, int(cx + r + 1))
    y0 = max(0, int(cy - r))
    y1 = min(h, int(cy + r + 1))
    if x1 <= x0 or y1 <= y0:
        return (0, 0, 0)
    sub = arr[y0:y1, x0:x1, :]
    ys, xs = np.ogrid[y0:y1, x0:x1]
    mask = (xs - cx) ** 2 + (ys - cy) ** 2 <= r ** 2
    if mask.sum() == 0:
        return (0, 0, 0)
    pix = sub[mask]
    med = np.median(pix, axis=0)
    return (int(round(med[0])), int(round(med[1])), int(round(med[2])))


def extract_canonical(img: Image.Image
                      ) -> Tuple[List[int], List[float]]:
    """Extract 91 F_13 symbols + per-carrier distances from a canonical image.

    Kept at two return values because that is what every caller since the
    beginning expects; :func:`extract_canonical_full` adds the margins, which
    are the signal the erasure logic actually wants.
    """
    symbols, distances, _margins = extract_canonical_full(img)
    return symbols, distances


def extract_canonical_full(img: Image.Image
                           ) -> Tuple[List[int], List[float], List[float]]:
    """Extract 91 symbols with both doubt signals: distances **and margins**.

    Uses local color search for edge tags (finds the most-colorful cluster
    near the canonical position to compensate for homography misalignment)
    and multi-sample majority voting for vertices.

    The margin — how much closer a carrier sits to its symbol than to the
    runner-up — is what separates a misread from a good read. Absolute
    distance does not: under a mediocre photograph the two distributions
    overlap almost entirely (see ``scripts/detect_envelope.py``).
    """
    if img.mode != "RGB":
        img = img.convert("RGB")
    arr = np.asarray(img)
    size = img.size[0]
    if img.size[0] != img.size[1]:
        raise ValueError("image must be square")

    symbols: List[int] = [0] * (NUM_VERTICES + NUM_EDGES)
    distances: List[float] = [0.0] * (NUM_VERTICES + NUM_EDGES)
    margins: List[float] = [0.0] * (NUM_VERTICES + NUM_EDGES)

    # --- Vertices: local color search + multi-sample ring, majority-vote ---
    r_v = size * VERTEX_RADIUS_FRAC
    r_inner = r_v * 0.55  # outside glyph (which spans 0..0.55 r_v)
    r_outer = r_v * 1.10  # wider ring to tolerate position offset
    vertex_search_r = r_v * 3.0  # search radius for local color centroid
    for i, coord in enumerate(VERTICES):
        cx, cy = _project(coord, size)
        # Local color search: find the most-colorful pixel cluster
        # near the canonical vertex position (same technique as edge tags).
        refined_cx, refined_cy = _refine_vertex_position(
            arr, cx, cy, r_v, vertex_search_r, size)
        # Multi-sample ring around the refined position
        offsets = [(0.0, 0.0),
                   (2.0, 0.0), (-2.0, 0.0),
                   (0.0, 2.0), (0.0, -2.0)]
        votes = []
        best_d = 999.0
        best_margin = 0.0
        for dx, dy in offsets:
            rgb = _sample_ring_color(arr, refined_cx + dx, refined_cy + dy,
                                      r_inner, r_outer)
            sym, d, m = classify_margin(*rgb)
            votes.append(sym)
            if d < best_d:
                best_d = d
                best_margin = m
        # Also try disk sampling at refined position (more tolerant of blur)
        from collections import Counter as _Counter
        disk_r = r_v * 0.80
        rgb_disk = _sample_disk_color_inner(arr, refined_cx, refined_cy, disk_r)
        sym_disk, d_disk, m_disk = classify_margin(*rgb_disk)
        votes.append(sym_disk)
        if d_disk < best_d:
            best_d = d_disk
            best_margin = m_disk
        counts = _Counter(votes).most_common()
        symbols[i] = counts[0][0]
        distances[i] = best_d
        # A split vote is doubt no distance can express: the samples read
        # different symbols, so the carrier is a prime erasure candidate
        # whatever the winning sample's own margin says.
        if len(counts) > 1 and counts[0][1] - counts[1][1] <= 1:
            best_margin = 0.0
        margins[i] = best_margin

    # --- Edges: read the colored tag at each canonical tag position ---
    for j, (vi, vj) in enumerate(EDGES):
        p1 = _project(VERTICES[vi], size)
        p2 = _project(VERTICES[vj], size)
        sym, d, m = _classify_edge_tag(arr, p1, p2, canvas_size=size)
        symbols[NUM_VERTICES + j] = sym
        distances[NUM_VERTICES + j] = d
        margins[NUM_VERTICES + j] = m

    return symbols, distances, margins


def extract_robust(img: Image.Image,
                   decode_fn=None) -> Tuple[List[int], List[float]]:
    """Extract symbols with multi-strategy retry: try several sampling
    configurations and return the first that decodes successfully.

    decode_fn: callable(symbols, erasures) -> bool or result.
               If it returns a truthy value, that value is returned along
               with the symbols/distances that produced it.
               If None, just returns the first extract_canonical result.
    """
    from .reed_solomon import TOTAL_N

    if img.mode != "RGB":
        img = img.convert("RGB")
    arr = np.asarray(img).copy()
    size = img.size[0]

    # Strategy 1: default extraction (local search + multi-sample)
    syms, dists, margins = extract_canonical_full(img)
    if decode_fn is None:
        return syms, dists
    result = decode_fn(syms, erasures_from_confidences(dists))
    if result:
        return syms, dists

    # Strategy 2: spend the erasure budget per block, ranked by margin.
    #
    # Order matters. A block satisfies 2t + e <= 3, so one erasure still
    # leaves one correctable error while three leave none — climb, never
    # start at the top. Measured on a mediocre photograph (worst block 2),
    # one margin-ranked erasure per block turns a failure into the right
    # seed, where every distance-ranked variant fails. Three per block is
    # deliberately absent: with t=0 it does not recover the hard cases and
    # it invites a miscorrection, which is worse than a refusal.
    for n in (1, 2):
        era = erasures_per_block(dists, margins=margins, max_per_block=n)
        if not era:
            continue
        result = decode_fn(syms, erasures=era)
        if result:
            return syms, dists

    # Strategy 2b: the historical global thresholds, kept as a fallback for
    # damage the margin does not see (a whole region washed out, say).
    for threshold in [0.15, 0.10, 0.07]:
        era = erasures_from_confidences(dists, threshold=threshold)
        if len(era) > 21:
            continue  # too many erasures
        result = decode_fn(syms, erasures=era)
        if result:
            return syms, dists

    # Strategy 3: re-extract with slightly different ring radii for vertices
    # (wider ring catches more of the disk, narrower avoids edge contamination)
    for r_inner_mult, r_outer_mult in [(0.50, 0.85), (0.70, 0.95)]:
        alt_syms = list(syms)
        alt_dists = list(dists)
        r_v = size * VERTEX_RADIUS_FRAC
        r_inner = r_v * r_inner_mult
        r_outer = r_v * r_outer_mult
        for i, coord in enumerate(VERTICES):
            cx, cy = _project(coord, size)
            rgb = _sample_ring_color(arr, cx, cy, r_inner, r_outer)
            sym, d = classify_color(*rgb)
            alt_syms[i] = sym
            alt_dists[i] = d
        result = decode_fn(alt_syms)
        if result:
            return alt_syms, alt_dists

    # Strategy 4: re-extract vertices with larger position offsets
    # to compensate for homography misalignment on phone photos
    _Counter = None  # lazy import
    for offset in [4.0, 8.0]:
        alt_syms = list(syms)
        alt_dists = list(dists)
        r_v = size * VERTEX_RADIUS_FRAC
        r_inner = r_v * 0.55
        r_outer = r_v * 1.10
        for i, coord in enumerate(VERTICES):
            cx, cy = _project(coord, size)
            refined_cx, refined_cy = _refine_vertex_position(
                arr, cx, cy, r_v, r_v * 3.0, size)
            votes = []
            best_d = 999.0
            best_sym = 0
            for dx, dy in [(0,0), (offset,0), (-offset,0),
                           (0,offset), (0,-offset)]:
                rgb = _sample_ring_color(arr, refined_cx+dx, refined_cy+dy,
                                          r_inner, r_outer)
                sym, d = classify_color(*rgb)
                votes.append(sym)
                if d < best_d:
                    best_d = d
                    best_sym = sym
            if _Counter is None:
                from collections import Counter as _Counter
            alt_syms[i] = _Counter(votes).most_common(1)[0][0]
            alt_dists[i] = best_d
        result = decode_fn(alt_syms)
        if result:
            return alt_syms, alt_dists

    # All strategies failed; return the best we have
    return syms, dists


def sample_carriers(img: Image.Image
                   ) -> Tuple[List[Tuple[int, int, int]],
                              List[Tuple[int, int, int]]]:
    """Legacy helper: return RGB samples per carrier (no classification).

    Kept for debugging / instrumentation.
    """
    if img.mode != "RGB":
        img = img.convert("RGB")
    arr = np.asarray(img)
    size = img.size[0]
    r_v = size * VERTEX_RADIUS_FRAC
    r_inner = r_v * 0.62
    r_outer = r_v * 0.90

    vertex_colors: List[Tuple[int, int, int]] = []
    for coord in VERTICES:
        cx, cy = _project(coord, size)
        vertex_colors.append(_sample_ring_color(arr, cx, cy, r_inner, r_outer))

    edge_colors: List[Tuple[int, int, int]] = []
    for vi, vj in EDGES:
        p1 = _project(VERTICES[vi], size)
        p2 = _project(VERTICES[vj], size)
        # Single representative pixel near the v_i endpoint for legacy callers.
        t = 0.30
        bx = p1[0] + t * (p2[0] - p1[0])
        by = p1[1] + t * (p2[1] - p1[1])
        sx, sy = int(round(bx)), int(round(by))
        if 0 <= sx < arr.shape[1] and 0 <= sy < arr.shape[0]:
            r, g, b = arr[sy, sx, :3]
            edge_colors.append((int(r), int(g), int(b)))
        else:
            edge_colors.append((0, 0, 0))
    return vertex_colors, edge_colors


def erasures_from_confidences(distances: Sequence[float],
                              threshold: float = ERASURE_THRESHOLD_OKLAB
                              ) -> List[int]:
    """Return the list of carrier positions whose distance exceeds threshold."""
    return [i for i, d in enumerate(distances) if d > threshold]


def erasures_per_block(distances: Sequence[float], *,
                       margins: Optional[Sequence[float]] = None,
                       max_per_block: int = 1,
                       min_distance: float = 0.03,
                       max_margin: float = 0.06) -> List[int]:
    """Flag the least-confident carriers *within each interleaved RS block*.

    A global threshold ignores the shape of the budget. The code is RS(13,10)
    interleaved seven ways: each block tolerates three erasures on its own, and
    an erasure only helps the block it lands in. Ten doubtful carriers crowded
    into one block are ten wasted flags; one flag in each of seven blocks is
    seven repairs.

    ``max_per_block`` also decides how much error-correction survives, since a
    block satisfies ``2t + e <= 3``:

    ==================  ====================================
    erasures per block  errors still correctable in that block
    ==================  ====================================
    0                   1
    1                   1
    2                   0
    3                   0
    ==================  ====================================

    So ``max_per_block=1`` is the frugal choice — it repairs one carrier *and*
    keeps a correction in hand — while 3 only pays off when all three of a
    block's errors are among the flagged. Callers should climb that ladder
    rather than start at the top.

    Pass ``margins`` (from :func:`extract_canonical_full`) and carriers are
    ranked by *ascending margin* instead of descending distance, which is the
    ranking that works. Measured on a mediocre photograph: misread carriers
    have a median margin of 0.034 against 0.092 for correct ones, and rank
    second in their block; ranked by distance they land mid-pack, because a
    shadow pushes every carrier away from the palette at once and a difference
    cancels what a magnitude cannot.

    ``min_distance`` / ``max_margin`` keep confident carriers out: a pristine
    render classifies below 0.05 with wide margins, and flagging a symbol that
    was never in doubt spends budget for nothing.
    """
    from .reed_solomon import NUM_BLOCKS

    out: List[int] = []
    for block in range(NUM_BLOCKS):
        carriers = [i for i in range(len(distances)) if i % NUM_BLOCKS == block]
        if margins is not None:
            carriers.sort(key=lambda i: margins[i])
            out.extend(i for i in carriers[:max_per_block]
                       if margins[i] < max_margin)
        else:
            carriers.sort(key=lambda i: distances[i], reverse=True)
            out.extend(i for i in carriers[:max_per_block]
                       if distances[i] > min_distance)
    return sorted(out)


# ---------------------------------------------------------------------------
# Perspective rectification (for real photographs)
# ---------------------------------------------------------------------------

def _compute_homography(src: Sequence[Tuple[float, float]],
                        dst: Sequence[Tuple[float, float]]) -> np.ndarray:
    """Compute the 3x3 homography H such that dst[i] = H * src[i] (homogeneous).

    Uses normalized DLT + SVD. Requires len(src) == len(dst) >= 4.
    """
    if len(src) != len(dst):
        raise ValueError("src and dst must have equal length")
    if len(src) < 4:
        raise ValueError("need at least 4 corresponding points")

    A = []
    for (x, y), (X, Y) in zip(src, dst):
        A.append([-x, -y, -1, 0, 0, 0, X * x, X * y, X])
        A.append([0, 0, 0, -x, -y, -1, Y * x, Y * y, Y])
    A = np.asarray(A, dtype=np.float64)
    _U, _S, Vt = np.linalg.svd(A)
    h = Vt[-1]
    H = h.reshape(3, 3)
    H = H / H[2, 2]
    return H


def rectify(img: Image.Image,
            src_points: Sequence[Tuple[float, float]],
            dst_size: int = DEFAULT_CANVAS) -> Image.Image:
    """Warp a photograph so the cube fills a canonical square frame.

    src_points: list of 6 pixel coordinates in the photo, corresponding to
                the 6 outer-hexagon vertices in canonical index order
                (i.e. matching VERTICES[7..12]).

    dst_size:   side length of the canonical output (square, RGB).
    """
    if img.mode != "RGB":
        img = img.convert("RGB")
    if len(src_points) != 6:
        raise ValueError("src_points must contain the 6 outer hexagon vertices "
                         "in canonical order (indices 7..12)")

    # Destination = pixel positions of canonical outer-hexagon vertices.
    dst_points = [_project(VERTICES[i], dst_size) for i in range(7, 13)]

    H = _compute_homography(src_points, dst_points)
    # PIL.Image.transform expects the INVERSE map (dst -> src).
    H_inv = np.linalg.inv(H)
    H_inv = H_inv / H_inv[2, 2]
    coeffs = (
        H_inv[0, 0], H_inv[0, 1], H_inv[0, 2],
        H_inv[1, 0], H_inv[1, 1], H_inv[1, 2],
        H_inv[2, 0], H_inv[2, 1],
    )
    return img.transform(
        (dst_size, dst_size),
        Image.Transform.PERSPECTIVE,
        coeffs,
        resample=Image.Resampling.BICUBIC,
        fillcolor=(255, 255, 255),
    )


def extract_from_photo(img: Image.Image,
                       src_points: Sequence[Tuple[float, float]],
                       dst_size: int = DEFAULT_CANVAS
                       ) -> Tuple[List[int], List[float], Image.Image]:
    """Full chain: photo + 6 fiducial points -> (symbols, confidences, rectified).

    The rectified image is returned for visual debugging.
    """
    rect = rectify(img, src_points, dst_size=dst_size)
    syms, dists = extract_canonical(rect)
    return syms, dists, rect
