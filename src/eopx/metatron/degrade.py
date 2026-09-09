"""A reference degradation model for the camera path, and how to score it.

The Metatron carrier is RS(13,10) interleaved seven ways: per block the code
corrects **one** unknown error, or three erasures. What decides a scan is
therefore not the global symbol error rate but the **worst block** — 7 errors
spread one per block decode, while 3 errors landing in one block do not.
Every measurement here reports that number.

The degradations are deterministic given their parameters (the noise axis
takes an explicit seed), so an envelope measured today can be compared against
the same envelope measured after a change. They are a *model* of a photograph,
not a photograph: real capture also brings ArUco detection error, rolling
shutter, motion blur and print gamut. Treat the numbers as an upper bound on
what a phone will achieve, never as a field result.

Pillow + numpy only — no OpenCV — so the harness runs anywhere the package
installs.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import numpy as np
from PIL import Image, ImageFilter

from .detect import _compute_homography, extract_from_photo
from .graph import VERTICES
from .reed_solomon import NUM_BLOCKS
from .render import _project

Point = Tuple[float, float]

#: The six outer-hexagon vertices used as fiducials by the rectifier.
FIDUCIAL_VERTICES = tuple(range(7, 13))

#: Unit displacement of the six fiducials, scaled by the ``strength`` argument
#: of :func:`perspective`. ``strength=1`` is a roughly steady handheld shot
#: (~1-2% of the figure radius on a 1024 px canvas).
PERSPECTIVE_UNIT: Tuple[Point, ...] = (
    (6.0, -4.0), (-5.0, 3.0), (8.0, 6.0), (-2.0, 8.0), (4.0, -7.0), (-6.0, -2.0),
)

#: Background the perspective transform reveals outside the source image —
#: the render's own backdrop, so the frame edge does not read as a symbol.
FILL_RGB = (16, 16, 22)


def canonical_fiducials(canvas: int) -> List[Point]:
    """Where the six fiducials sit on an undistorted render of ``canvas`` px."""
    return [_project(VERTICES[i], canvas) for i in FIDUCIAL_VERTICES]


# ---------------------------------------------------------------------------
# Degradation axes
# ---------------------------------------------------------------------------

def perspective(img: Image.Image, strength: float, *,
                canvas: Optional[int] = None
                ) -> Tuple[Image.Image, List[Point]]:
    """Tilt the card. Returns the image *and* where its fiducials moved to.

    ``strength`` scales :data:`PERSPECTIVE_UNIT`; the rectifier is then given
    the displaced points, so this measures the symbol pipeline rather than
    fiducial *detection* (which is a separate error source, not modelled here).
    """
    canvas = canvas or img.size[0]
    src = canonical_fiducials(canvas)
    if strength == 0:
        return img, src
    dst = [(x + dx * strength, y + dy * strength)
           for (x, y), (dx, dy) in zip(src, PERSPECTIVE_UNIT)]
    h = _compute_homography(src, dst)
    h_inv = np.linalg.inv(h)
    h_inv = h_inv / h_inv[2, 2]
    out = img.transform(
        (canvas, canvas), Image.Transform.PERSPECTIVE,
        tuple(h_inv.flatten()[:8]),
        resample=Image.Resampling.BICUBIC, fillcolor=FILL_RGB,
    )
    return out, dst


def blur(img: Image.Image, radius: float) -> Image.Image:
    """Defocus / camera shake, as a Gaussian of ``radius`` pixels."""
    return img if radius <= 0 else img.filter(ImageFilter.GaussianBlur(radius))


def jpeg(img: Image.Image, quality: int) -> Image.Image:
    """A round trip through JPEG — what every phone hands the app."""
    buf = io.BytesIO()
    img.convert("RGB").save(buf, format="JPEG", quality=int(quality))
    buf.seek(0)
    return Image.open(buf).convert("RGB")


def illumination(img: Image.Image, strength: float, *,
                 angle_deg: float = 30.0) -> Image.Image:
    """A linear brightness gradient: a lamp on one side, shadow on the other.

    ``strength`` is the peak multiplicative deviation (0.4 spans x0.6 to x1.4).
    """
    if strength <= 0:
        return img
    arr = np.asarray(img.convert("RGB"), dtype=np.float32)
    h, w = arr.shape[:2]
    yy, xx = np.mgrid[0:h, 0:w]
    theta = np.deg2rad(angle_deg)
    ramp = (xx * np.cos(theta) + yy * np.sin(theta))
    # np.ptp(x), not x.ptp(): the method was removed in numpy 2.
    ramp = (ramp - ramp.min()) / max(float(np.ptp(ramp)), 1e-9)   # 0..1
    gain = (1.0 - strength) + 2.0 * strength * ramp          # 1-s .. 1+s
    out = np.clip(arr * gain[..., None], 0, 255).astype(np.uint8)
    return Image.fromarray(out, "RGB")


def chroma_noise(img: Image.Image, sigma: float, *, seed: int = 0
                 ) -> Image.Image:
    """Sensor noise on the colour channels — the axis the palette feels most."""
    if sigma <= 0:
        return img
    arr = np.asarray(img.convert("RGB"), dtype=np.float32)
    rng = np.random.default_rng(seed)
    out = np.clip(arr + rng.normal(0.0, sigma, arr.shape), 0, 255)
    return Image.fromarray(out.astype(np.uint8), "RGB")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class Score:
    """What a degraded image did to the 91 carriers."""

    errors: int                 #: symbols read differently from the codeword
    worst_block: int            #: max errors within one interleaved block
    per_block: List[int]        #: errors per block, in interleave order
    distances: List[float]      #: per-carrier Oklab classification distance
    symbols: List[int]          #: what the detector actually read

    @property
    def within_error_budget(self) -> bool:
        """True when pure error correction (t=1 per block) suffices."""
        return self.worst_block <= 1


def block_of(carrier: int) -> int:
    """Which interleaved RS block a carrier position belongs to."""
    return carrier % NUM_BLOCKS


def score(img: Image.Image, src_points: Sequence[Point],
          codeword: Sequence[int], *, canvas: int = 1024) -> Score:
    """Run the detection chain on a degraded image and score it."""
    syms, dists, _ = extract_from_photo(img, src_points, dst_size=canvas)
    bad = [i for i, (a, b) in enumerate(zip(syms, codeword)) if a != b]
    per_block = [sum(1 for i in bad if block_of(i) == b)
                 for b in range(NUM_BLOCKS)]
    return Score(errors=len(bad), worst_block=max(per_block) if per_block else 0,
                 per_block=per_block, distances=list(dists), symbols=list(syms))


def envelope(measure, levels: Sequence[float], *,
             limit: int = 1) -> Optional[float]:
    """The largest level in ``levels`` whose worst block stays within ``limit``.

    ``measure(level) -> Score``. ``levels`` must be ordered from gentlest to
    harshest *for the axis at hand* (JPEG quality descends, blur ascends).
    Returns ``None`` when even the gentlest level already exceeds the limit —
    a result worth reading as "this axis is broken", not as "zero".
    """
    passed: Optional[float] = None
    for level in levels:
        if measure(level).worst_block <= limit:
            passed = level
        else:
            break
    return passed


__all__ = [
    "FIDUCIAL_VERTICES", "PERSPECTIVE_UNIT", "FILL_RGB",
    "canonical_fiducials", "perspective", "blur", "jpeg", "illumination",
    "chroma_noise", "Score", "block_of", "score", "envelope",
]
