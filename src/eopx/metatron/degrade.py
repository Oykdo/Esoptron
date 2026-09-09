"""A reference degradation model for the camera path, and how to score it.

The Metatron carrier is RS(13,10) interleaved seven ways: per block the code
corrects **one** unknown error, or three erasures. What decides a scan is
therefore not the global symbol error rate but the **worst block** — 7 errors
spread one per block decode, while 3 errors landing in one block do not.
Every measurement here reports that number.

The degradations are deterministic given their parameters (the noise axis
takes an explicit seed), so an envelope measured today can be compared against
the same envelope measured after a change. They are a *model* of a photograph,
not a photograph: real capture also brings rolling shutter, motion blur and
print gamut. Treat the numbers as an upper bound on what a phone will achieve,
never as a field result.

Fiducial localisation error used to be excluded too — the image was degraded
and the six fiducials were then handed to the rectifier exactly. That omission
mattered more than the others, because locating the fiducials is precisely
what distinguishes one rectification strategy from another, and geometry is
the binding axis. :func:`fiducial_jitter` and :func:`fiducial_shift` measure
it, split the way a homography treats it.

Pillow + numpy only — no OpenCV — so the harness runs anywhere the package
installs.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import numpy as np
from PIL import Image, ImageFilter

from .detect import extract_from_photo
from .graph import VERTICES
from .reed_solomon import NUM_BLOCKS
from .render import _project

Point = Tuple[float, float]

#: The six outer-hexagon vertices used as fiducials by the rectifier.
FIDUCIAL_VERTICES = tuple(range(7, 13))

#: Background the perspective transform reveals outside the source image —
#: the render's own backdrop, so the frame edge does not read as a symbol.
FILL_RGB = (16, 16, 22)


def canonical_fiducials(canvas: int) -> List[Point]:
    """Where the six fiducials sit on an undistorted render of ``canvas`` px."""
    return [_project(VERTICES[i], canvas) for i in FIDUCIAL_VERTICES]


# ---------------------------------------------------------------------------
# Degradation axes
# ---------------------------------------------------------------------------

#: Camera-to-card distance for :func:`tilt`, in canvas widths. 3.0 is roughly
#: a phone 25 cm from an 8.5 cm card. Measured to be nearly inert: at 70 deg
#: the score is identical for distances 1.5 through 10, because the damage is
#: foreshortening (cos theta), not projective divergence.
DEFAULT_TILT_DISTANCE = 3.0


def tilt_homography(canvas: int, tilt_deg: float, *,
                    azimuth_deg: float = 0.0,
                    distance: float = DEFAULT_TILT_DISTANCE) -> np.ndarray:
    """The homography of a card plane rotated ``tilt_deg`` and reprojected.

    Exposed because the fiducial destinations must be *derived* from this
    matrix rather than fitted to it — that is the whole difference from the
    axis this replaces.

    Construction: rotate the card plane by ``tilt_deg`` about an in-plane axis
    at ``azimuth_deg`` (Rodrigues), then project through a pinhole at
    ``distance`` canvas widths with the focal length pinned to that distance,
    so ``tilt_deg == 0`` yields exactly the identity rather than a silent
    rescale. Only the first two columns of the rotation appear: the card is a
    plane, so its third column never enters.
    """
    if not 0.0 <= tilt_deg < 90.0:
        raise ValueError(f"tilt_deg must be in [0, 90), got {tilt_deg}")
    D = distance * canvas
    theta = np.radians(tilt_deg)
    phi = np.radians(azimuth_deg)

    # No card point may cross the camera plane, or the matrix flips silently.
    if D <= (canvas / (2 ** 0.5)) * np.sin(theta):
        raise ValueError(
            f"distance {distance} is too small for tilt {tilt_deg} deg: the "
            "card would cross the camera plane")

    axis = np.array([np.cos(phi), np.sin(phi), 0.0])
    K = np.array([[0.0, -axis[2], axis[1]],
                  [axis[2], 0.0, -axis[0]],
                  [-axis[1], axis[0], 0.0]])
    R = np.eye(3) + np.sin(theta) * K + (1.0 - np.cos(theta)) * (K @ K)

    H_c = np.array([
        [R[0, 0], R[0, 1], 0.0],
        [R[1, 0], R[1, 1], 0.0],
        [-R[2, 0] / D, -R[2, 1] / D, 1.0],
    ])

    c = canvas / 2.0
    to_origin = np.array([[1.0, 0.0, -c], [0.0, 1.0, -c], [0.0, 0.0, 1.0]])
    from_origin = np.array([[1.0, 0.0, c], [0.0, 1.0, c], [0.0, 0.0, 1.0]])
    H = from_origin @ H_c @ to_origin
    return H / H[2, 2]


def _apply(h: np.ndarray, point: Point) -> Point:
    v = h @ np.array([point[0], point[1], 1.0])
    return float(v[0] / v[2]), float(v[1] / v[2])


def tilt(img: Image.Image, tilt_deg: float, *,
         azimuth_deg: float = 0.0,
         distance: float = DEFAULT_TILT_DISTANCE,
         canvas: Optional[int] = None) -> Tuple[Image.Image, List[Point]]:
    """Tilt the card by ``tilt_deg``. Returns the image and its fiducials.

    Replaces a ``perspective(img, strength)`` axis whose ``strength`` had no
    interpretation. That axis displaced the six fiducials by six hand-chosen
    vectors, which no homography can realise, least-squares-fitted a matrix to
    them, warped the image by the fit, and then handed the caller the
    *unfitted* targets. The gap reached 68 px at the level pinned as the
    envelope: the axis was four parts fiducial error to one part geometry.

    Here the matrix comes first and the fiducials are read off it, so the
    residual is identically zero and the axis measures tilt alone. The scalar
    is an angle, which means an envelope can be stated as a capture condition
    — "the card may be tilted N degrees" — instead of an opaque unit.
    """
    canvas = canvas or img.size[0]
    src = canonical_fiducials(canvas)
    if tilt_deg == 0:
        return img, src

    h = tilt_homography(canvas, tilt_deg, azimuth_deg=azimuth_deg,
                        distance=distance)
    dst = [_apply(h, p) for p in src]

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
# Fiducial localisation — the term the rest of this module used to exclude
# ---------------------------------------------------------------------------
#
# Every axis above degrades the *image* and then hands the rectifier the six
# fiducial positions exactly. A real scanner does not get them: it estimates
# them, and is wrong by some amount. That excluded term is what separates the
# rectification strategies -- page-corner markers far from the cube against
# fiducials that travel with it -- so a bench that omits it cannot compare
# them, and reports an envelope no phone can reach.
#
# The two functions below split the error in the way the homography does,
# which is the whole point: a four-point homography absorbs a translation
# exactly, so only the *differential* part of a localisation error reaches the
# carriers. Measuring the two separately turns "how well must a scanner find
# the fiducials" into a number, instead of a worry.


def fiducial_shift(points: Sequence[Point], dx: float, dy: float) -> List[Point]:
    """Move every fiducial by the same vector — common-mode error.

    It is tempting to expect this to be free, on the grounds that a homography
    can translate. It is not: the *destination* is the fixed canonical frame,
    so a uniform error in the source correspondences slides the whole sampling
    grid across the photograph, and the carriers are read off-centre. Measured
    on a 1024 px canvas it survives to about 12 px and collapses by 16 —
    cheap, but not free.
    """
    return [(x + dx, y + dy) for x, y in points]


def fiducial_jitter(points: Sequence[Point], sigma: float, *,
                    seed: int = 0) -> List[Point]:
    """Perturb each fiducial independently — differential error, in pixels.

    Gaussian, isotropic, one draw per fiducial, deterministic in ``seed`` so
    an envelope is comparable across runs. The six points no longer describe
    one rigid figure, so the fitted warp is *sheared*, and the error it leaves
    grows with distance from the fiducials rather than staying put.

    This is roughly an order of magnitude more expensive than the common-mode
    case: on a 1024 px canvas, sigma 1 px already puts some draws out of
    budget, against 12 px of uniform slide. A scanner therefore has to place
    the six fiducials to about **one pixel of relative accuracy over a 410 px
    figure radius** — a quarter of a percent. That requirement, not the image
    quality, is what separates fiducials seen across a whole sheet from
    fiducials that travel with the cube.

    Single draws vary wildly, because one badly-placed fiducial dominates the
    fit. Sweep several seeds and read the distribution, never one number.
    """
    if sigma <= 0:
        return list(points)
    rng = np.random.default_rng(seed)
    return [(x + float(rng.normal(0.0, sigma)),
             y + float(rng.normal(0.0, sigma)))
            for x, y in points]


def fiducial_radius(canvas: int) -> float:
    """Distance from the figure centre to a fiducial, in pixels.

    Lets a jitter measured on one canvas be read on another: what matters to
    the homography is the error *relative to* the figure it spans, not its
    absolute size. Divide a sigma by this to get a scale-free number.
    """
    cx, cy = canvas / 2.0, canvas / 2.0
    pts = canonical_fiducials(canvas)
    return sum(((x - cx) ** 2 + (y - cy) ** 2) ** 0.5 for x, y in pts) / len(pts)


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
    "FIDUCIAL_VERTICES", "FILL_RGB", "DEFAULT_TILT_DISTANCE",
    "tilt", "tilt_homography",
    "fiducial_shift", "fiducial_jitter", "fiducial_radius",
    "canonical_fiducials", "blur", "jpeg", "illumination",
    "chroma_noise", "Score", "block_of", "score", "envelope",
]
