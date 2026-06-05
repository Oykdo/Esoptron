"""Generate the Esoptron PWA app icons (maskable) into pwa/public/.

Draws the EPX-H hexagram seal (two interlocked triangles) in the brand accent
duotone over a dark radial field, with a soft glow. Maskable-safe: the mark
sits well inside the centre safe zone and the background fills the whole canvas.

    py scripts/gen_pwa_icons.py
"""

from __future__ import annotations

import math
import os

from PIL import Image, ImageDraw, ImageFilter

BG_CENTER = (20, 20, 42)      # #14142a
BG_EDGE = (10, 10, 20)        # #0a0a14
ACCENT = (155, 89, 182)       # #9b59b6 (purple, downward triangle)
ACCENT2 = (93, 173, 226)      # #5dade2 (blue, upward triangle)

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "pwa", "public")
SIZES = (192, 512)
SS = 4  # supersampling factor for crisp lines


def _triangle(cx: float, cy: float, r: float, up: bool) -> list:
    base = -90 if up else 90
    return [
        (cx + r * math.cos(math.radians(base + i * 120)),
         cy + r * math.sin(math.radians(base + i * 120)))
        for i in range(3)
    ]


def _radial_bg(size: int) -> Image.Image:
    img = Image.new("RGB", (size, size), BG_EDGE)
    px = img.load()
    assert px is not None
    cx = cy = size / 2
    maxd = size * 0.62
    for y in range(size):
        for x in range(size):
            d = min(1.0, math.hypot(x - cx, y - cy) / maxd)
            px[x, y] = tuple(
                round(BG_CENTER[k] + (BG_EDGE[k] - BG_CENTER[k]) * d)
                for k in range(3)
            )
    return img


def render(size: int) -> Image.Image:
    s = size * SS
    img = _radial_bg(size).resize((s, s), Image.Resampling.LANCZOS).convert("RGB")

    cx = cy = s / 2
    r = s * 0.30          # circumradius of each triangle (inside safe zone)
    w = max(2, round(s * 0.018))

    # Glow layer: both triangles, blurred.
    glow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.polygon(_triangle(cx, cy, r, True), outline=ACCENT2 + (255,), width=w * 2)
    gd.polygon(_triangle(cx, cy, r, False), outline=ACCENT + (255,), width=w * 2)
    glow = glow.filter(ImageFilter.GaussianBlur(s * 0.02))
    img = Image.alpha_composite(img.convert("RGBA"), glow)

    # Crisp seal on top.
    d = ImageDraw.Draw(img)
    d.polygon(_triangle(cx, cy, r, True), outline=ACCENT2 + (255,), width=w)
    d.polygon(_triangle(cx, cy, r, False), outline=ACCENT + (255,), width=w)
    # A breathing centre point (matches the PWA brand-dot).
    rd = s * 0.035
    d.ellipse([cx - rd, cy - rd, cx + rd, cy + rd],
              fill=(236, 237, 243, 255))

    return img.resize((size, size), Image.Resampling.LANCZOS).convert("RGB")


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    for size in SIZES:
        path = os.path.normpath(os.path.join(OUT_DIR, f"icon-{size}.png"))
        render(size).save(path, "PNG")
        print(f"wrote {path}")
    # Apple touch icon (iOS home screen) at 180.
    apple = os.path.normpath(os.path.join(OUT_DIR, "apple-touch-icon.png"))
    render(180).save(apple, "PNG")
    print(f"wrote {apple}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
