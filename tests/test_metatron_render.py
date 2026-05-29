"""Render layer: determinism and basic shape sanity."""

import io
import os

from PIL import Image

from eopx.metatron import render
from eopx.metatron import encode_public, encode_private


def test_render_dimensions():
    symbols = [s % 13 for s in range(91)]
    img = render(symbols, size=256)
    assert img.size == (256, 256)
    assert img.mode == "RGB"


def test_render_determinism_public():
    spinor = os.urandom(64)
    syms = encode_public(spinor)
    img1 = render(syms, size=256)
    img2 = render(syms, size=256)
    # Pixel-byte equality
    assert img1.tobytes() == img2.tobytes()


def test_render_determinism_private():
    seed = os.urandom(32)
    syms = encode_private(seed)
    img1 = render(syms, size=256)
    img2 = render(syms, size=256)
    assert img1.tobytes() == img2.tobytes()


def test_render_distinct_inputs_distinct_outputs():
    a = encode_public(b"vault-a" * 8)
    b = encode_public(b"vault-b" * 8)
    img_a = render(a, size=256).tobytes()
    img_b = render(b, size=256).tobytes()
    assert img_a != img_b


def test_render_png_bytes_round_trip():
    """Render symbols, save as PNG, load back, compare pixels."""
    syms = encode_private(os.urandom(32))
    img1 = render(syms, size=512)
    buf = io.BytesIO()
    img1.save(buf, format="PNG", optimize=False)
    buf.seek(0)
    img2 = Image.open(buf).convert("RGB")
    assert img2.tobytes() == img1.tobytes()
