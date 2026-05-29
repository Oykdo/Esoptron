"""Metatron prototype — K_13 visual cryptographic canvas.

Public API:
    encode_public(spinor_hash)  -> list[int]   (91 F_13 symbols)
    encode_private(seed)        -> list[int]   (91 F_13 symbols, in code C)
    decode_private(symbols)     -> bytes       (recovered seed)
    is_in_code(symbols)         -> bool        (Theorem 2 algebraic test)
    render(symbols, ...)        -> PIL.Image
"""

from .public import encode_public
from .mnemonic import encode_private, decode_private
from .reed_solomon import is_in_code
from .render import render
from .detect import (
    extract_canonical, extract_from_photo, rectify,
    erasures_from_confidences, extract_robust,
)

__all__ = [
    "encode_public",
    "encode_private",
    "decode_private",
    "is_in_code",
    "render",
    "extract_canonical",
    "extract_from_photo",
    "rectify",
    "erasures_from_confidences",
    "extract_robust",
]
