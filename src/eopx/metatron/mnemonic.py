"""Private inscription (Metatron Mnemonic / Recovery Plate).

Whitepaper II §5 (encoding) and §6 (decoding).

Pipeline:
    seed (32 bytes)
      -> payload = version_byte ‖ seed                                 (33 bytes)
      -> 70 F_13 message symbols   (base-13 conversion)
      -> 91 F_13 codeword symbols  (RS interleaved x7)
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from . import field as F
from . import reed_solomon as RS

VERSION_BYTE = 0x01
SEED_BYTES = 32
PAYLOAD_BYTES = 1 + SEED_BYTES  # = 33

# 33 bytes = 264 bits ; smallest n such that 13^n >= 2^264 is n = 74
# (13^73 ~ 2.07e81 < 2^264 ~ 2.92e79? -- actually 2^264 ~= 2.92e79;
#  13^73 ~= 13^73, log10(13)*73 ~= 81.4, so 13^73 ~ 10^81.4 ~ 2.5e81 > 2.92e79.
#  Hence n = 73 already suffices. But we use 70 by relying on top-bit zero
#  in the version byte to keep the payload within 13^70.)
#
# However, 13^70 ~= 10^78 = 1e78 < 2.92e79 = 2^264. Pure base-13 of 33 bytes
# does NOT fit in 70 digits. We therefore pack only 256 bits + 3 bit version
# instead of a full byte version:
#     payload_bits = version(3) ‖ seed(256) = 259 bits
#     value < 2^259 ~= 9.27e77 < 13^70 ~= 1.0e78. OK.
#
# Implementation: we encode (version, seed) into a 259-bit integer, then
# express that integer in 70 base-13 digits.
VERSION_BITS = 3
SEED_BITS = SEED_BYTES * 8
TOTAL_BITS = VERSION_BITS + SEED_BITS  # 259
# Sanity: 13^70 must exceed 2^TOTAL_BITS.
assert 13 ** RS.TOTAL_K > (1 << TOTAL_BITS), \
    "70 base-13 digits cannot hold 259 bits"


def _pack_payload(seed: bytes, version: int = 1) -> int:
    if len(seed) != SEED_BYTES:
        raise ValueError(f"seed must be {SEED_BYTES} bytes")
    if not (0 <= version < (1 << VERSION_BITS)):
        raise ValueError(f"version must fit in {VERSION_BITS} bits")
    n = version
    for b in seed:
        n = (n << 8) | b
    return n


def _unpack_payload(n: int) -> tuple[int, bytes]:
    seed_int = n & ((1 << SEED_BITS) - 1)
    version = (n >> SEED_BITS) & ((1 << VERSION_BITS) - 1)
    seed = seed_int.to_bytes(SEED_BYTES, "big")
    return version, seed


def _int_to_base13(n: int, n_digits: int) -> List[int]:
    out: List[int] = []
    for _ in range(n_digits):
        out.append(n % F.Q)
        n //= F.Q
    if n != 0:
        raise ValueError("value does not fit in n_digits base-13")
    return list(reversed(out))


def _base13_to_int(digits: Sequence[int]) -> int:
    n = 0
    for d in digits:
        if not (0 <= d < F.Q):
            raise ValueError(f"digit {d} out of F_13")
        n = n * F.Q + d
    return n


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encode_private(seed: bytes, version: int = 1) -> List[int]:
    """Encode a 256-bit seed into 91 F_13 symbols (interleaved RS codeword).

    The returned vector lies in the linear code C ⊂ F_13^91 of dimension 70.
    """
    n = _pack_payload(seed, version)
    message_symbols = _int_to_base13(n, RS.TOTAL_K)
    return RS.encode(message_symbols)


def decode_private(codeword: Sequence[int],
                   erasures: Optional[Iterable[int]] = None
                   ) -> tuple[bytes, int]:
    """Decode a 91-symbol codeword back to (seed, version).

    erasures: optional iterable of carrier positions known to be unreliable
              (0..90). The RS layer tolerates up to 3 erasures per block.
    """
    message_symbols = RS.decode(codeword, erasures)
    n = _base13_to_int(message_symbols)
    version, seed = _unpack_payload(n)
    return seed, version
