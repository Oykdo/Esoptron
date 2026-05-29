"""Public render path: spinor_hash -> 91 F_13 symbols.

Whitepaper I §4.1.

Pipeline:
    spinor_hash (bytes, typically 64 bytes from Eidolon Phase 6)
      -> HKDF-SHA3-512(spinor_hash, info="esoptron.render.metatron.v1")
         producing >= 91 * log2(13) ~= 337 bits of key material
      -> 91 F_13 symbols
"""

from __future__ import annotations

from typing import List

from . import field as F
from . import reed_solomon as RS

INFO_STRING = b"esoptron.render.metatron.v1"
SALT = b""  # not secret, public domain separator (HKDF salt is optional)

# We need enough HKDF output to derive 91 base-13 symbols. log2(13^91) ~= 337
# bits = 42.2 bytes. We pull 64 bytes (one SHA3-512 block) for comfort.
HKDF_BYTES = 64


def encode_public(spinor_hash: bytes) -> List[int]:
    """Derive 91 F_13 symbols deterministically from a vault's spinor_hash.

    Under the PRF assumption of HKDF-SHA3-512, the resulting symbols are
    computationally indistinguishable from uniform on F_13^91.
    """
    if not spinor_hash:
        raise ValueError("spinor_hash must be non-empty")

    okm = F.hkdf_sha3_512(
        ikm=spinor_hash,
        salt=SALT,
        info=INFO_STRING,
        length=HKDF_BYTES,
    )

    # Convert okm bytes (big-endian integer) into 91 base-13 digits.
    n = int.from_bytes(okm, "big")
    digits: List[int] = []
    for _ in range(RS.TOTAL_N):
        digits.append(n % F.Q)
        n //= F.Q
    # We do not require n == 0 here: HKDF gave us more entropy than 91 base-13
    # digits can hold, so any leftover high-order bits are simply discarded.
    return list(reversed(digits))
