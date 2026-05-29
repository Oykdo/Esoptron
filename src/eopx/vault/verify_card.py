"""Protocol B: verify that a printed PUBLIC card matches a known vault.

The card encodes a one-way HKDF expansion of the vault's spinor_hash.
Whitepaper III, Theorem 2: distinct spinor_hashes yield indistinguishable
distributions on F_13^91, but EQUAL spinors must yield IDENTICAL symbol
vectors. Verification is therefore a constant-time equality check on the
91 symbols, after re-encoding the locally-known spinor_hash.

This protocol recovers NO secret. It is purely a "this paper belongs to
this vault" attestation.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Sequence

from ..metatron import encode_public


def card_fingerprint(symbols: Sequence[int]) -> bytes:
    """Stable 32-byte fingerprint of a scanned card.

    Used to index a card in a local registry without revealing the spinor
    that produced it. Domain-separated SHA3-256 over the 91 symbol bytes.

    Out-of-distribution inputs (symbols outside ``[0, 12]``) are rejected
    explicitly rather than silently mapped via ``% 13`` — this prevents
    decoder regressions or sign-conversion bugs from producing a stable
    fingerprint for malformed input that would diverge between the Python
    and TypeScript ports.
    """
    if len(symbols) != 91:
        raise ValueError("symbols must have length 91")
    coerced = bytearray(91)
    for i, s in enumerate(symbols):
        v = int(s)
        if not (0 <= v < 13):
            raise ValueError(
                f"symbol at index {i} out of range: {s!r} "
                "(must be 0 <= s < 13)"
            )
        coerced[i] = v
    h = hashlib.sha3_256()
    h.update(b"esoptron.metatron.card_fingerprint.v1\n")
    h.update(bytes(coerced))
    return h.digest()


def verify_card(symbols: Sequence[int], spinor_hash_local: bytes) -> bool:
    """Return True iff the scanned card was produced from spinor_hash_local.

    The check is constant-time at the symbol level (hmac.compare_digest on
    a domain-separated SHA3-256 of both vectors), so a timing attacker
    cannot learn which symbol mismatched.
    """
    if len(symbols) != 91:
        raise ValueError("symbols must have length 91")
    expected = encode_public(spinor_hash_local)
    fp_scanned = card_fingerprint(symbols)
    fp_expected = card_fingerprint(expected)
    return hmac.compare_digest(fp_scanned, fp_expected)
