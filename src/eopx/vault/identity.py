"""What identifies a vault — one definition, and why it is this one.

``vault_fp`` is the **card fingerprint**: the domain-separated SHA3-256 over
the 91 F₁₃ symbols of the vault's public card
(:func:`~eopx.vault.verify_card.card_fingerprint`). EPX-G §143 already says so
— *"vault_fp : 32 B  # = card_fp at time of original enrollment"* — and
``vault/enroll``, ``vault/genesis`` and ``collection`` already follow it.

This module exists because two other derivations had grown up beside it and
nothing named the winner. For one and the same vault they disagreed::

    card_fingerprint(card)                        74ad6428…7123f910
    sha3_256("esoptron.vault_fp.v1|" ‖ seed)      29f96634…b3bd96a5
    sha3_256("epx-h.badge.vault_fp.v1" ‖ spinor)  bb212913…cd5b02f2

Three answers to "which vault is this" is the same as none. Anything keyed by
``vault_fp`` — the anchor's ``vault_anchors`` index, the EPX-H seal geometry,
and above all ``egg_token.founder_egg``, which draws a golden egg from it —
silently depended on which call site the caller had come through.

Why the card fingerprint wins
-----------------------------
It is the only one of the three a **scan** can produce. The product is
photographing a card and routing to a protocol; a vault identity that cannot
be derived from a photograph of that card is unusable in exactly the flows the
system exists for. The seed-derived variant is worse still: the seed is
secret, so a verifier can never recompute it — an identifier nobody but the
holder can check is not an identifier, it is a second secret.

The spinor variant is merely redundant. ``encode_public`` is deterministic, so
:func:`vault_fingerprint` recovers the same value from the spinor by going
through the card, which keeps one definition instead of two that happen to
agree today.

Not a secret, and not an authorisation
--------------------------------------
A ``vault_fp`` is public: anyone holding the card can compute it. It names a
vault, it never proves control of one. Possession is the anchor's business
(``transfer/binding``), and a signature is the only thing that establishes it.
"""

from __future__ import annotations

from typing import Sequence

from ..metatron import encode_public
from .verify_card import card_fingerprint

#: Byte length of every vault fingerprint.
VAULT_FP_BYTES = 32


def vault_fingerprint(spinor_hash: bytes) -> bytes:
    """The vault's fingerprint, from its ``spinor_hash``.

    ``spinor_hash`` is what the vault layer publishes for a vault (Eidolon's
    Phase-6 output is 64 bytes; 32 and 48 also occur). The card is re-encoded
    rather than hashed directly, so this and
    :func:`vault_fingerprint_from_card` cannot drift apart: they are the same
    function reached from two different starting points.
    """
    if not spinor_hash:
        raise ValueError("spinor_hash must be non-empty")
    return card_fingerprint(encode_public(spinor_hash))


def vault_fingerprint_from_card(symbols: Sequence[int]) -> bytes:
    """The vault's fingerprint, from the 91 symbols read off its card.

    This is the path a scanner takes, and the reason the definition is what it
    is: no secret, no registry lookup, no network — a photograph is enough.
    """
    return card_fingerprint(symbols)


def is_vault_fingerprint(value: bytes) -> bool:
    """Whether ``value`` has the shape of a vault fingerprint.

    A shape check, never an existence check: a well-formed fingerprint of a
    vault nobody ever enrolled passes this and means nothing.
    """
    return isinstance(value, (bytes, bytearray)) and len(value) == VAULT_FP_BYTES


def require_vault_fingerprint(value: bytes, name: str = "vault_fp") -> bytes:
    """Return ``value`` if it is a well-formed fingerprint, else raise.

    Used at the boundaries that consume one — the founder draw, the seal
    geometry — because a truncated or hex-string fingerprint that reaches a
    KDF produces a stable, plausible, wrong answer instead of an error.
    """
    if not is_vault_fingerprint(value):
        got = f"{len(value)} bytes" if isinstance(value, (bytes, bytearray)) \
            else type(value).__name__
        raise ValueError(f"{name} must be {VAULT_FP_BYTES} raw bytes, got {got}")
    return bytes(value)


__all__ = [
    "VAULT_FP_BYTES",
    "vault_fingerprint",
    "vault_fingerprint_from_card",
    "is_vault_fingerprint",
    "require_vault_fingerprint",
]
