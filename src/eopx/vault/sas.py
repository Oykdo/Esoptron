"""Protocol C: Strong Authentication Sheet (SAS).

A challenge/response 2FA protocol where unlocking requires BOTH a
publicly printed Metatron card AND a device that still holds the
matching spinor_hash in trusted storage (or can re-derive it via
Eidolon Phases 1..6).

Threat model
------------
- Card alone is useless (it is public; anyone could photograph it).
- Device alone is useless (it refuses to release the session key
  without the live card scan).
- Stolen card + stolen device require simultaneous physical possession.

Flow
----
1. Device generates a fresh 256-bit nonce N and shows / emits a SAS
   challenge (nonce, t_now, vault_id).
2. User scans the card (camera) -> symbols S.
3. Device computes:
       fp        = card_fingerprint(S)
       expected  = card_fingerprint(encode_public(spinor_hash_local))
       if fp != expected -> abort
4. Device derives session_key = HKDF(spinor_hash_local || S_bytes || N).
5. session_key is used to decrypt the vault for this open ONLY.

This module is transport-agnostic. A reference CLI is in
`scripts/open_vault_from_photo.py`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Optional, Sequence

from ..metatron import encode_public
from .verify_card import card_fingerprint

NONCE_BYTES = 32
SESSION_KEY_BYTES = 32
CHALLENGE_TTL_SECONDS = 120  # paper-scan must occur within 2 minutes

INFO_SESSION = b"esoptron.vault.sas.session.v1"


@dataclass(frozen=True)
class SASChallenge:
    """A device-issued challenge bound to a vault and a time window."""
    vault_id: bytes        # 32-byte stable vault identifier
    nonce: bytes           # 32-byte freshness
    issued_at: float       # unix time
    ttl_seconds: int = CHALLENGE_TTL_SECONDS

    def is_alive(self, now: Optional[float] = None) -> bool:
        t = time.time() if now is None else now
        return 0 <= (t - self.issued_at) <= self.ttl_seconds


@dataclass(frozen=True)
class SASResponse:
    """A response produced after a successful card scan."""
    challenge: SASChallenge
    card_fp: bytes         # 32-byte fingerprint of scanned card
    tag: bytes             # 32-byte HMAC binding card+challenge+spinor


def new_challenge(vault_id: bytes,
                  nonce: Optional[bytes] = None,
                  issued_at: Optional[float] = None
                  ) -> SASChallenge:
    """Create a fresh SAS challenge for a given vault."""
    if len(vault_id) != 32:
        raise ValueError("vault_id must be 32 bytes")
    n = nonce if nonce is not None else os.urandom(NONCE_BYTES)
    if len(n) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes")
    t = issued_at if issued_at is not None else time.time()
    return SASChallenge(vault_id=vault_id, nonce=n, issued_at=float(t))


def _bind(spinor_hash_local: bytes,
          symbols: Sequence[int],
          challenge: SASChallenge,
          info: bytes) -> bytes:
    """HMAC-SHA3-256 binding of (spinor, symbols, vault_id, nonce, info)."""
    if len(symbols) != 91:
        raise ValueError("symbols must have length 91")
    msg = b"".join([
        b"esoptron.vault.sas.v1\n",
        challenge.vault_id,
        challenge.nonce,
        bytes(int(s) % 13 for s in symbols),
        info,
    ])
    return hmac.new(spinor_hash_local, msg, "sha3_256").digest()


def respond(symbols: Sequence[int],
            spinor_hash_local: bytes,
            challenge: SASChallenge) -> SASResponse:
    """User-side: produce a SAS response from a freshly scanned card.

    Raises ValueError if the card does not match the locally-known vault
    (so a wrong card never leaves the device's verifier).
    """
    expected = encode_public(spinor_hash_local)
    fp_scanned = card_fingerprint(symbols)
    fp_expected = card_fingerprint(expected)
    if not hmac.compare_digest(fp_scanned, fp_expected):
        raise ValueError("scanned card does not match the vault's spinor_hash")
    tag = _bind(spinor_hash_local, symbols, challenge, info=INFO_SESSION)
    return SASResponse(challenge=challenge, card_fp=fp_scanned, tag=tag)


def verify_response(response: SASResponse,
                    spinor_hash_local: bytes,
                    symbols: Sequence[int],
                    now: Optional[float] = None
                    ) -> Optional[bytes]:
    """Verifier-side: confirm response is fresh + correct, then return the
    derived session key. Returns None on any failure.
    """
    if not response.challenge.is_alive(now):
        return None
    expected = encode_public(spinor_hash_local)
    fp_expected = card_fingerprint(expected)
    if not hmac.compare_digest(response.card_fp, fp_expected):
        return None
    expected_tag = _bind(spinor_hash_local, symbols, response.challenge,
                          info=INFO_SESSION)
    if not hmac.compare_digest(response.tag, expected_tag):
        return None
    # Session key = a separate HKDF-style derivation so the tag itself
    # never leaks key material.
    h = hashlib.sha3_512()
    h.update(b"esoptron.vault.sas.session_key.v1\n")
    h.update(spinor_hash_local)
    h.update(response.challenge.vault_id)
    h.update(response.challenge.nonce)
    h.update(response.card_fp)
    return h.digest()[:SESSION_KEY_BYTES]
