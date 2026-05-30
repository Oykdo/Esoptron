"""Protocol G — Identity Reclaim.

Re-derive the *exact* :class:`EnrollmentRecord` originally issued to a
now-lost or migrating device, given:

  1. the PUBLIC Metatron card that anchored the original enrollment
     (91 F_13 symbols), and
  2. a backup that yields the original ``device_entropy``:

       * Path P — a 24-word BIP-39 recovery phrase, or
       * Path S — a quorum of Esoptron recovery shards (k-of-n).

The procedure produces:

  * a re-derived :class:`EnrollmentRecord` bit-for-bit identical to the
    one originally created by Protocol D, and
  * a self-contained :class:`ReclaimClaim` proving possession of
    ``device_secret`` in the current reclaim context.

A verifier holding ``device_secret`` (or its hash escrowed at
enrollment time) can confirm the claim, gating Eidolon-side
acceptance.

Normative spec: ``docs/specs/EPX-G_reclaim.md``.

This module is **Esoptron-only**: it does not touch Eidolon Phases
1..6, the ``spinor_hash`` derivation, or the ``machine_lock`` policy.
Eidolon integration is layered on top by trusting a successful
``verify_reclaim`` decision against an ``enrollment_fp`` it has on
file.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple, Union

from .enroll import EnrollmentRecord, enroll_from_card
from .genesis import recovery_phrase_to_entropy

# ---------------------------------------------------------------------------
# Protocol constants — frozen at v1 per EPX-G spec
# ---------------------------------------------------------------------------

RECLAIM_CLAIM_VERSION = 1

#: Default time-to-live for a fresh claim, in seconds. Override via
#: ``ESOPTRON_RECLAIM_TTL_SECONDS`` at runtime if needed.
DEFAULT_RECLAIM_TTL_SECONDS = 600

RECLAIM_DOMAIN_ID = b"epx-g.reclaim_id.v1"
RECLAIM_DOMAIN_TAG = b"epx-g.claim_tag.v1\n"
RECLAIM_DOMAIN_NO_TARGET = b"epx-g.no-target-context.v1"

NONCE_BYTES = 32
FP_BYTES = 32
CONTEXT_BYTES = 32
TAG_BYTES = 32
TIMESTAMP_BYTES = 8           # uint64 big-endian
CLAIM_BINARY_SIZE = (
    1                           # version
    + FP_BYTES                  # enrollment_fp
    + FP_BYTES                  # vault_fp
    + CONTEXT_BYTES             # target_context
    + NONCE_BYTES               # nonce
    + TIMESTAMP_BYTES           # timestamp
    + FP_BYTES                  # claim_id
    + TAG_BYTES                 # claim_tag
)  # = 201

#: Pre-computed default "no target context" value: SHA3-256 of the domain tag.
NO_TARGET_CONTEXT: bytes = hashlib.sha3_256(RECLAIM_DOMAIN_NO_TARGET).digest()

#: Path labels (documentary; not authenticated).
PATH_PHRASE = "phrase"
PATH_SHARDS = "shards"
PATH_OTHER = "other"
_VALID_PATHS = frozenset({PATH_PHRASE, PATH_SHARDS, PATH_OTHER})


def _ttl_seconds() -> int:
    raw = os.environ.get("ESOPTRON_RECLAIM_TTL_SECONDS")
    if raw is None:
        return DEFAULT_RECLAIM_TTL_SECONDS
    try:
        v = int(raw)
        if v <= 0:
            raise ValueError
    except ValueError:
        return DEFAULT_RECLAIM_TTL_SECONDS
    return v


# ---------------------------------------------------------------------------
# ReclaimClaim wire-format dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReclaimClaim:
    """Self-contained proof-of-reclaim, transportable + verifiable.

    All byte fields are exactly the lengths declared by the spec; the
    constructor enforces these so a ``ReclaimClaim`` is *always* a
    well-formed wire object.
    """
    version: int
    enrollment_fp: bytes
    vault_fp: bytes
    target_context: bytes
    nonce: bytes
    timestamp: int
    claim_id: bytes
    claim_tag: bytes
    path: str = PATH_PHRASE

    def __post_init__(self) -> None:
        if self.version != RECLAIM_CLAIM_VERSION:
            raise ValueError(
                f"unsupported ReclaimClaim version: {self.version} "
                f"(expected {RECLAIM_CLAIM_VERSION})"
            )
        for name, val, expected in (
            ("enrollment_fp", self.enrollment_fp, FP_BYTES),
            ("vault_fp", self.vault_fp, FP_BYTES),
            ("target_context", self.target_context, CONTEXT_BYTES),
            ("nonce", self.nonce, NONCE_BYTES),
            ("claim_id", self.claim_id, FP_BYTES),
            ("claim_tag", self.claim_tag, TAG_BYTES),
        ):
            if not isinstance(val, (bytes, bytearray)) or len(val) != expected:
                raise ValueError(
                    f"{name} must be exactly {expected} bytes (got {len(val) if val is not None else 'None'})"
                )
        if not isinstance(self.timestamp, int) or self.timestamp < 0:
            raise ValueError("timestamp must be a non-negative integer (Unix seconds)")
        if self.timestamp >= 1 << 64:
            raise ValueError("timestamp does not fit in uint64")
        if self.path not in _VALID_PATHS:
            raise ValueError(
                f"path must be one of {sorted(_VALID_PATHS)}; got {self.path!r}"
            )

    # ----- wire encodings --------------------------------------------------

    def _message_bytes(self) -> bytes:
        """The 167 message bytes covered by ``claim_tag`` (everything up to
        but excluding the tag itself, including version)."""
        return b"".join((
            bytes([self.version]),
            self.enrollment_fp,
            self.vault_fp,
            self.target_context,
            self.nonce,
            struct.pack(">Q", self.timestamp),
            self.claim_id,
        ))

    def to_bytes(self) -> bytes:
        """Canonical 199-byte binary encoding (spec §5.1)."""
        return self._message_bytes() + self.claim_tag

    def to_dict(self) -> dict:
        """JSON-safe dict (spec §5.2). ``path`` is documentary only."""
        return {
            "version": self.version,
            "type": "epx-g.reclaim_claim.v1",
            "enrollment_fp_hex": self.enrollment_fp.hex(),
            "vault_fp_hex": self.vault_fp.hex(),
            "target_context_hex": self.target_context.hex(),
            "nonce_hex": self.nonce.hex(),
            "timestamp": self.timestamp,
            "claim_id_hex": self.claim_id.hex(),
            "claim_tag_hex": self.claim_tag.hex(),
            "path": self.path,
        }

    # ----- wire decoders ---------------------------------------------------

    @classmethod
    def from_bytes(cls, raw: bytes, *, path: str = PATH_OTHER) -> "ReclaimClaim":
        if len(raw) != CLAIM_BINARY_SIZE:
            raise ValueError(
                f"ReclaimClaim binary must be exactly {CLAIM_BINARY_SIZE} bytes "
                f"(got {len(raw)})"
            )
        version = raw[0]
        off = 1
        enrollment_fp = raw[off:off + FP_BYTES]; off += FP_BYTES
        vault_fp = raw[off:off + FP_BYTES]; off += FP_BYTES
        target_context = raw[off:off + CONTEXT_BYTES]; off += CONTEXT_BYTES
        nonce = raw[off:off + NONCE_BYTES]; off += NONCE_BYTES
        (timestamp,) = struct.unpack(">Q", raw[off:off + TIMESTAMP_BYTES])
        off += TIMESTAMP_BYTES
        claim_id = raw[off:off + FP_BYTES]; off += FP_BYTES
        claim_tag = raw[off:off + TAG_BYTES]
        return cls(
            version=version,
            enrollment_fp=enrollment_fp,
            vault_fp=vault_fp,
            target_context=target_context,
            nonce=nonce,
            timestamp=int(timestamp),
            claim_id=claim_id,
            claim_tag=claim_tag,
            path=path,
        )

    @classmethod
    def from_dict(cls, d: dict) -> "ReclaimClaim":
        if d.get("type") not in (None, "epx-g.reclaim_claim.v1"):
            raise ValueError(f"unexpected type: {d.get('type')!r}")
        return cls(
            version=int(d["version"]),
            enrollment_fp=bytes.fromhex(d["enrollment_fp_hex"]),
            vault_fp=bytes.fromhex(d["vault_fp_hex"]),
            target_context=bytes.fromhex(d["target_context_hex"]),
            nonce=bytes.fromhex(d["nonce_hex"]),
            timestamp=int(d["timestamp"]),
            claim_id=bytes.fromhex(d["claim_id_hex"]),
            claim_tag=bytes.fromhex(d["claim_tag_hex"]),
            path=d.get("path", PATH_OTHER),
        )


# ---------------------------------------------------------------------------
# Internal derivation primitives
# ---------------------------------------------------------------------------

def _compute_claim_id(enrollment_fp: bytes,
                      target_context: bytes,
                      nonce: bytes,
                      timestamp: int) -> bytes:
    """Per-spec §3.3: claim_id = SHA3-256(domain ‖ ids ‖ nonce ‖ ts_be8)."""
    h = hashlib.sha3_256()
    h.update(RECLAIM_DOMAIN_ID)
    h.update(enrollment_fp)
    h.update(target_context)
    h.update(nonce)
    h.update(struct.pack(">Q", timestamp))
    return h.digest()


def _compute_claim_tag(device_secret: bytes, claim_id: bytes) -> bytes:
    """Per-spec §3.3: claim_tag = HMAC-SHA3-256(device_secret, domain ‖ claim_id)."""
    return hmac.new(
        device_secret,
        RECLAIM_DOMAIN_TAG + claim_id,
        "sha3_256",
    ).digest()


def _resolve_context(target_context: Optional[bytes]) -> bytes:
    if target_context is None:
        return NO_TARGET_CONTEXT
    if not isinstance(target_context, (bytes, bytearray)) or len(target_context) != CONTEXT_BYTES:
        raise ValueError(
            f"target_context must be exactly {CONTEXT_BYTES} bytes (or None)"
        )
    return bytes(target_context)


def _resolve_nonce(nonce: Optional[bytes]) -> bytes:
    if nonce is None:
        return secrets.token_bytes(NONCE_BYTES)
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be exactly {NONCE_BYTES} bytes (or None)")
    return bytes(nonce)


def _resolve_timestamp(timestamp: Optional[int]) -> int:
    if timestamp is None:
        return int(time.time())
    if not isinstance(timestamp, int) or timestamp < 0:
        raise ValueError("timestamp must be a non-negative integer (Unix seconds)")
    return int(timestamp)


# ---------------------------------------------------------------------------
# Claim issuance
# ---------------------------------------------------------------------------

def _issue_claim(
    enrollment: EnrollmentRecord,
    *,
    target_context: Optional[bytes],
    timestamp: Optional[int],
    nonce: Optional[bytes],
    path: str,
) -> ReclaimClaim:
    ctx = _resolve_context(target_context)
    n = _resolve_nonce(nonce)
    t = _resolve_timestamp(timestamp)
    cid = _compute_claim_id(enrollment.enrollment_fp, ctx, n, t)
    tag = _compute_claim_tag(enrollment.device_secret, cid)
    return ReclaimClaim(
        version=RECLAIM_CLAIM_VERSION,
        enrollment_fp=enrollment.enrollment_fp,
        vault_fp=enrollment.vault_fp,
        target_context=ctx,
        nonce=n,
        timestamp=t,
        claim_id=cid,
        claim_tag=tag,
        path=path,
    )


# ---------------------------------------------------------------------------
# Path P — BIP-39 phrase
# ---------------------------------------------------------------------------

def reclaim_from_phrase(
    card_symbols: Sequence[int],
    recovery_phrase: Sequence[str],
    *,
    target_context: Optional[bytes] = None,
    timestamp: Optional[int] = None,
    nonce: Optional[bytes] = None,
    language: str = "english",
) -> Tuple[EnrollmentRecord, ReclaimClaim]:
    """Reclaim an enrollment from a BIP-39 phrase (Path P).

    Parameters
    ----------
    card_symbols:
        91 F_13 symbols extracted from the original PUBLIC Metatron card.
    recovery_phrase:
        24-word BIP-39 phrase originally produced at Protocol D enrollment.
    target_context, timestamp, nonce:
        Optional reclaim-context parameters; see :class:`ReclaimClaim`.
        Defaults: ``target_context=NO_TARGET_CONTEXT``, ``timestamp=now()``,
        ``nonce=csprng(32)``.
    language:
        BIP-39 wordlist language (default ``"english"``).

    Returns
    -------
    (EnrollmentRecord, ReclaimClaim)
        The re-derived enrollment (bit-identical to the original) and the
        accompanying claim suitable for transmission to a verifier.
    """
    if len(card_symbols) != 91:
        raise ValueError("card_symbols must have length 91")
    words = list(recovery_phrase)
    device_entropy = recovery_phrase_to_entropy(words, language=language)
    enrollment = enroll_from_card(card_symbols, device_entropy=device_entropy)
    claim = _issue_claim(
        enrollment,
        target_context=target_context,
        timestamp=timestamp,
        nonce=nonce,
        path=PATH_PHRASE,
    )
    return enrollment, claim


# ---------------------------------------------------------------------------
# Path S — Shamir shard quorum
# ---------------------------------------------------------------------------

def reclaim_from_entropy(
    card_symbols: Sequence[int],
    device_entropy: bytes,
    *,
    target_context: Optional[bytes] = None,
    timestamp: Optional[int] = None,
    nonce: Optional[bytes] = None,
    path: str = PATH_OTHER,
) -> Tuple[EnrollmentRecord, ReclaimClaim]:
    """Reclaim with a pre-reconstructed ``device_entropy`` (low-level entry).

    Callers that perform their own backup recovery (e.g. via
    :func:`eopx.recovery.recover_entropy_flexible`) can hand the
    reconstructed 32-byte entropy directly to this function. For the
    canonical Path S flow that consumes a ``RecoveryPackage``, use
    :func:`reclaim_from_shards` instead.
    """
    if len(card_symbols) != 91:
        raise ValueError("card_symbols must have length 91")
    if not isinstance(device_entropy, (bytes, bytearray)) or len(device_entropy) != 32:
        raise ValueError("device_entropy must be exactly 32 bytes")
    enrollment = enroll_from_card(card_symbols, device_entropy=bytes(device_entropy))
    claim = _issue_claim(
        enrollment,
        target_context=target_context,
        timestamp=timestamp,
        nonce=nonce,
        path=path,
    )
    return enrollment, claim


def reclaim_from_shards(
    card_symbols: Sequence[int],
    package,
    creds,
    *,
    target_context: Optional[bytes] = None,
    timestamp: Optional[int] = None,
    nonce: Optional[bytes] = None,
) -> Tuple[EnrollmentRecord, ReclaimClaim]:
    """Reclaim an enrollment from a Shamir shard quorum (Path S).

    ``package`` is an :class:`eopx.recovery.RecoveryPackage` and
    ``creds`` is either a :class:`eopx.recovery.RecoveryCredentials`
    (2-of-3 default) or :class:`eopx.recovery.FlexibleCredentials`
    (k-of-n general case).

    Imports are deferred to keep ``eopx.recovery`` (with its Argon2id
    + ML-KEM dependencies) optional for callers that only need Path P.
    """
    from ..recovery import (
        FlexibleCredentials,
        RecoveryCredentials,
        recover_entropy,
        recover_entropy_flexible,
    )

    if isinstance(creds, FlexibleCredentials):
        device_entropy = recover_entropy_flexible(package, creds)
    elif isinstance(creds, RecoveryCredentials):
        device_entropy = recover_entropy(package, creds)
    else:
        raise TypeError(
            "creds must be RecoveryCredentials or FlexibleCredentials"
        )
    return reclaim_from_entropy(
        card_symbols, device_entropy,
        target_context=target_context,
        timestamp=timestamp,
        nonce=nonce,
        path=PATH_SHARDS,
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_reclaim(
    claim: ReclaimClaim,
    device_secret: bytes,
    *,
    now: Optional[int] = None,
    ttl: Optional[int] = None,
    enrollment_fp: Optional[bytes] = None,
    vault_fp: Optional[bytes] = None,
) -> bool:
    """Verify a :class:`ReclaimClaim` against a known ``device_secret``.

    Parameters
    ----------
    claim:
        The claim to verify.
    device_secret:
        The 32-byte ``device_secret`` of the original enrollment. Anyone
        holding this can verify the claim.
    now:
        Override the current Unix time (for tests / reproducible audits).
        Defaults to ``time.time()``.
    ttl:
        Override the TTL window in seconds. Defaults to
        ``RECLAIM_TTL_SECONDS`` (environment-overridable).
    enrollment_fp, vault_fp:
        If provided, the claim's matching fields MUST equal these values
        (and verification fails otherwise). This catches replay of a
        valid-but-unrelated claim by a malicious relay.

    Returns
    -------
    bool
        True iff the claim is fresh and the HMAC verifies in constant time.
    """
    if not isinstance(device_secret, (bytes, bytearray)) or len(device_secret) != 32:
        raise ValueError("device_secret must be exactly 32 bytes")

    if enrollment_fp is not None and not hmac.compare_digest(
            bytes(enrollment_fp), claim.enrollment_fp):
        return False
    if vault_fp is not None and not hmac.compare_digest(
            bytes(vault_fp), claim.vault_fp):
        return False

    # Freshness check.
    current = int(time.time()) if now is None else int(now)
    window = _ttl_seconds() if ttl is None else int(ttl)
    if window < 0:
        raise ValueError("ttl must be non-negative")
    if abs(current - claim.timestamp) > window:
        return False

    # Independently re-derive claim_id from the spec inputs; do not trust
    # the field in the claim (defence against mutation of claim_id alone).
    expected_id = _compute_claim_id(
        claim.enrollment_fp,
        claim.target_context,
        claim.nonce,
        claim.timestamp,
    )
    if not hmac.compare_digest(expected_id, claim.claim_id):
        return False

    expected_tag = _compute_claim_tag(bytes(device_secret), expected_id)
    return hmac.compare_digest(expected_tag, claim.claim_tag)


__all__ = [
    "RECLAIM_CLAIM_VERSION",
    "DEFAULT_RECLAIM_TTL_SECONDS",
    "RECLAIM_DOMAIN_ID",
    "RECLAIM_DOMAIN_TAG",
    "RECLAIM_DOMAIN_NO_TARGET",
    "NO_TARGET_CONTEXT",
    "CLAIM_BINARY_SIZE",
    "PATH_PHRASE",
    "PATH_SHARDS",
    "PATH_OTHER",
    "ReclaimClaim",
    "reclaim_from_phrase",
    "reclaim_from_shards",
    "reclaim_from_entropy",
    "verify_reclaim",
]
