"""Holographic Recovery — 2-of-3 Shamir-sharded device entropy.

A self-custody alternative to the BIP-39 mnemonic that combines:

* **Shamir GF(2^8)** to split the 32-byte ``device_entropy`` into 3
  shares with threshold 2 (any 2 of 3 recover the secret; 1 reveals
  nothing).
* **Per-share recipient binding**, each share encrypted under its own
  recipient mechanism so a single share file is useless without the
  matching credential:

  ============== ==========================================================
  ``kind``       Recipient mechanism
  ============== ==========================================================
  ``card_pin``   Argon2id over a user-chosen short PIN. Designed to be
                 printed onto a second Metatron card.
  ``kyber_pk``   ML-KEM-1024 KEM to a contact's public key. Encrypts the
                 share for an offline-friend or another Eidolon vault.
  ``passphrase`` Argon2id over a longer passphrase. Designed for a
                 self-hosted cloud / file backup with no service trust.
  ============== ==========================================================

Wire format is **frozen v1** — any future change must bump the
``schema_version`` field and ship a migration path.

Threat model
------------
* Lose any 1 share → vault still recoverable from the other 2.
* Compromise any 1 share → attacker learns NOTHING (Shamir property).
* Compromise any 2 shares → attacker still needs the corresponding
  credentials (PIN, Kyber sk, or passphrase) to decrypt those shares.
* Compromise all 3 shares AND credentials → attacker recovers the
  vault, equivalent to BIP-39 phrase compromise. The point of the
  scheme is that this requires *simultaneous* compromise of three
  independent channels, not a single piece of paper.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .format.keys import EopxKey, key_fingerprint
from .format.shamir import shamir_combine, shamir_split

SCHEMA_VERSION = 1
DEFAULT_THRESHOLD = 2
DEFAULT_TOTAL = 3
NONCE_LEN = 12
SALT_LEN = 16
AEAD_KEY_LEN = 32
AEAD_INFO_KYBER = b"esoptron.recovery.kyber.aead.v1"

# Argon2id parameter tiers. Memory is in KiB.
#
# Two profiles are shipped:
#
#   "workstation" (default)
#     Card PIN  : t=3, m=64 MiB   (≈ 1-2 s on a laptop)
#     Passphrase: t=4, m=128 MiB  (≈ 4-8 s on a laptop)
#
#   "mobile"
#     Card PIN  : t=3, m=32 MiB   (≈ 3-5 s on a mid-range Android)
#     Passphrase: t=3, m=64 MiB   (≈ 8-12 s on a mid-range Android)
#
# The tier is selected per-share via the ``kdf_profile`` field, defaulting
# to "workstation". The wire format records the actual parameters so a
# package created on a workstation can still be opened on mobile (the
# verifier just consumes the recorded params; it does not enforce a tier).
#
# To override the default for a whole session set
# ``ESOPTRON_ARGON2_PROFILE=mobile``.

ARGON2_PROFILES: dict[str, dict[str, dict[str, int]]] = {
    "workstation": {
        "card_pin":   {"time_cost": 3, "memory_cost": 64 * 1024,  "parallelism": 1},
        "passphrase": {"time_cost": 4, "memory_cost": 128 * 1024, "parallelism": 1},
    },
    "mobile": {
        "card_pin":   {"time_cost": 3, "memory_cost": 32 * 1024,  "parallelism": 1},
        "passphrase": {"time_cost": 3, "memory_cost": 64 * 1024,  "parallelism": 1},
    },
}


def _active_profile() -> str:
    import os as _os
    name = _os.environ.get("ESOPTRON_ARGON2_PROFILE", "workstation").lower()
    if name not in ARGON2_PROFILES:
        raise ValueError(
            f"unknown ESOPTRON_ARGON2_PROFILE={name!r}; "
            f"expected one of {sorted(ARGON2_PROFILES)}"
        )
    return name


# Back-compat exports kept for callers that imported the constants directly.
ARGON2_CARD_PARAMS = ARGON2_PROFILES["workstation"]["card_pin"]
ARGON2_CLOUD_PARAMS = ARGON2_PROFILES["workstation"]["passphrase"]


# ---------------------------------------------------------------------------
# Argon2id helper (mirror what the TS port will do via @noble/hashes argon2)
# ---------------------------------------------------------------------------

def _argon2id(password: bytes, salt: bytes,
               *, time_cost: int, memory_cost: int, parallelism: int,
               length: int = AEAD_KEY_LEN) -> bytes:
    """Argon2id KDF wrapper kept in one place for parity with the TS port."""
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw(
        secret=password, salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )


def _kdf_kyber(shared_secret: bytes, info: bytes = AEAD_INFO_KYBER,
                length: int = AEAD_KEY_LEN) -> bytes:
    """HKDF-SHA3-256 expansion of a Kyber shared secret.

    Delegates to the centralised ``metatron.field.hkdf_sha3_256``. The
    output is bytewise identical to the previous single-block roll-your-own
    implementation, which already matched RFC 5869 for ``length <= 32``.
    """
    from .metatron.field import hkdf_sha3_256
    return hkdf_sha3_256(
        ikm=shared_secret, salt=b"", info=info, length=length,
    )


def _argon2_params_for(kind: str, profile: str | None = None) -> dict[str, int]:
    """Return the Argon2id parameter dict for ``kind`` under ``profile``."""
    p = profile or _active_profile()
    if p not in ARGON2_PROFILES:
        raise ValueError(f"unknown Argon2 profile: {p!r}")
    params = ARGON2_PROFILES[p].get(kind)
    if params is None:
        raise ValueError(f"no Argon2 params for kind={kind!r}")
    return params


def _kdf_params_str(kind: str, profile: str | None = None) -> str:
    p = _argon2_params_for(kind, profile)
    return f"argon2id-m{p['memory_cost'] // 1024}-t{p['time_cost']}-p{p['parallelism']}"


def _parse_kdf_params(kdf: str, *, kind: str) -> dict[str, int]:
    """Parse a recorded ``argon2id-m{MiB}-t{N}-p{N}`` string back into kwargs.

    Defensive: if the string is malformed, fall back to the active profile
    for ``kind`` so old / unknown packages still attempt to open. The Argon2
    layer itself will fail loudly when the recorded parameters do not
    actually match the stored ciphertext, so the fallback cannot be used as
    an oracle.
    """
    try:
        prefix, rest = kdf.split("-", 1)
        if prefix != "argon2id":
            raise ValueError
        parts = rest.split("-")
        kw: dict[str, int] = {}
        for part in parts:
            tag = part[:1]
            val = int(part[1:])
            if tag == "m":
                kw["memory_cost"] = val * 1024
            elif tag == "t":
                kw["time_cost"] = val
            elif tag == "p":
                kw["parallelism"] = val
            else:
                raise ValueError
        for required in ("memory_cost", "time_cost", "parallelism"):
            if required not in kw:
                raise ValueError
        return kw
    except (ValueError, IndexError):
        return _argon2_params_for(kind)


# ---------------------------------------------------------------------------
# Encrypted share envelopes — one dataclass per kind
# ---------------------------------------------------------------------------

@dataclass
class ShareEnvelope:
    """Common bits shared by every recovery share envelope."""
    index: int
    kind: str  # "card_pin" | "kyber_pk" | "passphrase"
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "kind": self.kind,
            "nonce_hex": self.nonce.hex(),
            "ciphertext_hex": self.ciphertext.hex(),
        }


@dataclass
class CardPinShare(ShareEnvelope):
    salt: bytes = b""
    kdf: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out = super().to_dict()
        out.update({"salt_hex": self.salt.hex(), "kdf": self.kdf})
        return out


@dataclass
class KyberShare(ShareEnvelope):
    recipient_fp: bytes = b""
    kem_ciphertext: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        out = super().to_dict()
        out.update({
            "recipient_fp_hex": self.recipient_fp.hex(),
            "kem_ciphertext_hex": self.kem_ciphertext.hex(),
        })
        return out


@dataclass
class PassphraseShare(ShareEnvelope):
    salt: bytes = b""
    kdf: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out = super().to_dict()
        out.update({"salt_hex": self.salt.hex(), "kdf": self.kdf})
        return out


# ---------------------------------------------------------------------------
# Package container
# ---------------------------------------------------------------------------

@dataclass
class RecoveryPackage:
    """Full 2-of-3 recovery setup, ready to be persisted or transmitted."""
    group_id: str
    threshold: int
    total: int
    vault_fp_hex: str
    created_at: str
    shares: List[ShareEnvelope] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "group_id": self.group_id,
            "threshold": self.threshold,
            "total": self.total,
            "vault_fp_hex": self.vault_fp_hex,
            "created_at": self.created_at,
            "shares": [s.to_dict() for s in self.shares],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RecoveryPackage":
        if d.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema_version: {d.get('schema_version')}"
            )
        shares: List[ShareEnvelope] = []
        for s in d["shares"]:
            kind = s["kind"]
            common = dict(
                index=int(s["index"]),
                kind=kind,
                nonce=bytes.fromhex(s["nonce_hex"]),
                ciphertext=bytes.fromhex(s["ciphertext_hex"]),
            )
            if kind == "card_pin":
                shares.append(CardPinShare(
                    **common,
                    salt=bytes.fromhex(s["salt_hex"]),
                    kdf=s["kdf"],
                ))
            elif kind == "kyber_pk":
                shares.append(KyberShare(
                    **common,
                    recipient_fp=bytes.fromhex(s["recipient_fp_hex"]),
                    kem_ciphertext=bytes.fromhex(s["kem_ciphertext_hex"]),
                ))
            elif kind == "passphrase":
                shares.append(PassphraseShare(
                    **common,
                    salt=bytes.fromhex(s["salt_hex"]),
                    kdf=s["kdf"],
                ))
            else:
                raise ValueError(f"unknown share kind: {kind}")
        return cls(
            group_id=d["group_id"],
            threshold=int(d["threshold"]),
            total=int(d["total"]),
            vault_fp_hex=d["vault_fp_hex"],
            created_at=d["created_at"],
            shares=shares,
        )

    @classmethod
    def from_json(cls, s: str) -> "RecoveryPackage":
        return cls.from_dict(json.loads(s))


# ---------------------------------------------------------------------------
# AEAD helpers
# ---------------------------------------------------------------------------

def _aead_seal(key: bytes, nonce: bytes, plaintext: bytes,
                aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def _aead_open(key: bytes, nonce: bytes, ciphertext: bytes,
                aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def _aad_for_share(group_id: str, index: int, kind: str,
                    threshold: int, total: int) -> bytes:
    """AAD binds each share to its identity to prevent cross-group swaps."""
    return "|".join([
        "esoptron.recovery.v1",
        group_id, str(index), kind, str(threshold), str(total),
    ]).encode("utf-8")


# ---------------------------------------------------------------------------
# Per-kind seal / open
# ---------------------------------------------------------------------------

def _seal_card_pin(share_bytes: bytes, pin: str, *,
                    group_id: str, index: int, threshold: int, total: int,
                    profile: str | None = None,
                    ) -> CardPinShare:
    params = _argon2_params_for("card_pin", profile)
    salt = secrets.token_bytes(SALT_LEN)
    key = _argon2id(pin.encode("utf-8"), salt, **params)
    nonce = secrets.token_bytes(NONCE_LEN)
    aad = _aad_for_share(group_id, index, "card_pin", threshold, total)
    ct = _aead_seal(key, nonce, share_bytes, aad)
    return CardPinShare(
        index=index, kind="card_pin",
        nonce=nonce, ciphertext=ct,
        salt=salt, kdf=_kdf_params_str("card_pin", profile),
    )


def _open_card_pin(env: CardPinShare, pin: str, *,
                    group_id: str, threshold: int, total: int) -> bytes:
    params = _parse_kdf_params(env.kdf, kind="card_pin")
    key = _argon2id(pin.encode("utf-8"), env.salt, **params)
    aad = _aad_for_share(group_id, env.index, "card_pin", threshold, total)
    return _aead_open(key, env.nonce, env.ciphertext, aad)


def _seal_kyber(share_bytes: bytes, recipient_pk: bytes, *,
                 group_id: str, index: int, threshold: int, total: int,
                 ) -> KyberShare:
    from pqcrypto.kem import ml_kem_1024 as _kem
    kem_ct, ss = _kem.encrypt(recipient_pk)
    key = _kdf_kyber(ss)
    nonce = secrets.token_bytes(NONCE_LEN)
    aad = _aad_for_share(group_id, index, "kyber_pk", threshold, total)
    ct = _aead_seal(key, nonce, share_bytes, aad)
    return KyberShare(
        index=index, kind="kyber_pk",
        nonce=nonce, ciphertext=ct,
        recipient_fp=key_fingerprint(recipient_pk),
        kem_ciphertext=kem_ct,
    )


def _open_kyber(env: KyberShare, recipient_sk: bytes, *,
                 group_id: str, threshold: int, total: int) -> bytes:
    from pqcrypto.kem import ml_kem_1024 as _kem
    ss = _kem.decrypt(recipient_sk, env.kem_ciphertext)
    key = _kdf_kyber(ss)
    aad = _aad_for_share(group_id, env.index, "kyber_pk", threshold, total)
    return _aead_open(key, env.nonce, env.ciphertext, aad)


def _seal_passphrase(share_bytes: bytes, passphrase: str, *,
                       group_id: str, index: int, threshold: int, total: int,
                       profile: str | None = None,
                       ) -> PassphraseShare:
    params = _argon2_params_for("passphrase", profile)
    salt = secrets.token_bytes(SALT_LEN)
    key = _argon2id(passphrase.encode("utf-8"), salt, **params)
    nonce = secrets.token_bytes(NONCE_LEN)
    aad = _aad_for_share(group_id, index, "passphrase", threshold, total)
    ct = _aead_seal(key, nonce, share_bytes, aad)
    return PassphraseShare(
        index=index, kind="passphrase",
        nonce=nonce, ciphertext=ct,
        salt=salt, kdf=_kdf_params_str("passphrase", profile),
    )


def _open_passphrase(env: PassphraseShare, passphrase: str, *,
                      group_id: str, threshold: int, total: int) -> bytes:
    params = _parse_kdf_params(env.kdf, kind="passphrase")
    key = _argon2id(passphrase.encode("utf-8"), env.salt, **params)
    aad = _aad_for_share(group_id, env.index, "passphrase", threshold, total)
    return _aead_open(key, env.nonce, env.ciphertext, aad)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_recovery(device_entropy: bytes,
                    *,
                    card_pin: str,
                    contact_kyber_pk: Optional[bytes] = None,
                    cloud_passphrase: Optional[str] = None,
                    vault_fp_hex: str,
                    group_id: Optional[str] = None,
                    threshold: int = DEFAULT_THRESHOLD,
                    total: int = DEFAULT_TOTAL,
                    ) -> RecoveryPackage:
    """Split ``device_entropy`` into 3 shares and produce sealed envelopes.

    Parameters
    ----------
    device_entropy:
        The 32-byte secret to protect (e.g. the BIP-39 entropy of an
        existing Esoptron enrollment).
    card_pin:
        PIN that protects share #1 (typically 6 digits — short, easy to
        remember; the Argon2id KDF compensates for the low-entropy).
    contact_kyber_pk:
        ML-KEM-1024 public key of a recovery contact, OR ``None`` to
        protect share #2 with a passphrase too (passed as
        ``cloud_passphrase``).
    cloud_passphrase:
        Passphrase for share #3 (cloud / file backup). Optional; if
        ``None`` the package only carries shares 1 and 2 — which is
        enough as long as both are reachable, but reduces resilience.
    vault_fp_hex:
        Card fingerprint of the source vault, recorded in the package.
    group_id:
        32 hex chars linking all 3 shares; auto-generated if absent.
    threshold / total:
        Defaults to 2-of-3.

    Returns
    -------
    RecoveryPackage
        Serialisable container holding the 3 sealed share envelopes.
    """
    if len(device_entropy) < 1:
        raise ValueError("device_entropy must be non-empty")
    if total != 3 or threshold != 2:
        # For arbitrary k-of-n, use setup_recovery_flexible() instead
        raise NotImplementedError(
            "setup_recovery() supports 2-of-3 only; for arbitrary k-of-n "
            "use setup_recovery_flexible()"
        )
    if not card_pin or len(card_pin) < 4:
        raise ValueError("card_pin must be at least 4 characters")
    if contact_kyber_pk is None and cloud_passphrase is None:
        raise ValueError(
            "at least one of contact_kyber_pk or cloud_passphrase must "
            "be provided (otherwise only the card share could be used "
            "for recovery and the 2-of-3 threshold cannot be met)"
        )

    group_id = group_id or uuid.uuid4().hex
    created_at = _dt.datetime.now(_dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    shares = shamir_split(device_entropy, k=threshold, n=total)
    # shares[i] is (index, share_bytes); index 1..3
    assert len(shares) == 3

    share1 = _seal_card_pin(
        shares[0][1], card_pin,
        group_id=group_id, index=1, threshold=threshold, total=total,
    )

    if contact_kyber_pk is not None:
        share2: ShareEnvelope = _seal_kyber(
            shares[1][1], contact_kyber_pk,
            group_id=group_id, index=2, threshold=threshold, total=total,
        )
    else:
        # Fallback: treat share #2 as a second passphrase-protected share.
        # Caller MUST provide cloud_passphrase in this branch; the same
        # passphrase is reused (or a derived sub-key if the caller wants
        # to differentiate). For MVP we require explicit second secret.
        raise ValueError(
            "contact_kyber_pk omitted but cloud_passphrase alone cannot "
            "produce 2 distinct shares; supply both."
        )

    if cloud_passphrase is not None:
        share3: ShareEnvelope = _seal_passphrase(
            shares[2][1], cloud_passphrase,
            group_id=group_id, index=3, threshold=threshold, total=total,
        )
    else:
        # No cloud passphrase: derive a deterministic "second card PIN"
        # fallback so we still emit a valid third share. The user is
        # expected to set this up later via ``rotate_cloud_share``.
        raise ValueError(
            "cloud_passphrase=None not yet supported in MVP; pass a value "
            "(can be a long random string the app stores under biometric "
            "lock if you want a 'set and forget' cloud share)"
        )

    return RecoveryPackage(
        group_id=group_id, threshold=threshold, total=total,
        vault_fp_hex=vault_fp_hex, created_at=created_at,
        shares=[share1, share2, share3],
    )


# ---------------------------------------------------------------------------
# Flexible k-of-n recovery setup
# ---------------------------------------------------------------------------

@dataclass
class ShareConfig:
    """Configuration for a single recovery share."""
    kind: str  # "card_pin" | "kyber_pk" | "passphrase"
    # For card_pin / passphrase:
    secret: Optional[str] = None
    # For kyber_pk:
    recipient_pk: Optional[bytes] = None


def setup_recovery_flexible(
    device_entropy: bytes,
    *,
    share_configs: List[ShareConfig],
    vault_fp_hex: str,
    threshold: int,
    group_id: Optional[str] = None,
) -> RecoveryPackage:
    """Split ``device_entropy`` into k-of-n shares with flexible configuration.

    This is the general-purpose version of ``setup_recovery`` that supports
    arbitrary thresholds and share counts.

    Parameters
    ----------
    device_entropy:
        The 32-byte secret to protect.
    share_configs:
        List of ShareConfig, one per share. Length determines n (total).
        Each config specifies the protection mechanism:
        - kind="card_pin": secret is the PIN string
        - kind="kyber_pk": recipient_pk is the ML-KEM-1024 public key
        - kind="passphrase": secret is the passphrase string
    vault_fp_hex:
        Card fingerprint of the source vault.
    threshold:
        Minimum number of shares needed to reconstruct (k).
    group_id:
        Optional 32 hex chars linking all shares; auto-generated if absent.

    Returns
    -------
    RecoveryPackage
        Container with n sealed share envelopes.

    Examples
    --------
    # 3-of-5 with mixed protection:
    setup_recovery_flexible(
        entropy,
        share_configs=[
            ShareConfig(kind="card_pin", secret="123456"),
            ShareConfig(kind="card_pin", secret="654321"),
            ShareConfig(kind="kyber_pk", recipient_pk=alice_pk),
            ShareConfig(kind="kyber_pk", recipient_pk=bob_pk),
            ShareConfig(kind="passphrase", secret="long phrase here"),
        ],
        vault_fp_hex="...",
        threshold=3,
    )
    """
    if len(device_entropy) < 1:
        raise ValueError("device_entropy must be non-empty")
    total = len(share_configs)
    if total < 2:
        raise ValueError("need at least 2 shares")
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if threshold > total:
        raise ValueError(f"threshold ({threshold}) > total ({total})")

    group_id = group_id or uuid.uuid4().hex
    created_at = _dt.datetime.now(_dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    shares_raw = shamir_split(device_entropy, k=threshold, n=total)
    # shares_raw[i] is (index, share_bytes); index 1..n

    sealed_shares: List[ShareEnvelope] = []
    for i, (cfg, (idx, share_bytes)) in enumerate(zip(share_configs, shares_raw)):
        share_index = i + 1  # 1-based
        if cfg.kind == "card_pin":
            if not cfg.secret or len(cfg.secret) < 4:
                raise ValueError(f"share #{share_index}: card_pin must be >= 4 chars")
            envelope = _seal_card_pin(
                share_bytes, cfg.secret,
                group_id=group_id, index=share_index,
                threshold=threshold, total=total,
            )
        elif cfg.kind == "kyber_pk":
            if cfg.recipient_pk is None:
                raise ValueError(f"share #{share_index}: kyber_pk requires recipient_pk")
            envelope = _seal_kyber(
                share_bytes, cfg.recipient_pk,
                group_id=group_id, index=share_index,
                threshold=threshold, total=total,
            )
        elif cfg.kind == "passphrase":
            if not cfg.secret or len(cfg.secret) < 8:
                raise ValueError(f"share #{share_index}: passphrase must be >= 8 chars")
            envelope = _seal_passphrase(
                share_bytes, cfg.secret,
                group_id=group_id, index=share_index,
                threshold=threshold, total=total,
            )
        else:
            raise ValueError(f"share #{share_index}: unknown kind '{cfg.kind}'")
        sealed_shares.append(envelope)

    return RecoveryPackage(
        group_id=group_id, threshold=threshold, total=total,
        vault_fp_hex=vault_fp_hex, created_at=created_at,
        shares=sealed_shares,
    )


@dataclass
class FlexibleCredentials:
    """Credentials for flexible k-of-n recovery.

    Maps share index (1-based) to the credential for that share.
    """
    # index -> PIN/passphrase string
    pins: Dict[int, str] = field(default_factory=dict)
    passphrases: Dict[int, str] = field(default_factory=dict)
    # index -> Kyber secret key bytes
    kyber_sks: Dict[int, bytes] = field(default_factory=dict)


def recover_entropy_flexible(
    package: RecoveryPackage,
    creds: FlexibleCredentials,
) -> bytes:
    """Reconstruct device_entropy from a k-of-n package using flexible credentials.

    Parameters
    ----------
    package:
        The RecoveryPackage with n shares.
    creds:
        FlexibleCredentials mapping share indices to their secrets.

    Returns
    -------
    bytes
        The reconstructed device_entropy.

    Raises
    ------
    ValueError
        If fewer than threshold shares could be decrypted.
    """
    opened: List[tuple[int, bytes]] = []
    errors: List[str] = []

    for env in package.shares:
        try:
            if isinstance(env, CardPinShare):
                pin = creds.pins.get(env.index)
                if pin is None:
                    continue
                pt = _open_card_pin(
                    env, pin,
                    group_id=package.group_id,
                    threshold=package.threshold, total=package.total,
                )
            elif isinstance(env, KyberShare):
                sk = creds.kyber_sks.get(env.index)
                if sk is None:
                    continue
                pt = _open_kyber(
                    env, sk,
                    group_id=package.group_id,
                    threshold=package.threshold, total=package.total,
                )
            elif isinstance(env, PassphraseShare):
                pp = creds.passphrases.get(env.index)
                if pp is None:
                    continue
                pt = _open_passphrase(
                    env, pp,
                    group_id=package.group_id,
                    threshold=package.threshold, total=package.total,
                )
            else:
                continue
            opened.append((env.index, pt))
            if len(opened) >= package.threshold:
                break
        except Exception as exc:
            errors.append(f"share #{env.index} ({env.kind}): {exc}")
            continue

    if len(opened) < package.threshold:
        raise ValueError(
            f"could not open enough shares: have {len(opened)}, "
            f"need {package.threshold}; errors: {errors}"
        )
    return shamir_combine(opened)


# ---------------------------------------------------------------------------
# Recovery — open any 2 of the 3 shares and reconstruct the secret
# ---------------------------------------------------------------------------

@dataclass
class RecoveryCredentials:
    """Whatever the user can provide to recover (any 2 of 3)."""
    card_pin: Optional[str] = None
    contact_kyber_sk: Optional[bytes] = None
    cloud_passphrase: Optional[str] = None


def recover_entropy(package: RecoveryPackage,
                     creds: RecoveryCredentials,
                     ) -> bytes:
    """Reconstruct ``device_entropy`` from ``package`` + credentials.

    The function tries to open each share for which the matching
    credential is provided. As soon as ``threshold`` shares have been
    opened it stops and combines them. Raises ``ValueError`` if fewer
    than ``threshold`` shares could be decrypted.
    """
    opened: List[tuple[int, bytes]] = []
    errors: List[str] = []

    for env in package.shares:
        try:
            if isinstance(env, CardPinShare):
                if creds.card_pin is None:
                    continue
                pt = _open_card_pin(
                    env, creds.card_pin,
                    group_id=package.group_id,
                    threshold=package.threshold, total=package.total,
                )
            elif isinstance(env, KyberShare):
                if creds.contact_kyber_sk is None:
                    continue
                pt = _open_kyber(
                    env, creds.contact_kyber_sk,
                    group_id=package.group_id,
                    threshold=package.threshold, total=package.total,
                )
            elif isinstance(env, PassphraseShare):
                if creds.cloud_passphrase is None:
                    continue
                pt = _open_passphrase(
                    env, creds.cloud_passphrase,
                    group_id=package.group_id,
                    threshold=package.threshold, total=package.total,
                )
            else:
                continue
            opened.append((env.index, pt))
            if len(opened) >= package.threshold:
                break
        except Exception as exc:
            errors.append(f"share #{env.index} ({env.kind}): {exc}")
            continue

    if len(opened) < package.threshold:
        raise ValueError(
            f"could not open enough shares: have {len(opened)}, "
            f"need {package.threshold}; errors: {errors}"
        )
    return shamir_combine(opened)


__all__ = [
    "SCHEMA_VERSION",
    "DEFAULT_THRESHOLD", "DEFAULT_TOTAL",
    "CardPinShare", "KyberShare", "PassphraseShare", "ShareEnvelope",
    "RecoveryPackage", "RecoveryCredentials",
    "setup_recovery", "recover_entropy",
    # Flexible k-of-n API
    "ShareConfig", "FlexibleCredentials",
    "setup_recovery_flexible", "recover_entropy_flexible",
]
