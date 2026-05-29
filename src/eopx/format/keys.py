"""Post-quantum key management for Esoptron.

Wraps ``pqcrypto.sign.ml_dsa_87`` (Dilithium5) and
``pqcrypto.kem.ml_kem_1024`` (Kyber1024) so the rest of the package
sees a stable API regardless of the underlying binding.

Keys live in a portable JSON envelope::

    {
        "version": 1,
        "created_utc": "2026-05-27T12:34:56Z",
        "dilithium_pk_b64": "...",
        "dilithium_sk_b64": "...",
        "kyber_pk_b64": "...",
        "kyber_sk_b64": "..."
    }

Private fields are intentionally NOT encrypted at rest — that is the
caller's responsibility (Eidolon-side machine_lock, OS keystore, etc.).
The file mode is set to ``0o600`` on POSIX where applicable.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_UTC = _dt.timezone.utc

try:
    from pqcrypto.sign import ml_dsa_87 as _dsa
    from pqcrypto.kem import ml_kem_1024 as _kem
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "pqcrypto is required for Esoptron format; "
        "install with `pip install pqcrypto`"
    ) from exc


SIG_ALGORITHM = "ML-DSA-87"  # NIST FIPS 204 (Dilithium5)
KEM_ALGORITHM = "ML-KEM-1024"  # NIST FIPS 203 (Kyber1024)

SIG_PUBLIC_KEY_SIZE = _dsa.PUBLIC_KEY_SIZE  # 2592
SIG_SECRET_KEY_SIZE = _dsa.SECRET_KEY_SIZE  # 4896
SIG_SIGNATURE_SIZE = _dsa.SIGNATURE_SIZE    # 4627

KEM_PUBLIC_KEY_SIZE = _kem.PUBLIC_KEY_SIZE  # 1568
KEM_SECRET_KEY_SIZE = _kem.SECRET_KEY_SIZE  # 3168
KEM_CIPHERTEXT_SIZE = _kem.CIPHERTEXT_SIZE  # 1568


def _utc_now() -> str:
    return _dt.datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def key_fingerprint(public_key: bytes) -> bytes:
    """SHA3-256 fingerprint of a public key (32 bytes)."""
    return hashlib.sha3_256(public_key).digest()


@dataclass
class EopxKey:
    """A Dilithium5 + Kyber1024 keypair envelope.

    Either the secret keys are present (signer/recipient role) or only
    the public keys are present (verifier role). Use :meth:`public_only`
    to derive a verifier-safe copy.
    """
    dilithium_pk: bytes
    kyber_pk: bytes
    dilithium_sk: Optional[bytes] = None
    kyber_sk: Optional[bytes] = None
    created_utc: str = ""

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> "EopxKey":
        """Generate a fresh Dilithium5 + Kyber1024 keypair."""
        dilithium_pk, dilithium_sk = _dsa.generate_keypair()
        kyber_pk, kyber_sk = _kem.generate_keypair()
        return cls(
            dilithium_pk=dilithium_pk, dilithium_sk=dilithium_sk,
            kyber_pk=kyber_pk, kyber_sk=kyber_sk,
            created_utc=_utc_now(),
        )

    def public_only(self) -> "EopxKey":
        """Return a copy with secret material stripped."""
        return EopxKey(
            dilithium_pk=self.dilithium_pk,
            kyber_pk=self.kyber_pk,
            created_utc=self.created_utc,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def has_secrets(self) -> bool:
        return self.dilithium_sk is not None and self.kyber_sk is not None

    @property
    def dilithium_pk_fp(self) -> bytes:
        """SHA3-256 fingerprint of the Dilithium5 public key."""
        return key_fingerprint(self.dilithium_pk)

    @property
    def kyber_pk_fp(self) -> bytes:
        """SHA3-256 fingerprint of the Kyber1024 public key."""
        return key_fingerprint(self.kyber_pk)

    # ------------------------------------------------------------------
    # Signing primitives (raise if secret not present)
    # ------------------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """Sign a byte string with Dilithium5. Requires the secret key."""
        if self.dilithium_sk is None:
            raise RuntimeError("cannot sign: dilithium_sk not loaded")
        return _dsa.sign(self.dilithium_sk, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a Dilithium5 signature. Always available."""
        try:
            return _dsa.verify(self.dilithium_pk, message, signature)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # KEM primitives
    # ------------------------------------------------------------------

    def kem_encapsulate(self) -> tuple[bytes, bytes]:
        """Kyber1024 KEM encapsulation: return (ciphertext, shared_secret).

        Uses ``self.kyber_pk`` as the recipient's public key. Can be
        called on a public-only :class:`EopxKey`.
        """
        ct, ss = _kem.encrypt(self.kyber_pk)
        return ct, ss

    def kem_decapsulate(self, ciphertext: bytes) -> bytes:
        """Kyber1024 KEM decapsulation. Requires the secret key."""
        if self.kyber_sk is None:
            raise RuntimeError("cannot decapsulate: kyber_sk not loaded")
        return _kem.decrypt(self.kyber_sk, ciphertext)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        out = {
            "version": 1,
            "created_utc": self.created_utc or _utc_now(),
            "sig_algorithm": SIG_ALGORITHM,
            "kem_algorithm": KEM_ALGORITHM,
            "dilithium_pk_b64": _b64e(self.dilithium_pk),
            "kyber_pk_b64": _b64e(self.kyber_pk),
        }
        if self.dilithium_sk is not None:
            out["dilithium_sk_b64"] = _b64e(self.dilithium_sk)
        if self.kyber_sk is not None:
            out["kyber_sk_b64"] = _b64e(self.kyber_sk)
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "EopxKey":
        if d.get("version") != 1:
            raise ValueError(f"unsupported EopxKey version: {d.get('version')}")
        return cls(
            dilithium_pk=_b64d(d["dilithium_pk_b64"]),
            kyber_pk=_b64d(d["kyber_pk_b64"]),
            dilithium_sk=_b64d(d["dilithium_sk_b64"]) if "dilithium_sk_b64" in d else None,
            kyber_sk=_b64d(d["kyber_sk_b64"]) if "kyber_sk_b64" in d else None,
            created_utc=d.get("created_utc", ""),
        )

    def save(self, path: str | Path) -> Path:
        """Write the envelope as JSON with restricted permissions.

        Best-effort: ``0o600`` on POSIX, DACL lock-down via ``icacls`` on
        Windows. Emits a warning when neither succeeds; the secret-key
        envelope is unencrypted so loss of file-level protection means
        any local user can read the private keys.
        """
        from .file_perms import restrict_secret_file

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(self.to_dict(), indent=2).encode("utf-8")
        path.write_bytes(data)
        if self.has_secrets:
            restrict_secret_file(path)
        return path

    @classmethod
    def load(cls, path: str | Path) -> "EopxKey":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    # ------------------------------------------------------------------
    # Best-effort wipe
    # ------------------------------------------------------------------

    def wipe_secrets(self) -> None:
        """Zero any in-memory secret-key material owned by this object.

        After this call the keypair becomes effectively public-only:
        :attr:`has_secrets` returns False and signing / decapsulation
        raise. This is a tactical mitigation; see ``secure_bytes`` for
        the caveats around Python's memory model.
        """
        from .secure_bytes import _zeroize
        for attr in ("dilithium_sk", "kyber_sk"):
            val = getattr(self, attr)
            if val is None:
                continue
            # Copy into a mutable buffer we can zero, then drop the
            # original reference. (The original immutable bytes may
            # still linger in private pqcrypto buffers — we cannot
            # touch those without modifying the binding.)
            scratch = bytearray(val)
            _zeroize(scratch)
            setattr(self, attr, None)
