"""Self-contained verifier for the ``.eopx`` container.

This module duplicates the canonical payload format used by the upstream
``eopx.format.eopx_format`` module so that the SDK can be shipped
independently. The wire format is FROZEN at version 1; any future change
will require a coordinated bump on both sides.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

__version__ = "0.1.0"

try:
    from PIL import Image
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "Pillow is required: pip install Pillow>=10.0"
    ) from exc

try:
    from pqcrypto.sign import ml_dsa_87 as _dsa
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "pqcrypto is required: pip install pqcrypto"
    ) from exc


CHUNK_PREFIX = "eopx:"
FORMAT_VERSION_SUPPORTED = "1"
ZEROS_32_HEX = "0" * 64

SIG_PUBLIC_KEY_SIZE = _dsa.PUBLIC_KEY_SIZE  # 2592


# ---------------------------------------------------------------------------
# Manifest (read-only twin of eopx.format.EopxManifest)
# ---------------------------------------------------------------------------

@dataclass
class Manifest:
    format_version: str
    vault_id: str
    dilithium_pk: bytes
    dilithium_pk_fp: str
    kyber_pk_fp: str
    merkle_root: str
    timestamp_utc: str
    image_sha3_512: str
    payload_hash: str
    signature: bytes
    kyber_pk: Optional[bytes] = None

    def canonical_payload(self) -> bytes:
        lines = [
            f"eopx_format_version={self.format_version}",
            f"vault_id={self.vault_id}",
            f"merkle_root={self.merkle_root}",
            f"dilithium_pk_fp={self.dilithium_pk_fp}",
            f"kyber_pk_fp={self.kyber_pk_fp}",
            f"timestamp_utc={self.timestamp_utc}",
            f"image_sha3_512={self.image_sha3_512}",
        ]
        return ("\n".join(lines)).encode("utf-8")


@dataclass
class VerificationResult:
    ok: bool = False
    manifest: Optional[Manifest] = None
    chunks_ok: bool = False
    image_hash_ok: bool = False
    payload_hash_ok: bool = False
    signature_ok: bool = False
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _parse_chunks(info: dict) -> Manifest:
    def _get(key: str, required: bool = True) -> str:
        v = info.get(f"{CHUNK_PREFIX}{key}", "")
        if required and not v:
            raise ValueError(f"missing required eopx chunk: {key}")
        return v

    fmt = _get("format_version")
    if fmt != FORMAT_VERSION_SUPPORTED:
        raise ValueError(
            f"unsupported eopx format_version: {fmt} "
            f"(this SDK speaks version {FORMAT_VERSION_SUPPORTED})"
        )

    dilithium_pk = _b64d(_get("dilithium_pk_b64"))
    if len(dilithium_pk) != SIG_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"dilithium_pk has wrong length: {len(dilithium_pk)} "
            f"(expected {SIG_PUBLIC_KEY_SIZE})"
        )
    fp_chunk = _get("dilithium_pk_fp")
    fp_actual = _sha3_256(dilithium_pk).hex()
    if fp_chunk != fp_actual:
        raise ValueError(
            "dilithium_pk_fp chunk inconsistent with embedded public key"
        )

    kyber_b64 = _get("kyber_pk_b64", required=False)
    kyber_pk = _b64d(kyber_b64) if kyber_b64 else None
    if kyber_pk is not None:
        fp = _sha3_256(kyber_pk).hex()
        chunk_fp = _get("kyber_pk_fp", required=False)
        if chunk_fp and chunk_fp != fp:
            raise ValueError(
                "kyber_pk_fp chunk inconsistent with embedded Kyber key"
            )

    return Manifest(
        format_version=fmt,
        vault_id=_get("vault_id"),
        dilithium_pk=dilithium_pk,
        dilithium_pk_fp=fp_actual,
        kyber_pk=kyber_pk,
        kyber_pk_fp=_get("kyber_pk_fp", required=False) or ZEROS_32_HEX,
        merkle_root=_get("merkle_root", required=False) or ZEROS_32_HEX,
        timestamp_utc=_get("timestamp_utc"),
        image_sha3_512=_get("image_sha3_512"),
        payload_hash=_get("payload_hash"),
        signature=_b64d(_get("sig_dilithium5_b64")),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

PathLike = Union[str, Path]


def read_manifest(path: PathLike) -> Manifest:
    """Parse the manifest of a ``.eopx`` without any cryptographic check."""
    with Image.open(path) as img:
        info = dict(img.info)
    return _parse_chunks(info)


def verify(path: PathLike,
           *,
           expected_dilithium_pk_fp: Optional[Union[bytes, str]] = None,
           ) -> VerificationResult:
    """Verify a ``.eopx`` artefact end-to-end.

    Parameters
    ----------
    path:
        Path to the ``.eopx`` file.
    expected_dilithium_pk_fp:
        Optional SHA3-256 fingerprint (32 bytes or 64-char hex) that the
        embedded signer key must match. Without this argument the SDK
        only attests that the file is internally consistent and signed
        by *whichever* identity it embeds.

    Returns
    -------
    VerificationResult
        See the dataclass; ``result.ok`` is ``True`` iff every check
        passes. Never raises on tampering — callers should always
        check ``ok`` and ``errors``.
    """
    res = VerificationResult()

    try:
        with Image.open(path) as img:
            img.load()
            info = dict(img.info)
            rgb = img.convert("RGB")
            pixel_hash = hashlib.sha3_512(rgb.tobytes()).hexdigest()
    except Exception as exc:
        res.errors.append(f"cannot open image: {exc}")
        return res

    try:
        manifest = _parse_chunks(info)
        res.manifest = manifest
        res.chunks_ok = True
    except Exception as exc:
        res.errors.append(f"manifest parse failed: {exc}")
        return res

    if expected_dilithium_pk_fp is not None:
        if isinstance(expected_dilithium_pk_fp, str):
            exp = expected_dilithium_pk_fp.lower()
        else:
            exp = bytes(expected_dilithium_pk_fp).hex()
        if exp != manifest.dilithium_pk_fp:
            res.errors.append(
                f"signer fingerprint mismatch: expected {exp}, "
                f"got {manifest.dilithium_pk_fp}"
            )
            return res

    if pixel_hash != manifest.image_sha3_512:
        res.errors.append("image pixel hash mismatch — pixels were tampered")
        return res
    res.image_hash_ok = True

    if hashlib.sha3_512(manifest.canonical_payload()).hexdigest() != manifest.payload_hash:
        res.errors.append("payload_hash inconsistent with canonical manifest")
        return res
    res.payload_hash_ok = True

    try:
        ok = _dsa.verify(manifest.dilithium_pk,
                          bytes.fromhex(manifest.payload_hash),
                          manifest.signature)
    except Exception:
        ok = False
    if not ok:
        res.errors.append("Dilithium5 signature verification failed")
        return res
    res.signature_ok = True
    res.ok = True
    return res
