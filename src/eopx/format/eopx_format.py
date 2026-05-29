"""Pack / verify the ``.eopx`` self-signed PNG container.

A ``.eopx`` is a PNG whose ``tEXt`` chunks carry a deterministic,
post-quantum-signed manifest. The signed payload covers BOTH the
metadata fields and a hash of the raw pixel buffer, so any
tampering — chunk edit, pixel edit, or strip-and-replace — is
detected at verification time.

Layered design:

    pack()    -> writes a PIL image + tEXt chunks to disk
    verify()  -> reads chunks, recomputes payload hash, checks Dilithium signature
    read_manifest()  -> parses chunks without crypto verification (debug)

The container is self-describing: the signer's Dilithium public key is
embedded inside the PNG itself, so a verifier needs no external key
registry. Trust is established out-of-band by comparing the published
``dilithium_pk_fp`` (32-byte SHA3-256 fingerprint) against a known value.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Union

from PIL import Image, PngImagePlugin

from .keys import (
    EopxKey,
    SIG_ALGORITHM,
    SIG_PUBLIC_KEY_SIZE,
    SIG_SIGNATURE_SIZE,
    key_fingerprint,
)

FORMAT_VERSION = "1"
CHUNK_PREFIX = "eopx:"

ZEROS_32 = bytes(32).hex()


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

@dataclass
class EopxManifest:
    """The signed metadata block of a ``.eopx``.

    All hex fields are lowercase. ``vault_id`` is an opaque 16-byte
    identifier; we default to a random UUID4 when packing.
    """
    vault_id: str
    dilithium_pk: bytes
    kyber_pk: Optional[bytes] = None
    merkle_root: str = ZEROS_32  # hex
    timestamp_utc: str = ""
    image_sha3_512: str = ""     # hex of SHA3-512(pixel_bytes)

    # Computed at sign time.
    payload_hash: str = ""        # hex SHA3-512(canonical_payload())
    signature: bytes = b""        # ML-DSA-87 signature

    format_version: str = FORMAT_VERSION

    # ----- properties -------------------------------------------------

    @property
    def dilithium_pk_fp(self) -> str:
        return key_fingerprint(self.dilithium_pk).hex()

    @property
    def kyber_pk_fp(self) -> str:
        if self.kyber_pk is None:
            return ZEROS_32
        return key_fingerprint(self.kyber_pk).hex()

    # ----- canonical serialization ------------------------------------

    def canonical_payload(self) -> bytes:
        """Deterministic byte string covered by the signature.

        Ordering and field set are FROZEN — any future format bump must
        increment ``format_version`` and define a new canonicalizer.
        """
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

    def compute_payload_hash(self) -> str:
        return hashlib.sha3_512(self.canonical_payload()).hexdigest()

    # ----- chunk encoding ---------------------------------------------

    def to_chunks(self) -> Dict[str, str]:
        if not self.payload_hash or not self.signature:
            raise RuntimeError("manifest is not yet signed; call pack() instead")
        return {
            f"{CHUNK_PREFIX}format_version": self.format_version,
            f"{CHUNK_PREFIX}vault_id": self.vault_id,
            f"{CHUNK_PREFIX}merkle_root": self.merkle_root,
            f"{CHUNK_PREFIX}dilithium_pk_b64": base64.b64encode(self.dilithium_pk).decode("ascii"),
            f"{CHUNK_PREFIX}dilithium_pk_fp": self.dilithium_pk_fp,
            f"{CHUNK_PREFIX}kyber_pk_b64": base64.b64encode(self.kyber_pk).decode("ascii") if self.kyber_pk else "",
            f"{CHUNK_PREFIX}kyber_pk_fp": self.kyber_pk_fp,
            f"{CHUNK_PREFIX}timestamp_utc": self.timestamp_utc,
            f"{CHUNK_PREFIX}image_sha3_512": self.image_sha3_512,
            f"{CHUNK_PREFIX}payload_hash": self.payload_hash,
            f"{CHUNK_PREFIX}sig_dilithium5_b64": base64.b64encode(self.signature).decode("ascii"),
        }

    @classmethod
    def from_chunks(cls, info: Dict[str, str]) -> "EopxManifest":
        def _get(key: str, required: bool = True) -> str:
            v = info.get(f"{CHUNK_PREFIX}{key}", "")
            if required and not v:
                raise ValueError(f"missing required eopx chunk: {key}")
            return v

        dilithium_pk = base64.b64decode(_get("dilithium_pk_b64"))
        if len(dilithium_pk) != SIG_PUBLIC_KEY_SIZE:
            raise ValueError(
                f"dilithium_pk has wrong length: {len(dilithium_pk)} "
                f"(expected {SIG_PUBLIC_KEY_SIZE})"
            )

        # Defense-in-depth: the embedded ``dilithium_pk_fp`` chunk must match
        # SHA3-256 of the embedded public key. Without this check, a tampered
        # PNG could carry a misleading fingerprint that passes verify() as
        # long as the signature itself is valid.
        fp_chunk = _get("dilithium_pk_fp", required=False)
        if fp_chunk:
            fp_actual = key_fingerprint(dilithium_pk).hex()
            if fp_chunk.lower() != fp_actual:
                raise ValueError(
                    "dilithium_pk_fp chunk inconsistent with embedded "
                    "Dilithium public key"
                )

        kyber_b64 = _get("kyber_pk_b64", required=False)
        kyber_pk = base64.b64decode(kyber_b64) if kyber_b64 else None
        if kyber_pk is not None:
            kfp_chunk = _get("kyber_pk_fp", required=False)
            kfp_actual = key_fingerprint(kyber_pk).hex()
            if not kfp_chunk:
                raise ValueError(
                    "kyber_pk_b64 chunk present but kyber_pk_fp chunk is "
                    "missing"
                )
            if kfp_chunk == ZEROS_32:
                raise ValueError(
                    "kyber_pk_fp chunk is the zero fingerprint but a "
                    "Kyber public key is embedded"
                )
            if kfp_chunk.lower() != kfp_actual:
                raise ValueError(
                    "kyber_pk_fp chunk inconsistent with embedded "
                    "Kyber public key"
                )

        signature = base64.b64decode(_get("sig_dilithium5_b64"))

        return cls(
            format_version=_get("format_version"),
            vault_id=_get("vault_id"),
            dilithium_pk=dilithium_pk,
            kyber_pk=kyber_pk,
            merkle_root=_get("merkle_root", required=False) or ZEROS_32,
            timestamp_utc=_get("timestamp_utc"),
            image_sha3_512=_get("image_sha3_512"),
            payload_hash=_get("payload_hash"),
            signature=signature,
        )


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Structured outcome of :func:`verify`.

    ``ok`` is True iff every check passed. The individual fields tell
    you *which* check failed when ``ok`` is False (signature, payload
    hash, image hash, or chunk parsing).
    """
    ok: bool
    manifest: Optional[EopxManifest] = None
    chunks_ok: bool = False
    image_hash_ok: bool = False
    payload_hash_ok: bool = False
    signature_ok: bool = False
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


# ---------------------------------------------------------------------------
# Pack / verify helpers
# ---------------------------------------------------------------------------

def _pixel_hash(img: Image.Image) -> str:
    """SHA3-512 over the canonical RGB byte buffer of an image."""
    if img.mode != "RGB":
        img = img.convert("RGB")
    return hashlib.sha3_512(img.tobytes()).hexdigest()


def _new_vault_id() -> str:
    """Generate a fresh random 16-byte vault ID (UUID4 hex)."""
    return uuid.uuid4().hex


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


ImageInput = Union[Image.Image, str, Path]


def _load_image(img: ImageInput) -> Image.Image:
    if isinstance(img, Image.Image):
        return img
    return Image.open(img)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def pack(image: ImageInput,
         out_path: str | Path,
         signer: EopxKey,
         *,
         vault_id: Optional[str] = None,
         merkle_root: bytes | str | None = None,
         kyber_pk: Optional[bytes] = None,
         timestamp_utc: Optional[str] = None,
         ) -> EopxManifest:
    """Sign an image and write it as a ``.eopx`` PNG.

    Parameters
    ----------
    image:
        PIL image, or a path to any image readable by PIL.
    out_path:
        Destination ``.eopx`` path. Existing files are overwritten.
    signer:
        :class:`EopxKey` with secret key material loaded.
    vault_id:
        16-byte hex. Defaults to a random UUID4.
    merkle_root:
        32-byte commitment to vault genesis data, or ``None`` to embed
        zeros. Accepts raw ``bytes`` or hex ``str``.
    kyber_pk:
        Optional override for the Kyber public key fingerprint embedded
        in the manifest. Defaults to ``signer.kyber_pk``.
    timestamp_utc:
        ISO-8601 string. Defaults to ``utcnow()``.
    """
    if not signer.has_secrets:
        raise ValueError("signer must hold a Dilithium private key")

    img = _load_image(image)
    if img.mode != "RGB":
        img = img.convert("RGB")

    # Normalize merkle_root to hex
    if merkle_root is None:
        mr_hex = ZEROS_32
    elif isinstance(merkle_root, (bytes, bytearray)):
        if len(merkle_root) != 32:
            raise ValueError("merkle_root must be 32 bytes")
        mr_hex = bytes(merkle_root).hex()
    else:
        mr_str = str(merkle_root).lower()
        if len(mr_str) != 64:
            raise ValueError("merkle_root hex must be 64 chars")
        mr_hex = mr_str

    manifest = EopxManifest(
        vault_id=vault_id or _new_vault_id(),
        dilithium_pk=signer.dilithium_pk,
        kyber_pk=kyber_pk if kyber_pk is not None else signer.kyber_pk,
        merkle_root=mr_hex,
        timestamp_utc=timestamp_utc or _utc_now(),
        image_sha3_512=_pixel_hash(img),
    )

    manifest.payload_hash = manifest.compute_payload_hash()
    manifest.signature = signer.sign(bytes.fromhex(manifest.payload_hash))
    if len(manifest.signature) != SIG_SIGNATURE_SIZE:
        raise RuntimeError(
            f"unexpected Dilithium5 signature size: {len(manifest.signature)}"
        )

    info = PngImagePlugin.PngInfo()
    for k, v in manifest.to_chunks().items():
        info.add_text(k, v)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out, format="PNG", pnginfo=info, optimize=False)
    return manifest


def read_manifest(path: str | Path) -> EopxManifest:
    """Parse the manifest of a ``.eopx`` without verifying anything.

    Useful for diagnostics. Raises ``ValueError`` only on structural
    issues (missing chunks, bad lengths) — not on tampered signatures.
    """
    with Image.open(path) as img:
        info = dict(img.info)
    return EopxManifest.from_chunks(info)


def verify(path: str | Path,
           *,
           expected_dilithium_pk_fp: Optional[bytes | str] = None,
           ) -> VerificationResult:
    """Verify a ``.eopx`` file: chunks → image hash → payload hash → signature.

    Parameters
    ----------
    path:
        Path to the ``.eopx`` (PNG with eopx chunks).
    expected_dilithium_pk_fp:
        Optional 32-byte fingerprint that the embedded Dilithium public
        key must match. If provided as ``str``, must be 64 hex chars.
        When ``None``, only structural/cryptographic checks run and the
        verifier trusts the embedded key (still useful: the signature
        proves the file was minted by *whoever* owns that key).
    """
    res = VerificationResult(ok=False)

    try:
        with Image.open(path) as img:
            img.load()
            chunks = dict(img.info)
            pil_rgb = img.convert("RGB")
            actual_pixel_hash = hashlib.sha3_512(pil_rgb.tobytes()).hexdigest()
    except Exception as exc:
        res.errors.append(f"cannot open image: {exc}")
        return res

    try:
        manifest = EopxManifest.from_chunks(chunks)
        res.manifest = manifest
        res.chunks_ok = True
    except Exception as exc:
        res.errors.append(f"manifest parse failed: {exc}")
        return res

    if expected_dilithium_pk_fp is not None:
        if isinstance(expected_dilithium_pk_fp, str):
            exp_fp_hex = expected_dilithium_pk_fp.lower()
        else:
            exp_fp_hex = bytes(expected_dilithium_pk_fp).hex()
        if exp_fp_hex != manifest.dilithium_pk_fp:
            res.errors.append(
                f"signer fingerprint mismatch: expected {exp_fp_hex}, "
                f"got {manifest.dilithium_pk_fp}"
            )
            return res

    if actual_pixel_hash != manifest.image_sha3_512:
        res.errors.append(
            f"image pixel hash mismatch (got {actual_pixel_hash[:16]}..., "
            f"manifest says {manifest.image_sha3_512[:16]}...)"
        )
        return res
    res.image_hash_ok = True

    recomputed_payload_hash = manifest.compute_payload_hash()
    if recomputed_payload_hash != manifest.payload_hash:
        res.errors.append("payload_hash inconsistent with canonical manifest")
        return res
    res.payload_hash_ok = True

    pub_only = EopxKey(
        dilithium_pk=manifest.dilithium_pk,
        kyber_pk=manifest.kyber_pk or bytes(0),
    )
    sig_ok = pub_only.verify(bytes.fromhex(manifest.payload_hash),
                              manifest.signature)
    if not sig_ok:
        res.errors.append("Dilithium5 signature verification failed")
        return res
    res.signature_ok = True
    res.ok = True
    return res
