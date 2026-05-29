"""Visual Shamir sharding: split a secret into ``n`` signed ``.eopx`` shards.

Each shard is a standalone PNG whose ``tEXt`` chunks carry:

* the **shared parameters** ``(k, n, share_index, group_id, secret_len)``
* a **Kyber1024 encapsulation** to the recipient: ``shard_kem_ct_b64``
* a **ChaCha20-Poly1305 ciphertext** of the share bytes, with the AEAD
  key derived from the KEM shared secret: ``shard_aead_b64``
* the **dilithium signature** that covers all the above

This means each shard:

* is independently verifiable (its signature attests integrity);
* can only be decrypted by the holder of the matching Kyber private key;
* leaks nothing about the secret beyond its length when held in
  isolation (Shamir property) and reveals no plaintext share to a
  passive observer who lacks the Kyber secret (KEM + AEAD).

The "image" of each shard is a 1x1 placeholder by default, but callers
may pass a real visualization (e.g. a Metatron-style cube) that will be
included in the signed payload via :func:`eopx.format.pack`.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import secrets as _secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from PIL import Image, PngImagePlugin

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .eopx_format import (
    CHUNK_PREFIX,
    FORMAT_VERSION,
    ZEROS_32,
    EopxManifest,
    _pixel_hash,
    _utc_now,
)
from .keys import EopxKey, key_fingerprint, KEM_CIPHERTEXT_SIZE
from .shamir import shamir_split, shamir_combine

SHARD_FORMAT_VERSION = "1"
AEAD_INFO = b"esoptron.shard.aead_key.v1"
AEAD_NONCE_LEN = 12


# ---------------------------------------------------------------------------
# Shard manifest — extends EopxManifest with shard-specific fields
# ---------------------------------------------------------------------------

@dataclass
class ShardManifest:
    """Extended manifest for a single ``.eopx`` shard.

    The ``base`` manifest carries the standard fields (vault_id,
    timestamps, signing key). The shard-specific fields are appended
    to the canonical payload BEFORE signing so they are covered by the
    same Dilithium signature.
    """
    base: EopxManifest
    group_id: str                # 32 hex chars — links shards of one split
    shard_index: int             # 1..n
    shard_k: int                 # threshold
    shard_n: int                 # total shards
    secret_len: int              # plaintext secret length in bytes
    recipient_kyber_pk_fp: str   # 64 hex — recipient's Kyber pubkey fingerprint
    kem_ciphertext: bytes        # Kyber1024 ciphertext
    aead_ciphertext: bytes       # ChaCha20-Poly1305(nonce || ct || tag)

    def canonical_payload(self) -> bytes:
        base_lines = self.base.canonical_payload().decode("utf-8").split("\n")
        # Shard-specific fields appended deterministically.
        extra = [
            f"shard_format_version={SHARD_FORMAT_VERSION}",
            f"shard_group_id={self.group_id}",
            f"shard_index={self.shard_index}",
            f"shard_k={self.shard_k}",
            f"shard_n={self.shard_n}",
            f"shard_secret_len={self.secret_len}",
            f"shard_recipient_kyber_pk_fp={self.recipient_kyber_pk_fp}",
            f"shard_kem_ciphertext_sha3_256={hashlib.sha3_256(self.kem_ciphertext).hexdigest()}",
            f"shard_aead_ciphertext_sha3_256={hashlib.sha3_256(self.aead_ciphertext).hexdigest()}",
        ]
        return ("\n".join(base_lines + extra)).encode("utf-8")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

from ..metatron.field import hkdf_sha3_256 as _hkdf_sha3_256  # noqa: E402


def _derive_aead_key(shared_secret: bytes, group_id: str) -> bytes:
    """Derive a 32-byte ChaCha20-Poly1305 key from a Kyber shared secret."""
    info = AEAD_INFO + b"|" + group_id.encode("ascii")
    return _hkdf_sha3_256(shared_secret, b"", info, 32)


def _derive_nonce(kem_ct: bytes, shard_index: int) -> bytes:
    """Deterministic 12-byte nonce per shard.

    Safe because each ``(kem_ct, shard_index)`` pair is unique by
    construction: ``kem_ct`` is produced by a fresh Kyber encapsulation
    per shard, and we never re-encrypt the same share twice.
    """
    h = hashlib.sha3_256(kem_ct + shard_index.to_bytes(2, "big")).digest()
    return h[:AEAD_NONCE_LEN]


def _encrypt_share(share: bytes, recipient_pk: bytes,
                    group_id: str, shard_index: int,
                    associated_data: bytes
                    ) -> Tuple[bytes, bytes]:
    """Return ``(kem_ct, aead_ct)``.

    The AAD binds the AEAD ciphertext to the shard's metadata, so an
    attacker swapping shards across groups breaks the AEAD tag check.
    """
    from pqcrypto.kem import ml_kem_1024 as _kem
    kem_ct, ss = _kem.encrypt(recipient_pk)
    aead_key = _derive_aead_key(ss, group_id)
    nonce = _derive_nonce(kem_ct, shard_index)
    aead_ct = ChaCha20Poly1305(aead_key).encrypt(nonce, share, associated_data)
    return kem_ct, aead_ct


def _decrypt_share(kem_ct: bytes, aead_ct: bytes,
                    recipient_sk: bytes,
                    group_id: str, shard_index: int,
                    associated_data: bytes
                    ) -> bytes:
    from pqcrypto.kem import ml_kem_1024 as _kem
    ss = _kem.decrypt(recipient_sk, kem_ct)
    aead_key = _derive_aead_key(ss, group_id)
    nonce = _derive_nonce(kem_ct, shard_index)
    return ChaCha20Poly1305(aead_key).decrypt(nonce, aead_ct, associated_data)


def _shard_associated_data(group_id: str, shard_index: int,
                            shard_k: int, shard_n: int,
                            recipient_kyber_pk_fp: str) -> bytes:
    """Public, non-secret data that binds the AEAD to the shard identity."""
    return "|".join([
        "esoptron.shard.v1",
        group_id,
        str(shard_index),
        str(shard_k),
        str(shard_n),
        recipient_kyber_pk_fp,
    ]).encode("utf-8")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class ShardPack:
    """Result of :func:`shard_secret`."""
    group_id: str
    paths: List[Path]
    manifests: List[ShardManifest]


def _default_placeholder_image() -> Image.Image:
    """Tiny opaque PNG used when the caller doesn't supply a shard image."""
    return Image.new("RGB", (16, 16), (220, 220, 220))


def shard_secret(secret: bytes,
                  k: int,
                  recipient_kyber_pks: Sequence[bytes],
                  signer: EopxKey,
                  out_dir: str | Path,
                  *,
                  image: Optional[Image.Image] = None,
                  vault_id: Optional[str] = None,
                  merkle_root: Optional[bytes | str] = None,
                  group_id: Optional[str] = None,
                  filename_prefix: str = "shard",
                  ) -> ShardPack:
    """Split ``secret`` into ``len(recipient_kyber_pks)`` signed ``.eopx`` shards.

    Parameters
    ----------
    secret:
        The raw bytes to share (e.g. a vault seed). Must be non-empty.
    k:
        Reconstruction threshold. Any ``k`` shards reconstruct the secret.
    recipient_kyber_pks:
        Ordered list of Kyber1024 public keys, one per recipient. The
        i-th recipient receives shard number ``i + 1``.
    signer:
        Dilithium5 signing key. Each shard is independently signed.
    out_dir:
        Directory where shard files are written. Created if absent.
    image:
        Optional PIL image to embed as the shard's visual layer. Defaults
        to a 16x16 grey placeholder so the manifest still rides in a
        valid PNG.
    vault_id:
        Optional vault identifier; defaults to a fresh UUID4 shared across
        all shards of this group.
    merkle_root:
        Optional 32-byte commitment carried in every shard's base manifest.
    group_id:
        Optional 32 hex-char identifier linking shards of one split;
        defaults to a fresh random value.
    filename_prefix:
        Used to build ``{prefix}_{group_id[:8]}_{index:02d}.eopx`` names.

    Returns
    -------
    ShardPack
        ``group_id``, list of file paths, and list of shard manifests.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise ValueError("secret must be non-empty bytes")
    if not signer.has_secrets:
        raise ValueError("signer must hold a Dilithium private key")
    n = len(recipient_kyber_pks)
    if not (1 <= k <= n):
        raise ValueError(f"need 1 <= k <= n, got k={k}, n={n}")

    group_id = group_id or uuid.uuid4().hex
    if len(group_id) != 32:
        raise ValueError("group_id must be 32 hex chars")
    vault_id = vault_id or uuid.uuid4().hex

    # Normalize merkle_root
    if merkle_root is None:
        mr_hex = ZEROS_32
    elif isinstance(merkle_root, (bytes, bytearray)):
        if len(merkle_root) != 32:
            raise ValueError("merkle_root must be 32 bytes")
        mr_hex = bytes(merkle_root).hex()
    else:
        mr_hex = str(merkle_root).lower()
        if len(mr_hex) != 64:
            raise ValueError("merkle_root hex must be 64 chars")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    img = image if image is not None else _default_placeholder_image()
    if img.mode != "RGB":
        img = img.convert("RGB")
    image_hash = _pixel_hash(img)
    timestamp = _utc_now()

    # 1. Shamir split the secret on GF(2^8).
    shares = shamir_split(bytes(secret), k=k, n=n)

    # 2. For each recipient: KEM encapsulate, AEAD encrypt, build manifest.
    paths: List[Path] = []
    manifests: List[ShardManifest] = []

    for shard_idx, recipient_pk in enumerate(recipient_kyber_pks, start=1):
        share_index_check, share_bytes = shares[shard_idx - 1]
        assert share_index_check == shard_idx
        recipient_fp = key_fingerprint(recipient_pk).hex()

        aad = _shard_associated_data(
            group_id=group_id, shard_index=shard_idx, shard_k=k, shard_n=n,
            recipient_kyber_pk_fp=recipient_fp,
        )
        kem_ct, aead_ct = _encrypt_share(
            share=share_bytes, recipient_pk=recipient_pk,
            group_id=group_id, shard_index=shard_idx,
            associated_data=aad,
        )

        # Base manifest (shared core).
        base = EopxManifest(
            vault_id=vault_id,
            dilithium_pk=signer.dilithium_pk,
            kyber_pk=recipient_pk,    # Identify the recipient in the manifest
            merkle_root=mr_hex,
            timestamp_utc=timestamp,
            image_sha3_512=image_hash,
        )
        shard = ShardManifest(
            base=base,
            group_id=group_id,
            shard_index=shard_idx,
            shard_k=k,
            shard_n=n,
            secret_len=len(secret),
            recipient_kyber_pk_fp=recipient_fp,
            kem_ciphertext=kem_ct,
            aead_ciphertext=aead_ct,
        )

        payload = shard.canonical_payload()
        payload_hash = hashlib.sha3_512(payload).hexdigest()
        signature = signer.sign(bytes.fromhex(payload_hash))

        # Write back into base manifest so to_chunks() works.
        base.payload_hash = payload_hash
        base.signature = signature

        # Compose PNG chunks: standard base chunks + shard-specific chunks.
        info = PngImagePlugin.PngInfo()
        for k_, v in base.to_chunks().items():
            info.add_text(k_, v)
        info.add_text(f"{CHUNK_PREFIX}shard_format_version", SHARD_FORMAT_VERSION)
        info.add_text(f"{CHUNK_PREFIX}shard_group_id", group_id)
        info.add_text(f"{CHUNK_PREFIX}shard_index", str(shard_idx))
        info.add_text(f"{CHUNK_PREFIX}shard_k", str(k))
        info.add_text(f"{CHUNK_PREFIX}shard_n", str(n))
        info.add_text(f"{CHUNK_PREFIX}shard_secret_len", str(len(secret)))
        info.add_text(f"{CHUNK_PREFIX}shard_recipient_kyber_pk_fp", recipient_fp)
        info.add_text(f"{CHUNK_PREFIX}shard_kem_ciphertext_b64",
                       base64.b64encode(kem_ct).decode("ascii"))
        info.add_text(f"{CHUNK_PREFIX}shard_aead_ciphertext_b64",
                       base64.b64encode(aead_ct).decode("ascii"))

        out_path = out_dir / f"{filename_prefix}_{group_id[:8]}_{shard_idx:02d}.eopx"
        img.save(out_path, format="PNG", pnginfo=info, optimize=False)

        paths.append(out_path)
        manifests.append(shard)

    return ShardPack(group_id=group_id, paths=paths, manifests=manifests)


# ---------------------------------------------------------------------------
# Loading / verifying / reconstructing
# ---------------------------------------------------------------------------

@dataclass
class LoadedShard:
    """A shard parsed from disk, ready for reconstruction."""
    base: EopxManifest
    shard_format_version: str
    group_id: str
    shard_index: int
    shard_k: int
    shard_n: int
    secret_len: int
    recipient_kyber_pk_fp: str
    kem_ciphertext: bytes
    aead_ciphertext: bytes
    path: Path

    def to_shard_manifest(self) -> ShardManifest:
        return ShardManifest(
            base=self.base,
            group_id=self.group_id,
            shard_index=self.shard_index,
            shard_k=self.shard_k,
            shard_n=self.shard_n,
            secret_len=self.secret_len,
            recipient_kyber_pk_fp=self.recipient_kyber_pk_fp,
            kem_ciphertext=self.kem_ciphertext,
            aead_ciphertext=self.aead_ciphertext,
        )


def _read_shard(path: str | Path) -> LoadedShard:
    path = Path(path)
    with Image.open(path) as img:
        img.load()
        info = dict(img.info)
        rgb = img.convert("RGB")
        actual_pixel_hash = hashlib.sha3_512(rgb.tobytes()).hexdigest()

    base = EopxManifest.from_chunks(info)
    if actual_pixel_hash != base.image_sha3_512:
        raise ValueError(f"pixel hash mismatch in {path}")

    def _get(key: str) -> str:
        v = info.get(f"{CHUNK_PREFIX}{key}", "")
        if not v:
            raise ValueError(f"missing required shard chunk: {key}")
        return v

    return LoadedShard(
        base=base,
        shard_format_version=_get("shard_format_version"),
        group_id=_get("shard_group_id"),
        shard_index=int(_get("shard_index")),
        shard_k=int(_get("shard_k")),
        shard_n=int(_get("shard_n")),
        secret_len=int(_get("shard_secret_len")),
        recipient_kyber_pk_fp=_get("shard_recipient_kyber_pk_fp"),
        kem_ciphertext=base64.b64decode(_get("shard_kem_ciphertext_b64")),
        aead_ciphertext=base64.b64decode(_get("shard_aead_ciphertext_b64")),
        path=path,
    )


def verify_shard(path: str | Path) -> Tuple[bool, LoadedShard, list[str]]:
    """Verify a single shard's signature and integrity.

    Returns ``(ok, loaded_shard, errors)``. Reconstruction does not
    require this step (the AEAD tag already authenticates the share),
    but callers should validate each shard's signature when shards are
    collected from untrusted sources.
    """
    errors: list[str] = []
    shard = _read_shard(path)
    sm = shard.to_shard_manifest()

    recomputed = hashlib.sha3_512(sm.canonical_payload()).hexdigest()
    if recomputed != shard.base.payload_hash:
        errors.append("shard payload_hash inconsistent with canonical manifest")
        return False, shard, errors

    pub_only = EopxKey(
        dilithium_pk=shard.base.dilithium_pk,
        kyber_pk=shard.base.kyber_pk or bytes(0),
    )
    if not pub_only.verify(bytes.fromhex(shard.base.payload_hash),
                            shard.base.signature):
        errors.append("Dilithium5 shard signature verification failed")
        return False, shard, errors
    return True, shard, errors


def reconstruct_secret(shard_paths: Sequence[str | Path],
                        recipient_keys: Sequence[EopxKey],
                        ) -> bytes:
    """Decrypt and combine ``k`` shards to recover the original secret.

    Parameters
    ----------
    shard_paths:
        Paths of the shards being combined (at least ``k`` of them, all
        sharing the same ``group_id``).
    recipient_keys:
        Kyber private keys able to decapsulate each shard. The list does
        not need to be in the same order as ``shard_paths`` — the
        decapsulator tries each key against each shard's kem_ct.

    Raises
    ------
    ValueError
        If shards belong to different groups, or if no recipient key can
        decrypt a given shard (AEAD tag failure).
    """
    if not shard_paths:
        raise ValueError("at least one shard path is required")

    loaded = [_read_shard(p) for p in shard_paths]

    group_ids = {sh.group_id for sh in loaded}
    if len(group_ids) != 1:
        raise ValueError(f"shards belong to different groups: {group_ids}")
    group_id = next(iter(group_ids))
    k_values = {sh.shard_k for sh in loaded}
    n_values = {sh.shard_n for sh in loaded}
    secret_lens = {sh.secret_len for sh in loaded}
    if len(k_values) != 1 or len(n_values) != 1 or len(secret_lens) != 1:
        raise ValueError("shards disagree on (k, n, secret_len)")
    k = next(iter(k_values))
    if len(loaded) < k:
        raise ValueError(
            f"need at least k={k} shards, got {len(loaded)}"
        )

    # For each shard, try every recipient key until decryption succeeds.
    shares: List[Tuple[int, bytes]] = []
    for sh in loaded[:k]:
        aad = _shard_associated_data(
            group_id=sh.group_id, shard_index=sh.shard_index,
            shard_k=sh.shard_k, shard_n=sh.shard_n,
            recipient_kyber_pk_fp=sh.recipient_kyber_pk_fp,
        )
        share_plain: Optional[bytes] = None
        last_err: Optional[Exception] = None
        for rk in recipient_keys:
            if rk.kyber_sk is None:
                continue
            # Optimization: skip keys whose pubkey doesn't match the shard's
            # advertised recipient.
            if key_fingerprint(rk.kyber_pk).hex() != sh.recipient_kyber_pk_fp:
                continue
            try:
                share_plain = _decrypt_share(
                    kem_ct=sh.kem_ciphertext,
                    aead_ct=sh.aead_ciphertext,
                    recipient_sk=rk.kyber_sk,
                    group_id=sh.group_id,
                    shard_index=sh.shard_index,
                    associated_data=aad,
                )
                break
            except Exception as exc:  # AEAD tag failure or KEM error
                last_err = exc
                continue
        if share_plain is None:
            raise ValueError(
                f"no recipient key could decrypt shard #{sh.shard_index} "
                f"(group={sh.group_id})"
            ) from last_err
        shares.append((sh.shard_index, share_plain))

    secret = shamir_combine(shares)
    if len(secret) != next(iter(secret_lens)):
        # Should never happen by construction.
        raise ValueError("reconstructed secret has unexpected length")
    return secret
