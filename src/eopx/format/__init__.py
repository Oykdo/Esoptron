"""Esoptron .eopx container format.

A ``.eopx`` is a regular PNG image whose ``tEXt`` chunks carry a
self-contained, post-quantum-signed manifest. The pixels are typically
a Metatron cube produced by :mod:`eopx.metatron`, but the format is
agnostic to the image content: any PNG can be wrapped.

Public API
----------
* :func:`pack` — produce a signed ``.eopx`` from a PIL image + metadata.
* :func:`verify` — read and validate a ``.eopx``; returns a structured
  :class:`VerificationResult` (never raises on tamper, sets a flag).
* :class:`EopxKey` — Dilithium5 / Kyber1024 keypair management.

Wire format
-----------
The following ``tEXt`` chunks are written, in this order:

============================  ===================================================
Key                           Value
============================  ===================================================
``eopx:format_version``       ``"1"``
``eopx:vault_id``             hex (16 bytes UUID)
``eopx:merkle_root``          hex (32 bytes, optional, zeros if absent)
``eopx:kyber_pk_fp``          hex SHA3-256(kyber_pk) (32 bytes), optional
``eopx:dilithium_pk_b64``     base64 (2592 bytes) — signer's ML-DSA-87 pubkey
``eopx:dilithium_pk_fp``      hex SHA3-256(dilithium_pk) (32 bytes)
``eopx:timestamp_utc``        ISO-8601 ``YYYY-MM-DDTHH:MM:SSZ``
``eopx:image_sha3_512``       hex of SHA3-512 over raw RGB pixel bytes
``eopx:payload_hash``         hex SHA3-512 of the canonical manifest payload
``eopx:sig_dilithium5_b64``   base64 ML-DSA-87 signature over ``payload_hash``
============================  ===================================================

Determinism: ``image_sha3_512`` is computed on the *decoded* RGB pixel
buffer (``PIL.Image.tobytes()``), so re-encoding the PNG (different
compression level, optimization, etc.) does not break the signature
as long as no pixel changes.
"""

from .keys import EopxKey, key_fingerprint
from .eopx_format import (
    EopxManifest,
    VerificationResult,
    pack,
    verify,
    read_manifest,
)
from .shamir import shamir_split, shamir_combine
from .visual_sharding import (
    ShardPack,
    ShardManifest,
    LoadedShard,
    shard_secret,
    reconstruct_secret,
    verify_shard,
)
from .secure_bytes import Secret, wipe_bytearrays

__all__ = [
    "EopxKey",
    "key_fingerprint",
    "EopxManifest",
    "VerificationResult",
    "pack",
    "verify",
    "read_manifest",
    "shamir_split",
    "shamir_combine",
    "ShardPack",
    "ShardManifest",
    "LoadedShard",
    "shard_secret",
    "reconstruct_secret",
    "verify_shard",
    "Secret",
    "wipe_bytearrays",
]
