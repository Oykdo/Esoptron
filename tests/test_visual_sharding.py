"""End-to-end visual sharding: split → write .eopx shards → reconstruct."""

from __future__ import annotations

import base64
import itertools
import secrets as _secrets
from pathlib import Path
from typing import List

import pytest
from PIL import Image, PngImagePlugin

from eopx.format import (
    EopxKey,
    shard_secret,
    reconstruct_secret,
    verify_shard,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def signer() -> EopxKey:
    return EopxKey.generate()


def _recipients(n: int) -> List[EopxKey]:
    return [EopxKey.generate() for _ in range(n)]


# ---------------------------------------------------------------------------
# Roundtrips
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("k,n", [(2, 3), (3, 5), (1, 1), (4, 7)])
def test_full_roundtrip(tmp_path: Path, signer: EopxKey, k: int, n: int) -> None:
    secret = _secrets.token_bytes(32)
    recipients = _recipients(n)
    pack = shard_secret(
        secret=secret, k=k,
        recipient_kyber_pks=[r.kyber_pk for r in recipients],
        signer=signer, out_dir=tmp_path,
    )
    assert len(pack.paths) == n
    for p in pack.paths:
        assert p.is_file()
        assert p.suffix == ".eopx"

    recovered = reconstruct_secret(pack.paths[:k], recipients)
    assert recovered == secret


def test_any_k_subset_recovers(tmp_path: Path, signer: EopxKey) -> None:
    secret = b"\xaa" * 48
    k, n = 3, 5
    recipients = _recipients(n)
    pack = shard_secret(
        secret=secret, k=k,
        recipient_kyber_pks=[r.kyber_pk for r in recipients],
        signer=signer, out_dir=tmp_path,
    )
    # All C(n, k) subsets reconstruct the same secret
    for subset_idx in itertools.combinations(range(n), k):
        paths = [pack.paths[i] for i in subset_idx]
        keys = [recipients[i] for i in subset_idx]
        assert reconstruct_secret(paths, keys) == secret


def test_each_shard_verifies(tmp_path: Path, signer: EopxKey) -> None:
    secret = _secrets.token_bytes(16)
    recipients = _recipients(3)
    pack = shard_secret(
        secret=secret, k=2,
        recipient_kyber_pks=[r.kyber_pk for r in recipients],
        signer=signer, out_dir=tmp_path,
    )
    for path in pack.paths:
        ok, _shard, errors = verify_shard(path)
        assert ok, f"shard {path} failed: {errors}"


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

def test_reconstruct_rejects_wrong_recipient(tmp_path: Path,
                                              signer: EopxKey) -> None:
    secret = b"my-secret-data-here-12345678901234"
    recipients = _recipients(3)
    pack = shard_secret(
        secret=secret, k=2,
        recipient_kyber_pks=[r.kyber_pk for r in recipients],
        signer=signer, out_dir=tmp_path,
    )
    # Provide unrelated recipient keys
    wrong_recipients = _recipients(3)
    with pytest.raises(ValueError, match="no recipient key could decrypt"):
        reconstruct_secret(pack.paths[:2], wrong_recipients)


def test_reconstruct_below_threshold_yields_wrong_secret(tmp_path: Path,
                                                          signer: EopxKey) -> None:
    secret = b"this is the real secret data!!!!"
    k, n = 3, 5
    recipients = _recipients(n)
    pack = shard_secret(
        secret=secret, k=k,
        recipient_kyber_pks=[r.kyber_pk for r in recipients],
        signer=signer, out_dir=tmp_path,
    )
    # k-1 shards: ValueError (we have a threshold check)
    with pytest.raises(ValueError, match=f"need at least k={k}"):
        reconstruct_secret(pack.paths[:k - 1], recipients)


def test_tampered_aead_chunk_fails_decryption(tmp_path: Path,
                                                signer: EopxKey) -> None:
    secret = b"sensitive content right here ok!"
    recipients = _recipients(3)
    pack = shard_secret(
        secret=secret, k=2,
        recipient_kyber_pks=[r.kyber_pk for r in recipients],
        signer=signer, out_dir=tmp_path,
    )
    # Tamper with shard #1's AEAD ciphertext
    p = pack.paths[0]
    with Image.open(p) as img:
        img.load()
        info = dict(img.info)
        rgb = img.convert("RGB")
    raw = bytearray(base64.b64decode(info["eopx:shard_aead_ciphertext_b64"]))
    raw[0] ^= 0xFF
    info["eopx:shard_aead_ciphertext_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    pngi = PngImagePlugin.PngInfo()
    for k_, v in info.items():
        if isinstance(v, str):
            pngi.add_text(k_, v)
    bad = tmp_path / "shard_bad.eopx"
    rgb.save(bad, format="PNG", pnginfo=pngi)

    # Verification of THIS shard fails (signature covers AEAD hash)
    ok, _shard, errors = verify_shard(bad)
    assert ok is False
    assert errors


def test_reconstruct_rejects_mixed_groups(tmp_path: Path,
                                            signer: EopxKey) -> None:
    secret_a = b"AAA" * 10
    secret_b = b"BBB" * 10
    recipients = _recipients(3)
    pks = [r.kyber_pk for r in recipients]
    pack_a = shard_secret(secret=secret_a, k=2,
                           recipient_kyber_pks=pks,
                           signer=signer, out_dir=tmp_path / "A")
    pack_b = shard_secret(secret=secret_b, k=2,
                           recipient_kyber_pks=pks,
                           signer=signer, out_dir=tmp_path / "B")
    mixed = [pack_a.paths[0], pack_b.paths[1]]
    with pytest.raises(ValueError, match="different groups"):
        reconstruct_secret(mixed, recipients)
