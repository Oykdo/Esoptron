"""Tests for the .eopx PNG container: pack, verify, and tampering detection."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

from eopx.format import EopxKey, EopxManifest, pack, read_manifest, verify


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def signer() -> EopxKey:
    return EopxKey.generate()


@pytest.fixture
def sample_image() -> Image.Image:
    return Image.new("RGB", (64, 64), (12, 34, 56))


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def test_keypair_sizes_match_constants(signer: EopxKey) -> None:
    from eopx.format.keys import (
        SIG_PUBLIC_KEY_SIZE, SIG_SECRET_KEY_SIZE,
        KEM_PUBLIC_KEY_SIZE, KEM_SECRET_KEY_SIZE,
    )
    assert len(signer.dilithium_pk) == SIG_PUBLIC_KEY_SIZE
    assert len(signer.dilithium_sk) == SIG_SECRET_KEY_SIZE
    assert len(signer.kyber_pk) == KEM_PUBLIC_KEY_SIZE
    assert len(signer.kyber_sk) == KEM_SECRET_KEY_SIZE


def test_key_save_load_roundtrip(tmp_path: Path, signer: EopxKey) -> None:
    p = signer.save(tmp_path / "kp.json")
    loaded = EopxKey.load(p)
    assert loaded.dilithium_pk == signer.dilithium_pk
    assert loaded.dilithium_sk == signer.dilithium_sk
    assert loaded.kyber_pk == signer.kyber_pk
    assert loaded.kyber_sk == signer.kyber_sk


def test_public_only_strips_secrets(signer: EopxKey) -> None:
    pub = signer.public_only()
    assert pub.dilithium_sk is None
    assert pub.kyber_sk is None
    assert pub.has_secrets is False
    assert pub.dilithium_pk == signer.dilithium_pk


def test_sign_verify_roundtrip(signer: EopxKey) -> None:
    sig = signer.sign(b"hello world")
    assert signer.verify(b"hello world", sig)
    assert not signer.verify(b"hello world!", sig)


def test_kem_roundtrip(signer: EopxKey) -> None:
    ct, ss1 = signer.kem_encapsulate()
    ss2 = signer.kem_decapsulate(ct)
    assert ss1 == ss2


# ---------------------------------------------------------------------------
# Pack / verify
# ---------------------------------------------------------------------------

def test_pack_writes_a_valid_eopx(tmp_path: Path, sample_image: Image.Image,
                                    signer: EopxKey) -> None:
    out = tmp_path / "vault.eopx"
    manifest = pack(sample_image, out, signer)
    assert out.is_file()
    assert manifest.payload_hash
    assert manifest.signature
    assert len(manifest.vault_id) == 32

    # Re-open as a regular PNG and confirm chunks are present
    with Image.open(out) as im:
        info = dict(im.info)
    assert "eopx:format_version" in info
    assert info["eopx:format_version"] == "1"
    assert "eopx:sig_dilithium5_b64" in info


def test_verify_accepts_a_fresh_eopx(tmp_path: Path, sample_image: Image.Image,
                                       signer: EopxKey) -> None:
    out = tmp_path / "vault.eopx"
    pack(sample_image, out, signer)
    res = verify(out)
    assert res.ok is True
    assert res.chunks_ok and res.image_hash_ok
    assert res.payload_hash_ok and res.signature_ok
    assert not res.errors


def test_verify_accepts_with_correct_fingerprint(tmp_path: Path,
                                                   sample_image: Image.Image,
                                                   signer: EopxKey) -> None:
    out = tmp_path / "vault.eopx"
    pack(sample_image, out, signer)
    res = verify(out, expected_dilithium_pk_fp=signer.dilithium_pk_fp)
    assert res.ok is True


def test_verify_rejects_with_wrong_fingerprint(tmp_path: Path,
                                                 sample_image: Image.Image,
                                                 signer: EopxKey) -> None:
    out = tmp_path / "vault.eopx"
    pack(sample_image, out, signer)
    other = EopxKey.generate()
    res = verify(out, expected_dilithium_pk_fp=other.dilithium_pk_fp)
    assert res.ok is False
    assert any("fingerprint mismatch" in e for e in res.errors)


def test_read_manifest_does_not_verify(tmp_path: Path,
                                         sample_image: Image.Image,
                                         signer: EopxKey) -> None:
    out = tmp_path / "vault.eopx"
    expected = pack(sample_image, out, signer)
    parsed = read_manifest(out)
    assert parsed.vault_id == expected.vault_id
    assert parsed.payload_hash == expected.payload_hash
    assert parsed.signature == expected.signature


def test_pack_with_vault_id_and_merkle_root(tmp_path: Path,
                                              sample_image: Image.Image,
                                              signer: EopxKey) -> None:
    custom_id = "deadbeef" * 4
    custom_root = bytes(range(32))
    out = tmp_path / "vault.eopx"
    manifest = pack(sample_image, out, signer,
                    vault_id=custom_id, merkle_root=custom_root)
    assert manifest.vault_id == custom_id
    assert manifest.merkle_root == custom_root.hex()
    res = verify(out)
    assert res.ok


def test_pack_cli_generates_private_metatron_eopx(tmp_path: Path,
                                                   signer: EopxKey) -> None:
    from scripts.eopx_pack import main as pack_main

    key_path = signer.save(tmp_path / "signer.json")
    out = tmp_path / "private_cube.eopx"

    rc = pack_main([
        "eopx_pack",
        "--seed", "11" * 32,
        "--role", "private",
        "--key", str(key_path),
        "--out", str(out),
    ])

    assert rc == 0
    res = verify(out)
    assert res.ok


# ---------------------------------------------------------------------------
# Tampering detection
# ---------------------------------------------------------------------------

def _rewrite_with_modified_chunk(src: Path, dst: Path, key: str, value: str) -> None:
    """Re-encode a PNG, replacing one tEXt chunk's value."""
    with Image.open(src) as im:
        im.load()
        info = dict(im.info)
        rgb = im.convert("RGB")
    info[key] = value
    pngi = PngImagePlugin.PngInfo()
    for k, v in info.items():
        if isinstance(v, str):
            pngi.add_text(k, v)
    rgb.save(dst, format="PNG", pnginfo=pngi)


def test_verify_detects_modified_metadata_chunk(tmp_path: Path,
                                                  sample_image: Image.Image,
                                                  signer: EopxKey) -> None:
    src = tmp_path / "ok.eopx"
    pack(sample_image, src, signer)
    bad = tmp_path / "bad_vault_id.eopx"
    _rewrite_with_modified_chunk(src, bad,
                                  "eopx:vault_id", "00" * 16)
    res = verify(bad)
    assert res.ok is False
    # The bad vault_id changes canonical_payload but payload_hash chunk
    # is unchanged → mismatch caught at payload_hash_ok stage.
    assert res.payload_hash_ok is False


def test_verify_detects_pixel_tampering(tmp_path: Path,
                                          sample_image: Image.Image,
                                          signer: EopxKey) -> None:
    src = tmp_path / "ok.eopx"
    pack(sample_image, src, signer)

    # Re-open, paint a single pixel red, keep the original chunks,
    # then write back. The image_sha3_512 in the manifest now lies.
    with Image.open(src) as im:
        im.load()
        info = dict(im.info)
        rgb = im.convert("RGB")
    rgb.putpixel((0, 0), (255, 0, 0))
    pngi = PngImagePlugin.PngInfo()
    for k, v in info.items():
        if isinstance(v, str):
            pngi.add_text(k, v)
    bad = tmp_path / "bad_pixel.eopx"
    rgb.save(bad, format="PNG", pnginfo=pngi)

    res = verify(bad)
    assert res.ok is False
    assert res.image_hash_ok is False


def test_verify_detects_forged_signature(tmp_path: Path,
                                           sample_image: Image.Image,
                                           signer: EopxKey) -> None:
    src = tmp_path / "ok.eopx"
    pack(sample_image, src, signer)

    # Flip one byte inside the base64-encoded signature
    with Image.open(src) as im:
        im.load()
        info = dict(im.info)
        rgb = im.convert("RGB")
    sig_b64 = info["eopx:sig_dilithium5_b64"]
    raw = bytearray(base64.b64decode(sig_b64))
    raw[100] ^= 0xFF
    info["eopx:sig_dilithium5_b64"] = base64.b64encode(bytes(raw)).decode("ascii")

    pngi = PngImagePlugin.PngInfo()
    for k, v in info.items():
        if isinstance(v, str):
            pngi.add_text(k, v)
    bad = tmp_path / "bad_sig.eopx"
    rgb.save(bad, format="PNG", pnginfo=pngi)

    res = verify(bad)
    assert res.ok is False
    assert res.signature_ok is False


# ---------------------------------------------------------------------------
# Re-encoding tolerance
# ---------------------------------------------------------------------------

def test_verify_survives_lossless_png_reencode(tmp_path: Path,
                                                 sample_image: Image.Image,
                                                 signer: EopxKey) -> None:
    src = tmp_path / "ok.eopx"
    pack(sample_image, src, signer)

    # Re-encode the PNG with different optimization settings — pixels are
    # identical so image_sha3_512 must still match.
    with Image.open(src) as im:
        im.load()
        info = dict(im.info)
        rgb = im.convert("RGB")
    pngi = PngImagePlugin.PngInfo()
    for k, v in info.items():
        if isinstance(v, str):
            pngi.add_text(k, v)
    reencoded = tmp_path / "reencoded.eopx"
    rgb.save(reencoded, format="PNG", pnginfo=pngi, optimize=True, compress_level=9)

    res = verify(reencoded)
    assert res.ok is True
