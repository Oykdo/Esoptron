"""Systematic tampering tests for the ``.eopx`` container.

For every mutable byte source (image pixels, each ``tEXt`` chunk), assert
that flipping a single byte breaks ``verify()`` with a recognisable error.
This is a defense-in-depth complement to the per-step sanity checks in
``test_eopx_format.py``.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

from eopx.format import EopxKey, pack, verify
from eopx.format.eopx_format import CHUNK_PREFIX
from eopx.format.keys import key_fingerprint


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def signer() -> EopxKey:
    return EopxKey.generate()


@pytest.fixture
def packed(tmp_path: Path, signer: EopxKey) -> Path:
    img = Image.new("RGB", (32, 32), (50, 100, 150))
    out = tmp_path / "vault.eopx"
    pack(img, out, signer)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_chunks(path: Path) -> dict:
    with Image.open(path) as img:
        img.load()
        return dict(img.info), img.convert("RGB")


def _rewrite_with_chunks(src: Path, dst: Path, chunks: dict,
                          rgb: Image.Image) -> None:
    info = PngImagePlugin.PngInfo()
    for k, v in chunks.items():
        info.add_text(k, v)
    rgb.save(dst, format="PNG", pnginfo=info, optimize=False)


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def test_baseline_passes(packed: Path) -> None:
    res = verify(packed)
    assert res.ok, res.errors


# ---------------------------------------------------------------------------
# Pixel tampering
# ---------------------------------------------------------------------------

def test_pixel_tampering_breaks_image_hash(tmp_path: Path,
                                            packed: Path) -> None:
    chunks, rgb = _read_chunks(packed)
    # Flip one pixel
    arr = bytearray(rgb.tobytes())
    arr[0] ^= 0x01
    tampered = Image.frombytes("RGB", rgb.size, bytes(arr))
    out = tmp_path / "tampered_pixel.eopx"
    _rewrite_with_chunks(packed, out, chunks, tampered)

    res = verify(out)
    assert not res.ok
    assert any("image" in e for e in res.errors)


# ---------------------------------------------------------------------------
# Chunk-by-chunk tampering — every required chunk must be covered by
# either an explicit consistency check or the signature.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("chunk_key", [
    "format_version",
    "vault_id",
    "merkle_root",
    "timestamp_utc",
    "image_sha3_512",
    "payload_hash",
])
def test_string_chunk_tamper_breaks_verify(tmp_path: Path, packed: Path,
                                            chunk_key: str) -> None:
    chunks, rgb = _read_chunks(packed)
    full_key = f"{CHUNK_PREFIX}{chunk_key}"
    original = chunks[full_key]
    # Mutate by flipping the first character (within the printable ASCII
    # range used by these chunks).
    if not original:
        pytest.skip(f"chunk {chunk_key} is empty in this build")
    flipped = ("X" if original[0] != "X" else "Y") + original[1:]
    chunks[full_key] = flipped
    out = tmp_path / f"tamper_{chunk_key}.eopx"
    _rewrite_with_chunks(packed, out, chunks, rgb)

    res = verify(out)
    assert not res.ok, (
        f"verify accepted a tampered {chunk_key} chunk: {res.errors}"
    )


def test_signature_tamper_breaks_verify(tmp_path: Path,
                                         packed: Path) -> None:
    chunks, rgb = _read_chunks(packed)
    key = f"{CHUNK_PREFIX}sig_dilithium5_b64"
    sig = base64.b64decode(chunks[key])
    tampered = bytearray(sig)
    tampered[0] ^= 0x01
    chunks[key] = base64.b64encode(bytes(tampered)).decode("ascii")
    out = tmp_path / "tamper_sig.eopx"
    _rewrite_with_chunks(packed, out, chunks, rgb)

    res = verify(out)
    assert not res.ok
    assert any("ignature" in e or "signature" in e for e in res.errors)


def test_dilithium_pk_substitution_caught(tmp_path: Path,
                                           packed: Path,
                                           signer: EopxKey) -> None:
    """If an attacker swaps the embedded pubkey for another valid Dilithium
    key (without re-signing), verify() must catch it via the
    ``dilithium_pk_fp`` consistency check OR the signature check."""
    chunks, rgb = _read_chunks(packed)
    other = EopxKey.generate()
    chunks[f"{CHUNK_PREFIX}dilithium_pk_b64"] = base64.b64encode(
        other.dilithium_pk).decode("ascii")
    # Note: we intentionally leave dilithium_pk_fp pointing at the OLD key
    # to exercise the alignment check.
    out = tmp_path / "tamper_pk.eopx"
    _rewrite_with_chunks(packed, out, chunks, rgb)

    res = verify(out)
    assert not res.ok
    # Either the new consistency check fires, or the signature check fires.
    msg = " | ".join(res.errors)
    assert (
        "dilithium_pk_fp" in msg
        or "manifest parse failed" in msg
        or "ignature" in msg
    )


def test_kyber_pk_substitution_caught(tmp_path: Path,
                                       packed: Path) -> None:
    """Swap embedded Kyber pubkey: the embedded fingerprint chunk must
    flag the inconsistency before signature verification even runs."""
    chunks, rgb = _read_chunks(packed)
    other = EopxKey.generate()
    chunks[f"{CHUNK_PREFIX}kyber_pk_b64"] = base64.b64encode(
        other.kyber_pk).decode("ascii")
    out = tmp_path / "tamper_kyber.eopx"
    _rewrite_with_chunks(packed, out, chunks, rgb)

    res = verify(out)
    assert not res.ok
    msg = " | ".join(res.errors)
    assert "kyber_pk_fp" in msg or "manifest parse failed" in msg


def test_expected_fingerprint_mismatch_caught(packed: Path,
                                                signer: EopxKey) -> None:
    bogus = bytes(32).hex()
    res = verify(packed, expected_dilithium_pk_fp=bogus)
    assert not res.ok
    assert any("fingerprint mismatch" in e for e in res.errors)


def test_expected_fingerprint_match_accepted(packed: Path,
                                               signer: EopxKey) -> None:
    fp = key_fingerprint(signer.dilithium_pk).hex()
    res = verify(packed, expected_dilithium_pk_fp=fp)
    assert res.ok, res.errors
