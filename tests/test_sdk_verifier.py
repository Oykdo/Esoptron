"""Cross-package tests: SDK verifier reads files produced by eopx.format.pack.

These tests intentionally import the SDK directly from
``sdk/python/esoptron`` (not from the main ``eopx.format`` namespace)
to make sure the SDK does NOT depend on anything outside its own
``Pillow + pqcrypto`` envelope.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from PIL import Image

# Make the SDK directory importable as a sibling package.
_SDK_DIR = Path(__file__).resolve().parents[1] / "sdk" / "python"
if str(_SDK_DIR) not in sys.path:
    sys.path.insert(0, str(_SDK_DIR))

# IMPORTANT: import the SDK before importing eopx.format to ensure
# the SDK has no transitive dependency on the main package.
import esoptron as sdk  # noqa: E402

# Packer comes from the main repo (NOT exposed by the SDK).
from eopx.format import EopxKey, pack  # noqa: E402


@pytest.fixture(scope="module")
def signer() -> EopxKey:
    return EopxKey.generate()


@pytest.fixture
def sample_eopx(tmp_path: Path, signer: EopxKey) -> Path:
    img = Image.new("RGB", (32, 32), (200, 100, 50))
    out = tmp_path / "sdk_demo.eopx"
    pack(img, out, signer)
    return out


def test_sdk_module_does_not_import_main_package() -> None:
    # Reach into the loaded SDK module and walk its dependency footprint.
    assert sdk.__package__ == "esoptron"
    assert "eopx" not in sdk.eopx_verify.__dict__.get("__module__", "")
    # The SDK should not have eopx.* in its module path.
    assert not sdk.__name__.startswith("eopx.")


def test_sdk_verifies_packed_file(sample_eopx: Path, signer: EopxKey) -> None:
    res = sdk.verify(sample_eopx)
    assert res.ok is True
    assert res.signature_ok and res.image_hash_ok and res.payload_hash_ok
    assert res.manifest is not None
    assert res.manifest.dilithium_pk_fp == signer.dilithium_pk_fp.hex()


def test_sdk_verifies_with_correct_fingerprint(sample_eopx: Path,
                                                 signer: EopxKey) -> None:
    res = sdk.verify(sample_eopx,
                      expected_dilithium_pk_fp=signer.dilithium_pk_fp.hex())
    assert res.ok is True


def test_sdk_rejects_wrong_fingerprint(sample_eopx: Path) -> None:
    other = EopxKey.generate()
    res = sdk.verify(sample_eopx,
                      expected_dilithium_pk_fp=other.dilithium_pk_fp)
    assert res.ok is False
    assert any("fingerprint mismatch" in e for e in res.errors)


def test_sdk_read_manifest_no_crypto(sample_eopx: Path, signer: EopxKey) -> None:
    m = sdk.read_manifest(sample_eopx)
    assert m.dilithium_pk_fp == signer.dilithium_pk_fp.hex()
    assert len(m.signature) > 0
    assert m.format_version == "1"


def test_sdk_detects_pixel_tampering(sample_eopx: Path, tmp_path: Path) -> None:
    from PIL import PngImagePlugin
    with Image.open(sample_eopx) as im:
        im.load()
        info = dict(im.info)
        rgb = im.convert("RGB")
    rgb.putpixel((5, 5), (0, 0, 0))
    pngi = PngImagePlugin.PngInfo()
    for k, v in info.items():
        if isinstance(v, str):
            pngi.add_text(k, v)
    bad = tmp_path / "bad.eopx"
    rgb.save(bad, format="PNG", pnginfo=pngi)

    res = sdk.verify(bad)
    assert res.ok is False
    assert res.image_hash_ok is False
