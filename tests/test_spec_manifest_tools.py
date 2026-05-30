"""Tests for ``tools/sign_spec.py`` and ``tools/verify_spec.py``.

Covers:
  * normalisation invariants (BOM/CRLF/trailing-ws/missing-final-LF)
  * round-trip sign + verify
  * tamper detection (1-byte mutation)
  * --all bulk operation
  * Dilithium-5 signature mode (forge-resistance)
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import sign_spec  # noqa: E402
import verify_spec  # noqa: E402

from eopx.format.keys import EopxKey  # noqa: E402


# ---------------------------------------------------------------------------
# Test sandbox: copy a real doc into a tmp dir + give it its own manifest
# ---------------------------------------------------------------------------

@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Create an isolated repo-shape directory with one tiny spec."""
    spec_dir = tmp_path / "docs" / "specs"
    spec_dir.mkdir(parents=True)
    doc = spec_dir / "EPX-test.md"
    doc.write_bytes(b"# Test\n\nSample document.\n")

    # Point both modules at our temp root.
    monkeypatch.setattr(sign_spec, "ROOT", tmp_path)
    monkeypatch.setattr(sign_spec, "MANIFEST", tmp_path / "SPECS.SHA3-256")
    monkeypatch.setattr(verify_spec, "ROOT", tmp_path)
    monkeypatch.setattr(verify_spec, "MANIFEST", tmp_path / "SPECS.SHA3-256")
    return tmp_path, doc


# ---------------------------------------------------------------------------
# normalise_bytes — the heart of the system
# ---------------------------------------------------------------------------

class TestNormalisation:
    def test_strip_bom(self):
        a = sign_spec.normalise_bytes(b"\xef\xbb\xbfhello\n")
        b = sign_spec.normalise_bytes(b"hello\n")
        assert a == b

    def test_crlf_equivalent_to_lf(self):
        a = sign_spec.normalise_bytes(b"a\r\nb\r\nc\n")
        b = sign_spec.normalise_bytes(b"a\nb\nc\n")
        assert a == b

    def test_lone_cr_equivalent_to_lf(self):
        a = sign_spec.normalise_bytes(b"a\rb\rc")
        b = sign_spec.normalise_bytes(b"a\nb\nc\n")
        assert a == b

    def test_trailing_ws_stripped_per_line(self):
        a = sign_spec.normalise_bytes(b"hello   \nworld\t\t\n")
        b = sign_spec.normalise_bytes(b"hello\nworld\n")
        assert a == b

    def test_missing_final_newline_added(self):
        a = sign_spec.normalise_bytes(b"hello")
        b = sign_spec.normalise_bytes(b"hello\n")
        assert a == b
        # And the normalised form does end with a LF.
        assert a.endswith(b"\n")

    def test_multiple_trailing_newlines_collapsed_to_one(self):
        a = sign_spec.normalise_bytes(b"hello\n\n\n\n")
        b = sign_spec.normalise_bytes(b"hello\n")
        assert a == b

    def test_nfc_applied(self):
        # "é" can be one codepoint (NFC) or two (NFD). Normalisation
        # collapses both into NFC.
        nfc = "résumé\n".encode("utf-8")
        nfd = ("re\u0301sume\u0301\n").encode("utf-8")
        assert sign_spec.normalise_bytes(nfc) == sign_spec.normalise_bytes(nfd)

    def test_invalid_utf8_rejected(self):
        with pytest.raises(UnicodeDecodeError):
            sign_spec.normalise_bytes(b"\xff\xfe\x00\x00 bogus")


# ---------------------------------------------------------------------------
# Sign + verify round-trip via the in-process modules
# ---------------------------------------------------------------------------

def _run(*args, expect_ok=True):
    """Invoke a CLI module's main() with sys.argv patching."""
    mod, *cli = args
    cli = [str(a) for a in cli]
    old = sys.argv[:]
    sys.argv = [mod.__name__] + cli
    try:
        rc = mod.main()
    finally:
        sys.argv = old
    if expect_ok:
        assert rc == 0, f"expected success, got rc={rc}"
    return rc


class TestSignVerifyRoundtrip:
    def test_basic_roundtrip(self, sandbox):
        root, doc = sandbox
        _run(sign_spec, doc, "--author", "Test", "--timestamp", "2026-01-01T00:00:00Z")
        _run(verify_spec, doc)

    def test_verify_detects_one_byte_tamper(self, sandbox):
        root, doc = sandbox
        _run(sign_spec, doc, "--author", "Test", "--timestamp", "2026-01-01T00:00:00Z")
        # Mutate one byte of the document.
        raw = doc.read_bytes()
        doc.write_bytes(raw[:5] + b"X" + raw[6:])
        rc = _run(verify_spec, doc, expect_ok=False)
        assert rc == 1

    def test_verify_ignores_line_ending_changes(self, sandbox):
        root, doc = sandbox
        _run(sign_spec, doc, "--author", "Test", "--timestamp", "2026-01-01T00:00:00Z")
        # CRLF re-save should not invalidate the hash, thanks to internal
        # normalisation.
        raw = doc.read_bytes()
        doc.write_bytes(raw.replace(b"\n", b"\r\n"))
        _run(verify_spec, doc)

    def test_verify_ignores_bom_addition(self, sandbox):
        root, doc = sandbox
        _run(sign_spec, doc, "--author", "Test", "--timestamp", "2026-01-01T00:00:00Z")
        doc.write_bytes(b"\xef\xbb\xbf" + doc.read_bytes())
        _run(verify_spec, doc)

    def test_verify_ignores_trailing_ws(self, sandbox):
        root, doc = sandbox
        _run(sign_spec, doc, "--author", "Test", "--timestamp", "2026-01-01T00:00:00Z")
        text = doc.read_text(encoding="utf-8")
        doc.write_bytes(text.replace("\n", "   \n").encode("utf-8"))
        _run(verify_spec, doc)


# ---------------------------------------------------------------------------
# Manifest semantics
# ---------------------------------------------------------------------------

class TestManifest:
    def test_manifest_contains_normalised_sizes(self, sandbox):
        root, doc = sandbox
        _run(sign_spec, doc, "--author", "Test", "--timestamp", "2026-01-01T00:00:00Z")
        manifest = (root / "SPECS.SHA3-256").read_text(encoding="utf-8")
        assert "bytes-raw:" in manifest
        assert "bytes-normalised:" in manifest
        assert "normalisation:" in manifest
        assert sign_spec.NORMALISATION_ID in manifest

    def test_resign_replaces_record_in_place(self, sandbox):
        root, doc = sandbox
        _run(sign_spec, doc, "--author", "A", "--timestamp", "2026-01-01T00:00:00Z")
        _run(sign_spec, doc, "--author", "B", "--timestamp", "2026-01-02T00:00:00Z")
        blocks = sign_spec._parse(
            (root / "SPECS.SHA3-256").read_text(encoding="utf-8")
        )
        # Only one record for the same path.
        matching = [b for b in blocks if b["spec"] == "docs/specs/EPX-test.md"]
        assert len(matching) == 1
        assert matching[0]["author"] == "B"
        assert matching[0]["timestamp"] == "2026-01-02T00:00:00Z"

    def test_scan_picks_up_known_docs(self, sandbox, monkeypatch):
        root, doc = sandbox
        # Inject our test doc into KNOWN_DOCS for the scan run.
        monkeypatch.setattr(sign_spec, "KNOWN_DOCS",
                            ("docs/specs/EPX-test.md",))
        _run(sign_spec, "--scan", "--author", "Test",
             "--timestamp", "2026-01-01T00:00:00Z")
        blocks = sign_spec._parse(
            (root / "SPECS.SHA3-256").read_text(encoding="utf-8")
        )
        assert any(b["spec"] == "docs/specs/EPX-test.md" for b in blocks)

    def test_all_refreshes_every_record(self, sandbox):
        root, doc = sandbox
        # Add a second spec.
        doc2 = root / "docs" / "specs" / "EPX-other.md"
        doc2.write_bytes(b"# Other\n")
        _run(sign_spec, doc, "--author", "T", "--timestamp", "2026-01-01T00:00:00Z")
        _run(sign_spec, doc2, "--author", "T", "--timestamp", "2026-01-01T00:00:00Z")
        # Now mutate one and run --all.
        doc.write_bytes(b"# Mutated\n")
        _run(sign_spec, "--all", "--author", "T",
             "--timestamp", "2026-02-01T00:00:00Z")
        _run(verify_spec, "--all")

    def test_manifest_has_no_crlf(self, sandbox):
        root, doc = sandbox
        _run(sign_spec, doc, "--author", "T",
             "--timestamp", "2026-01-01T00:00:00Z")
        raw = (root / "SPECS.SHA3-256").read_bytes()
        assert b"\r\n" not in raw, "manifest must be LF-only on every platform"


# ---------------------------------------------------------------------------
# Signature mode (Dilithium-5)
# ---------------------------------------------------------------------------

@pytest.fixture
def deployment_key_file(tmp_path):
    key = EopxKey.generate()
    p = tmp_path / "key.json"
    key.save(p)
    return p, key


class TestSignatureMode:
    def test_sign_with_key_emits_signature_field(
            self, sandbox, deployment_key_file):
        root, doc = sandbox
        key_path, _ = deployment_key_file
        _run(sign_spec, doc, "--author", "T", "--key", key_path,
             "--timestamp", "2026-01-01T00:00:00Z")
        manifest = (root / "SPECS.SHA3-256").read_text(encoding="utf-8")
        # The manifest uses padded keys; parse to be format-agnostic.
        blocks = sign_spec._parse(manifest)
        assert len(blocks) == 1
        rec = blocks[0]
        assert rec["signature"].startswith("dilithium5:")
        assert rec["signer-pk-fp"].startswith("sha3-256:")

    def test_verify_with_correct_pk_succeeds(
            self, sandbox, deployment_key_file):
        root, doc = sandbox
        key_path, key = deployment_key_file
        _run(sign_spec, doc, "--author", "T", "--key", key_path,
             "--timestamp", "2026-01-01T00:00:00Z")
        _run(verify_spec, doc, "--pk-hex", key.dilithium_pk.hex())

    def test_verify_with_wrong_pk_fails(self, sandbox, deployment_key_file):
        root, doc = sandbox
        key_path, _ = deployment_key_file
        _run(sign_spec, doc, "--author", "T", "--key", key_path,
             "--timestamp", "2026-01-01T00:00:00Z")
        other = EopxKey.generate()
        rc = _run(verify_spec, doc, "--pk-hex", other.dilithium_pk.hex(),
                  expect_ok=False)
        assert rc == 1
