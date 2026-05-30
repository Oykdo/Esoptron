"""Tests for ``tools/check_encoding.py``.

Confirms the encoding gatekeeper detects (and optionally fixes):
  * UTF-8 BOM
  * CRLF line endings
  * Non-UTF-8 byte sequences (cp1252 mojibake)
And tolerates:
  * Clean LF UTF-8
  * CRLF in explicit allow-list (.ps1/.bat/.cmd)
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_encoding  # noqa: E402


# ---------------------------------------------------------------------------
# _check_file (unit)
# ---------------------------------------------------------------------------

class TestCheckFileUnit:
    def test_clean_lf_utf8_passes(self, tmp_path):
        p = tmp_path / "clean.py"
        p.write_bytes(b"print('hello')\n")
        assert check_encoding._check_file(p, fix=False) == []

    def test_bom_detected(self, tmp_path):
        p = tmp_path / "bommed.py"
        p.write_bytes(b"\xef\xbb\xbfprint('hi')\n")
        issues = check_encoding._check_file(p, fix=False)
        assert any("BOM" in i for i in issues)

    def test_crlf_detected(self, tmp_path):
        p = tmp_path / "crlf.py"
        p.write_bytes(b"a = 1\r\nb = 2\r\n")
        issues = check_encoding._check_file(p, fix=False)
        assert any("CRLF" in i for i in issues)

    def test_crlf_allowed_for_ps1(self, tmp_path):
        p = tmp_path / "script.ps1"
        p.write_bytes(b"Write-Host hi\r\n")
        assert check_encoding._check_file(p, fix=False) == []

    def test_invalid_utf8_detected(self, tmp_path):
        p = tmp_path / "bad.md"
        # cp1252 "é" = 0xE9 — invalid as standalone UTF-8.
        p.write_bytes(b"Hello J\xe9r\xe9my\n")
        issues = check_encoding._check_file(p, fix=False)
        assert any("UTF-8" in i for i in issues)

    def test_fix_strips_bom(self, tmp_path):
        p = tmp_path / "bom.py"
        p.write_bytes(b"\xef\xbb\xbfprint('hi')\n")
        issues = check_encoding._check_file(p, fix=True)
        assert "[FIXED]" in issues
        assert p.read_bytes() == b"print('hi')\n"

    def test_fix_normalises_crlf(self, tmp_path):
        p = tmp_path / "crlf.md"
        p.write_bytes(b"# Title\r\n\r\nBody\r\n")
        issues = check_encoding._check_file(p, fix=True)
        assert "[FIXED]" in issues
        assert b"\r\n" not in p.read_bytes()
        assert p.read_bytes() == b"# Title\n\nBody\n"

    def test_fix_does_not_touch_clean_file(self, tmp_path):
        p = tmp_path / "clean.py"
        original = b"x = 1\n"
        p.write_bytes(original)
        check_encoding._check_file(p, fix=True)
        assert p.read_bytes() == original

    def test_fix_cannot_repair_invalid_utf8(self, tmp_path):
        """cp1252 bytes can't be safely auto-converted; we just report."""
        p = tmp_path / "bad.md"
        original = b"J\xe9r\xe9my\n"
        p.write_bytes(original)
        issues = check_encoding._check_file(p, fix=True)
        # File contents unchanged; the issue is still reported.
        assert any("UTF-8" in i for i in issues)
        assert p.read_bytes() == original


# ---------------------------------------------------------------------------
# main() integration
# ---------------------------------------------------------------------------

def _run_main(argv, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["check_encoding"] + list(argv))
    return check_encoding.main(), capsys.readouterr()


class TestMain:
    def test_explicit_clean_file(self, tmp_path, monkeypatch, capsys):
        p = tmp_path / "ok.md"
        p.write_bytes(b"# hi\n")
        rc, captured = _run_main([str(p)], monkeypatch, capsys)
        assert rc == 0
        assert "OK:" in captured.out

    def test_explicit_bommed_file(self, tmp_path, monkeypatch, capsys):
        p = tmp_path / "ng.md"
        p.write_bytes(b"\xef\xbb\xbf# hi\n")
        rc, captured = _run_main([str(p)], monkeypatch, capsys)
        assert rc == 1
        assert "BOM" in captured.err

    def test_fix_flag_repairs_and_succeeds(self, tmp_path, monkeypatch, capsys):
        p = tmp_path / "ng.md"
        p.write_bytes(b"\xef\xbb\xbf# hi\r\n")
        rc, captured = _run_main(["--fix", str(p)], monkeypatch, capsys)
        assert rc == 0
        assert p.read_bytes() == b"# hi\n"
        assert "fixed:" in captured.out

    def test_repo_scan_returns_zero(self, monkeypatch, capsys):
        """The real repo should be clean when this test suite runs."""
        rc, captured = _run_main([], monkeypatch, capsys)
        assert rc == 0, f"repo scan failed: {captured.err}"


# ---------------------------------------------------------------------------
# _iter_text_files
# ---------------------------------------------------------------------------

class TestIterTextFiles:
    def test_picks_up_known_suffixes(self, tmp_path):
        (tmp_path / "a.py").write_bytes(b"a\n")
        (tmp_path / "b.md").write_bytes(b"b\n")
        (tmp_path / "c.png").write_bytes(b"\x89PNG")
        found = {p.name for p in check_encoding._iter_text_files(tmp_path)}
        assert {"a.py", "b.md"} <= found
        assert "c.png" not in found

    def test_skips_blacklisted_directories(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.js").write_bytes(b"\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_bytes(b"\n")
        found = {p.name for p in check_encoding._iter_text_files(tmp_path)}
        assert "main.py" in found
        assert "lib.js" not in found

    def test_picks_up_always_text_filenames(self, tmp_path):
        (tmp_path / "SPECS.SHA3-256").write_bytes(b"# manifest\n")
        (tmp_path / ".editorconfig").write_bytes(b"root=true\n")
        found = {p.name for p in check_encoding._iter_text_files(tmp_path)}
        assert "SPECS.SHA3-256" in found
        assert ".editorconfig" in found
