"""Loopback test: upload the canonical print sheet to /api/frame and
verify the server recovers the known seed.

Runs the Flask app via Werkzeug's test client (no socket needed).
"""

from __future__ import annotations

import hashlib
import io
import sys
from pathlib import Path

from PIL import Image

from eopx.metatron import encode_private
from eopx.server.app import create_app, ServerConfig

# Re-use make_sheet from print_sheet.py.
_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from print_sheet import make_sheet  # type: ignore  # noqa: E402


def _sheet_bytes(passphrase: str) -> tuple[bytes, str]:
    seed = hashlib.sha3_256(passphrase.encode()).digest()
    cw = encode_private(seed)
    pil = make_sheet(cw, role="private", label=passphrase,
                      hash_hex=seed.hex())
    buf = io.BytesIO()
    pil.save(buf, format="PNG")
    return buf.getvalue(), seed.hex()


def test_server_private_mode_recovers_seed():
    png_bytes, seed_hex = _sheet_bytes("server.loopback.private.v1")
    cfg = ServerConfig(mode="private", known_seed_hex=seed_hex)
    app = create_app(cfg)
    client = app.test_client()

    # /api/config sanity
    r = client.get("/api/config")
    assert r.status_code == 200
    assert r.get_json()["mode"] == "private"

    # /api/frame upload
    data = {"frame": (io.BytesIO(png_bytes), "sheet.png")}
    r = client.post("/api/frame",
                     data=data, content_type="multipart/form-data")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["status"] == "OK", body
    assert body["seed_hex"].lower() == seed_hex.lower()
    assert body["seed_match"] is True

    # /api/status mirrors the result
    s = client.get("/api/status").get_json()
    assert s["result"]["status"] == "OK"
    assert s["last_update"] > 0


def test_server_genesis_mode_returns_only_ceremony_material():
    png_bytes, _seed_hex = _sheet_bytes("server.loopback.genesis.v1")
    cfg = ServerConfig(mode="genesis")
    app = create_app(cfg)
    client = app.test_client()

    data = {"frame": (io.BytesIO(png_bytes), "sheet.png")}
    r = client.post("/api/frame",
                     data=data, content_type="multipart/form-data")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["status"] == "GENESIS", body
    assert body["client_onboarding"] == "phone_local"
    assert len(body["ceremony_fp_hex"]) == 64
    assert len(body["ceremony_seed_hex"]) == 64
    assert "device_entropy_hex" not in body
    assert "vault_seed_hex" not in body
    assert "master_key_hex" not in body
    assert "blend_data" not in body


def test_server_no_markers_returns_NO_MARKERS():
    """A plain colored square has no ArUco markers."""
    cfg = ServerConfig(mode="private")
    app = create_app(cfg)
    client = app.test_client()
    img = Image.new("RGB", (640, 480), (200, 200, 200))
    buf = io.BytesIO(); img.save(buf, format="PNG")
    data = {"frame": (io.BytesIO(buf.getvalue()), "blank.png")}
    r = client.post("/api/frame",
                     data=data, content_type="multipart/form-data")
    body = r.get_json()
    assert body["status"] == "NO_MARKERS"


def test_dashboard_html_renders():
    app = create_app(ServerConfig(mode="enroll"))
    client = app.test_client()
    r = client.get("/")
    assert r.status_code == 200
    assert b"Esoptron live scan" in r.data
    # QR is embedded as data: URI
    assert b"data:image/png;base64," in r.data


def test_scan_page_renders(monkeypatch):
    monkeypatch.setenv("ESOPTRON_ENABLE_LEGACY_MOBILE_HTML", "1")
    monkeypatch.setattr(
        "eopx.server.app._ENABLE_LEGACY_MOBILE_HTML", True
    )
    app = create_app(ServerConfig(mode="sas",
                                    spinor_hex="00" * 64))
    client = app.test_client()
    r = client.get("/scan")
    assert r.status_code == 200
    assert b"Capturer" in r.data


def test_scan_page_disabled_by_default():
    app = create_app(ServerConfig(mode="sas",
                                    spinor_hex="00" * 64))
    client = app.test_client()
    r = client.get("/scan")
    assert r.status_code == 410


def test_genesis_scan_page_contains_local_onboarding(monkeypatch):
    monkeypatch.setattr(
        "eopx.server.app._ENABLE_LEGACY_MOBILE_HTML", True
    )
    app = create_app(ServerConfig(mode="genesis"))
    client = app.test_client()
    r = client.get("/scan")
    assert r.status_code == 200
    assert b"createOnboardingPackage" in r.data
    assert b"registerPublicPsnx" in r.data
    assert b"blend_data" in r.data
    assert b"psnx" in r.data


def test_register_psnx_stores_only_public_material(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "eopx.server.app._ENABLE_LEGACY_MOBILE_HTML", True
    )
    app = create_app(ServerConfig(mode="genesis"))
    client = app.test_client()
    psnx = {
        "format": "psnx",
        "version": 1,
        "security": "public",
        "vault_id": "vlt_" + "a" * 32,
        "created_at": "2026-05-26T00:00:00.000Z",
        "ceremony_fp_hex": "b" * 64,
        "vault_fp_hex": "c" * 64,
        "enrollment_fp_hex": "d" * 64,
        "public_tag_hex": "e" * 32,
        "kdf": "HKDF-HMAC-SHA256 browser-local v1",
    }

    r = client.post("/api/register_psnx", json=psnx)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["status"] == "REGISTERED"
    assert body["vault_id"] == psnx["vault_id"]
    assert (tmp_path / "out" / "registry"
            / f"{psnx['vault_id']}.psnx.json").exists()
    assert (tmp_path / "out" / "registry"
            / "vault_registry.jsonl").exists()


def test_register_psnx_rejects_private_material(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "eopx.server.app._ENABLE_LEGACY_MOBILE_HTML", True
    )
    app = create_app(ServerConfig(mode="genesis"))
    client = app.test_client()
    psnx = {
        "format": "psnx",
        "version": 1,
        "security": "public",
        "vault_id": "vlt_" + "a" * 32,
        "ceremony_fp_hex": "b" * 64,
        "vault_fp_hex": "c" * 64,
        "enrollment_fp_hex": "d" * 64,
        "public_tag_hex": "e" * 32,
        "vault_seed_hex": "f" * 64,
    }

    r = client.post("/api/register_psnx", json=psnx)
    assert r.status_code == 400
    body = r.get_json()
    assert body["status"] == "REJECTED"
    assert "private-looking field" in body["detail"]
