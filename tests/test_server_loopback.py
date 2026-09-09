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


def test_scan_page_redirects_to_the_pwa_when_configured(monkeypatch):
    monkeypatch.setenv("ESOPTRON_PWA_URL", "https://example.invalid/pwa")
    import importlib

    import eopx.server.app as app_mod
    importlib.reload(app_mod)
    try:
        client = app_mod.create_app(
            app_mod.ServerConfig(mode="sas", spinor_hex="00" * 64)
        ).test_client()
        r = client.get("/scan")
        assert r.status_code == 200
        assert b"example.invalid/pwa" in r.data
    finally:
        monkeypatch.delenv("ESOPTRON_PWA_URL", raising=False)
        importlib.reload(app_mod)


def test_scan_page_is_gone_without_a_pwa_url():
    app = create_app(ServerConfig(mode="sas", spinor_hex="00" * 64))
    r = app.test_client().get("/scan")
    assert r.status_code == 410


def test_register_psnx_is_gone(tmp_path, monkeypatch):
    """The public psnx registry was removed, not merely disabled.

    It accepted caller-supplied JSON and appended it to a registry under
    ``out/`` with no authentication and no quota (audit 2026-05-28, P1-7).
    Its only client was the inline ``/scan`` page, whose divergent KDF chain
    has been deleted, so the endpoint answers 410 and writes nothing.
    """
    monkeypatch.chdir(tmp_path)
    app = create_app(ServerConfig(mode="genesis"))
    client = app.test_client()

    r = client.post("/api/register_psnx", json={
        "format": "psnx", "version": 1, "security": "public",
        "vault_id": "vlt_" + "a" * 32,
    })
    assert r.status_code == 410
    assert r.get_json()["status"] == "GONE"
    assert not (tmp_path / "out" / "registry").exists()


def test_legacy_scan_page_no_longer_serves_its_own_crypto(tmp_path, monkeypatch):
    """The phone is sent to the PWA; there is no second KDF chain to revive.

    The page used to be gated behind ESOPTRON_ENABLE_LEGACY_MOBILE_HTML, which
    deferred the decision rather than making it. No environment variable brings
    it back, so the test asserts on the absence of the info strings too.
    """
    import eopx.server.app as app_mod

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ESOPTRON_ENABLE_LEGACY_MOBILE_HTML", "1")
    client = create_app(ServerConfig(mode="genesis")).test_client()

    r = client.get("/scan")
    assert r.status_code == 410
    body = r.data.decode("utf-8", "replace")
    assert "esoptron.mobile" not in body

    source = Path(app_mod.__file__).read_text(encoding="utf-8")
    for info in ("esoptron.mobile.genesis.vault_seed.sha256.v1",
                 "esoptron.mobile.vault.master_key.sha256.v1",
                 "esoptron.mobile.enrollment_fp.sha256.v1",
                 "esoptron.mobile.public_tag.sha256.v1"):
        assert info not in source, f"{info} came back"
