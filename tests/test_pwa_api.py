"""End-to-end tests for the PWA REST API.

These tests bypass the camera/ArUco pipeline by monkey-patching
``scan_and_route`` to return canned :class:`ScanResult` instances. The
goal is to validate the HTTP surface (multipart parsing, error mapping,
secret gating) rather than the detection pipeline itself.
"""

from __future__ import annotations

import io
import secrets

import pytest
from PIL import Image

from eopx.flows import Intent, ScanResult
from eopx.server.pwa_api import REVEAL_HEADER, create_app
from eopx.vault import EnrollmentRecord


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app():
    return create_app(allow_origins=["http://localhost:5173"])


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def sample_png_bytes() -> bytes:
    img = Image.new("RGB", (32, 32), (123, 45, 67))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_enrollment() -> EnrollmentRecord:
    return EnrollmentRecord(
        vault_fp=bytes(32),
        device_secret=secrets.token_bytes(32),
        enrollment_fp=secrets.token_bytes(32),
        public_tag=secrets.token_bytes(16),
        shadow_hologram=secrets.token_bytes(64),
    )


def _patch_scan(monkeypatch, canned: ScanResult) -> None:
    """Replace eopx.server.pwa_api.scan_and_route with a fixed function."""
    import eopx.server.pwa_api as api_mod
    monkeypatch.setattr(api_mod, "scan_and_route", lambda image, ctx: canned)


# ---------------------------------------------------------------------------
# Read-only endpoints
# ---------------------------------------------------------------------------

def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json["status"] == "ok"
    assert "version" in r.json


def test_info_lists_intents(client):
    r = client.get("/api/v1/info")
    assert r.status_code == 200
    assert "enroll" in r.json["intents"]
    assert "verify" in r.json["intents"]
    assert r.json["secret_reveal_header"] == REVEAL_HEADER


# ---------------------------------------------------------------------------
# /scan error mapping
# ---------------------------------------------------------------------------

def test_scan_missing_intent_returns_400(client, sample_png_bytes):
    r = client.post(
        "/api/v1/scan",
        data={"image": (io.BytesIO(sample_png_bytes), "card.png")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "intent" in r.json["error"]


def test_scan_unknown_intent_returns_400(client, sample_png_bytes):
    r = client.post(
        "/api/v1/scan",
        data={
            "image": (io.BytesIO(sample_png_bytes), "card.png"),
            "intent": "make-coffee",
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "intent" in r.json["error"]


def test_scan_missing_image_returns_400(client):
    r = client.post(
        "/api/v1/scan",
        data={"intent": "verify"},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "image" in r.json["error"]


def test_scan_invalid_hex_returns_400(client, sample_png_bytes):
    r = client.post(
        "/api/v1/scan",
        data={
            "image": (io.BytesIO(sample_png_bytes), "card.png"),
            "intent": "verify",
            "spinor_hash_hex": "not-hex-at-all",
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "hex" in r.json["error"]


def test_scan_wrong_length_hex_returns_400(client, sample_png_bytes):
    r = client.post(
        "/api/v1/scan",
        data={
            "image": (io.BytesIO(sample_png_bytes), "card.png"),
            "intent": "verify",
            "spinor_hash_hex": "ab" * 5,  # 5 bytes, not 32
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "32 bytes" in r.json["error"]


# ---------------------------------------------------------------------------
# /scan happy paths
# ---------------------------------------------------------------------------

def test_scan_verify_returns_public_dict(client, monkeypatch,
                                          sample_png_bytes):
    canned = ScanResult(
        success=True, intent=Intent.VERIFY,
        card_fingerprint_hex="ff" * 32,
        verify_ok=True,
        detection_method="cube_aruco", markers_used=4,
    )
    _patch_scan(monkeypatch, canned)
    r = client.post(
        "/api/v1/scan",
        data={
            "image": (io.BytesIO(sample_png_bytes), "card.png"),
            "intent": "verify",
            "spinor_hash_hex": "ab" * 32,
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    body = r.json
    assert body["success"] is True
    assert body["intent"] == "verify"
    assert body["verify_ok"] is True
    assert body["card_fingerprint_hex"] == "ff" * 32
    assert body["detection_method"] == "cube_aruco"


def test_scan_enroll_omits_device_secret_by_default(client, monkeypatch,
                                                      sample_png_bytes):
    rec = _make_enrollment()
    canned = ScanResult(
        success=True, intent=Intent.ENROLL,
        card_fingerprint_hex="aa" * 32,
        enrollment=rec,
        recovery_phrase=["abandon"] * 23 + ["art"],
    )
    _patch_scan(monkeypatch, canned)
    r = client.post(
        "/api/v1/scan",
        data={
            "image": (io.BytesIO(sample_png_bytes), "card.png"),
            "intent": "enroll",
            "device_entropy_hex": "00" * 32,
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    body = r.json
    assert body["success"] is True
    assert body["enrollment"]["enrollment_fp_hex"] == rec.enrollment_fp.hex()
    assert "device_secret_hex" not in body["enrollment"]  # GATED
    assert body["recovery_phrase"][-1] == "art"
    assert len(body["recovery_phrase"]) == 24


def test_scan_enroll_includes_secret_when_header_set(client, monkeypatch,
                                                       sample_png_bytes):
    rec = _make_enrollment()
    canned = ScanResult(
        success=True, intent=Intent.ENROLL,
        card_fingerprint_hex="aa" * 32,
        enrollment=rec,
    )
    _patch_scan(monkeypatch, canned)
    r = client.post(
        "/api/v1/scan",
        data={
            "image": (io.BytesIO(sample_png_bytes), "card.png"),
            "intent": "enroll",
            "device_entropy_hex": "00" * 32,
        },
        content_type="multipart/form-data",
        headers={REVEAL_HEADER: "1"},
    )
    assert r.status_code == 200
    body = r.json
    assert body["enrollment"]["device_secret_hex"] == rec.device_secret.hex()


def test_scan_failure_returns_200_with_errors(client, monkeypatch,
                                                sample_png_bytes):
    canned = ScanResult(
        success=False, intent=Intent.VERIFY,
        errors=["ArUco autodetect failed: no markers"],
    )
    _patch_scan(monkeypatch, canned)
    r = client.post(
        "/api/v1/scan",
        data={
            "image": (io.BytesIO(sample_png_bytes), "card.png"),
            "intent": "verify",
            "spinor_hash_hex": "ab" * 32,
        },
        content_type="multipart/form-data",
    )
    # Detection failures are not HTTP errors; the client inspects the body.
    assert r.status_code == 200
    assert r.json["success"] is False
    assert "ArUco autodetect failed" in r.json["errors"][0]


# ---------------------------------------------------------------------------
# /extract endpoint — detection only, no secrets
# ---------------------------------------------------------------------------

def test_extract_missing_image_returns_400(client):
    r = client.post("/api/v1/extract", data={},
                     content_type="multipart/form-data")
    assert r.status_code == 400


def test_extract_returns_symbols_no_secrets(client, monkeypatch,
                                              sample_png_bytes):
    """``/extract`` must NEVER return secrets, even with the reveal header."""
    from eopx.flows import ScanResult

    canned = ScanResult(
        success=True, intent=None,
        symbols=list(range(91)),
        card_fingerprint_hex="cd" * 32,
        detection_method="cube_aruco",
        markers_used=4,
    )
    import eopx.server.pwa_api as api_mod
    monkeypatch.setattr(api_mod, "scan_only", lambda image: canned)

    r = client.post(
        "/api/v1/extract",
        data={"image": (io.BytesIO(sample_png_bytes), "card.png")},
        content_type="multipart/form-data",
        headers={REVEAL_HEADER: "1"},  # ignored by this endpoint
    )
    assert r.status_code == 200
    body = r.json
    assert body["success"] is True
    assert body["symbols"] == list(range(91))
    assert body["card_fingerprint_hex"] == "cd" * 32
    assert body["detection_method"] == "cube_aruco"
    # The extract endpoint must NOT carry any secret field, ever.
    for forbidden in [
        "device_secret_hex", "vault_master_key_hex", "session_key_hex",
        "vault_seed_hex", "enrollment", "genesis_vault",
        "recovery_phrase",
    ]:
        assert forbidden not in body, (
            f"/extract leaked sensitive field: {forbidden}"
        )


def test_extract_failure_returns_200_with_errors(client, monkeypatch,
                                                  sample_png_bytes):
    from eopx.flows import ScanResult

    canned = ScanResult(
        success=False, intent=None,
        errors=["ArUco autodetect failed: no markers"],
    )
    import eopx.server.pwa_api as api_mod
    monkeypatch.setattr(api_mod, "scan_only", lambda image: canned)

    r = client.post(
        "/api/v1/extract",
        data={"image": (io.BytesIO(sample_png_bytes), "card.png")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    assert r.json["success"] is False
    assert r.json["symbols"] is None


def test_scan_recovery_phrase_translates_to_entropy(client, monkeypatch,
                                                      sample_png_bytes):
    """If the client sends a BIP-39 phrase, the API translates it to the
    raw entropy that ``scan_and_route`` expects."""
    captured = {}

    def capture(image, ctx):
        captured["device_entropy"] = ctx.device_entropy
        return ScanResult(success=True, intent=Intent.RECOVER)

    import eopx.server.pwa_api as api_mod
    monkeypatch.setattr(api_mod, "scan_and_route", capture)

    # 32 zero bytes <-> the canonical "abandon ... art" mnemonic
    phrase = " ".join(["abandon"] * 23 + ["art"])
    r = client.post(
        "/api/v1/scan",
        data={
            "image": (io.BytesIO(sample_png_bytes), "card.png"),
            "intent": "recover",
            "recovery_phrase": phrase,
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    assert captured["device_entropy"] == bytes(32)
