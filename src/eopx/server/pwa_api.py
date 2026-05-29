"""REST API consumed by the Esoptron PWA / mobile clients.

Design goals
------------
* **Stateless** — no session, no DB. Each request is self-contained.
* **JSON only** — multipart upload for the image field, JSON for
  everything else.
* **Versioned** — mounted at ``/api/v1`` so we can evolve in v2 without
  breaking existing clients.
* **Secret-aware** — secrets (``device_secret``, ``session_key``,
  ``vault_master_key``) are returned only when the request explicitly
  asks for them via ``X-Esoptron-Reveal-Secrets: 1``. Otherwise the
  client must call ``scan_and_route`` locally for sensitive intents.

Routes
------
* ``GET  /api/v1/health``
* ``GET  /api/v1/info``
* ``POST /api/v1/scan``            multipart: ``image`` + form fields

The blueprint can be registered on either an existing Flask app
(``app.register_blueprint(create_pwa_api())``) or served standalone via
``scripts/serve_pwa_api.py``.
"""

from __future__ import annotations

import base64
import io
import logging
from typing import Optional

from flask import Blueprint, jsonify, request
from PIL import Image

from .. import __version__
from ..flows import Intent, ScanContext, scan_and_route, scan_only
from ..vault.genesis import recovery_phrase_to_entropy
from .rate_limit import rate_limit
from .serialization import (
    extract_result_to_dict,
    intent_from_str,
    scan_result_to_dict,
)

_log = logging.getLogger("eopx.server.pwa_api")

REVEAL_HEADER = "X-Esoptron-Reveal-Secrets"
MAX_IMAGE_BYTES = 12 * 1024 * 1024     # 12 MB cap on inbound photo uploads
MAX_IMAGE_PIXELS = 25_000_000          # 25 megapixels cap (decompression bomb defence)

# Pillow has its own global cap; honour ours.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bad_request(msg: str, status: int = 400):
    return jsonify({"error": msg}), status


def _wants_secrets() -> bool:
    return request.headers.get(REVEAL_HEADER, "").strip() in ("1", "true", "yes")


def _read_image_field() -> Optional[Image.Image]:
    """Load the ``image`` multipart field. Returns None when missing or invalid."""
    f = request.files.get("image")
    if f is None:
        return None
    # Fail fast on Content-Length before reading the body.
    cl = request.content_length
    if cl is not None and cl > MAX_IMAGE_BYTES:
        raise ValueError(f"image exceeds {MAX_IMAGE_BYTES} bytes")
    blob = f.read(MAX_IMAGE_BYTES + 1)
    if len(blob) > MAX_IMAGE_BYTES:
        raise ValueError(f"image exceeds {MAX_IMAGE_BYTES} bytes")
    try:
        img = Image.open(io.BytesIO(blob))
        # Validate dimensions before allocating the pixel buffer.
        w, h = img.size
        if w * h > MAX_IMAGE_PIXELS:
            raise ValueError(
                f"image exceeds {MAX_IMAGE_PIXELS} pixels ({w}x{h})"
            )
        img.load()
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"cannot decode image: {exc}") from exc
    return img


def _read_optional_bytes(form_key: str, length: Optional[int] = None
                          ) -> Optional[bytes]:
    """Decode an optional hex-encoded field from the multipart form."""
    raw = request.form.get(form_key, "").strip()
    if not raw:
        return None
    try:
        out = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(f"{form_key} must be hex-encoded") from exc
    if length is not None and len(out) != length:
        raise ValueError(
            f"{form_key} must be {length} bytes ({2 * length} hex chars); "
            f"got {len(out)} bytes"
        )
    return out


def _read_optional_mnemonic(form_key: str) -> Optional[bytes]:
    """Accept a BIP-39 phrase as a single form field, return derived entropy."""
    raw = request.form.get(form_key, "").strip()
    if not raw:
        return None
    words = raw.split()
    return recovery_phrase_to_entropy(words)


# ---------------------------------------------------------------------------
# Blueprint factory
# ---------------------------------------------------------------------------

def create_pwa_api(url_prefix: str = "/api/v1") -> Blueprint:
    bp = Blueprint("eopx_pwa_api", __name__, url_prefix=url_prefix)

    @bp.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "version": __version__})

    @bp.route("/info", methods=["GET"])
    def info():
        return jsonify({
            "version": __version__,
            "intents": [i.value for i in Intent],
            "max_image_bytes": MAX_IMAGE_BYTES,
            "secret_reveal_header": REVEAL_HEADER,
        })

    @bp.route("/scan", methods=["POST"])
    @rate_limit("heavy")
    def scan():
        """Single endpoint for every intent.

        Form fields:
        - ``image``                (file, required)
        - ``intent``               (string, required, one of Intent values)
        - ``device_entropy_hex``   (32-byte hex, optional)
        - ``recovery_phrase``      (BIP-39 words space-separated, optional)
        - ``spinor_hash_hex``      (32-byte hex, optional)
        - ``challenge_vault_id_hex`` (32-byte hex, optional, UNLOCK only)
        - ``challenge_nonce_hex``  (32-byte hex, optional, UNLOCK only)
        - ``challenge_issued_at``  (unix float seconds, optional)

        Header:
        - ``X-Esoptron-Reveal-Secrets: 1`` to include sensitive fields.

        Returns:
            ``200`` with ``ScanResult`` JSON when the pipeline ran (even
            on detection failure — inspect ``success`` and ``errors``).
            ``400`` on malformed input. Never raises.
        """
        # ---- Parse intent ----
        intent_str = request.form.get("intent", "").strip()
        if not intent_str:
            return _bad_request("missing form field: intent")
        try:
            intent = intent_from_str(intent_str)
        except ValueError as exc:
            return _bad_request(str(exc))

        # ---- Parse image ----
        try:
            img = _read_image_field()
        except ValueError as exc:
            return _bad_request(str(exc))
        if img is None:
            return _bad_request("missing form field: image")

        # ---- Optional inputs ----
        try:
            device_entropy = _read_optional_bytes(
                "device_entropy_hex", length=32,
            )
            if device_entropy is None:
                device_entropy = _read_optional_mnemonic("recovery_phrase")
            spinor_hash = _read_optional_bytes("spinor_hash_hex", length=32)
            challenge_vault_id = _read_optional_bytes(
                "challenge_vault_id_hex", length=32,
            )
            challenge_nonce = _read_optional_bytes(
                "challenge_nonce_hex", length=32,
            )
        except ValueError as exc:
            return _bad_request(str(exc))

        challenge = None
        if challenge_vault_id is not None and challenge_nonce is not None:
            from ..vault import new_challenge
            issued_at_raw = request.form.get("challenge_issued_at", "").strip()
            issued_at = float(issued_at_raw) if issued_at_raw else None
            challenge = new_challenge(
                vault_id=challenge_vault_id, nonce=challenge_nonce,
                issued_at=issued_at,
            )

        ctx = ScanContext(
            intent=intent,
            device_entropy=device_entropy,
            spinor_hash_local=spinor_hash,
            challenge=challenge,
        )

        # ---- Dispatch ----
        result = scan_and_route(img, ctx)
        body = scan_result_to_dict(result, include_secrets=_wants_secrets())

        _log.info(
            "scan intent=%s success=%s method=%s errors=%d",
            intent.value, result.success,
            result.detection_method, len(result.errors),
        )
        return jsonify(body)

    @bp.route("/extract", methods=["POST"])
    @rate_limit("heavy")
    def extract():
        """Detection-only endpoint: returns the 91 symbols + fingerprint.

        Use this when the client wants to run vault crypto locally (the
        offline-first flow). The server never sees ``device_entropy``
        nor any derived secret because no intent is processed.

        Form fields:
        - ``image`` (file, required)

        Returns:
            ``200`` with detection result JSON (always; inspect
            ``success`` and ``errors``). ``400`` on malformed input.
        """
        try:
            img = _read_image_field()
        except ValueError as exc:
            return _bad_request(str(exc))
        if img is None:
            return _bad_request("missing form field: image")

        result = scan_only(img)
        body = extract_result_to_dict(result)
        _log.info(
            "extract success=%s method=%s errors=%d",
            result.success, result.detection_method, len(result.errors),
        )
        return jsonify(body)

    return bp


def _validate_cors_origin(origin: str) -> str:
    """Reject wildcard / malformed CORS origins.

    Allowing ``*`` together with credentials is a known foot-gun (browsers
    silently drop credentials, but the misconfiguration also signals that the
    operator did not think about who can hit the API). We refuse it outright
    and require an explicit scheme + host.
    """
    from urllib.parse import urlparse

    o = (origin or "").strip()
    if not o:
        raise ValueError("CORS origin is empty")
    if o == "*" or "*" in o:
        raise ValueError(
            f"CORS origin {origin!r} contains a wildcard; "
            "explicit scheme://host[:port] is required"
        )
    p = urlparse(o)
    if p.scheme not in ("http", "https"):
        raise ValueError(
            f"CORS origin {origin!r} must use http:// or https://"
        )
    if not p.netloc:
        raise ValueError(f"CORS origin {origin!r} has no host")
    # Reject path/query/fragment — these have no meaning in an Origin header.
    if p.path not in ("", "/") or p.query or p.fragment:
        raise ValueError(
            f"CORS origin {origin!r} must not contain a path, query, "
            "or fragment"
        )
    return f"{p.scheme}://{p.netloc}"


def create_app(allow_origins: Optional[list[str]] = None):
    """Standalone Flask app exposing only the PWA API.

    Set ``allow_origins`` to enable CORS (the PWA dev server typically
    runs on a different origin from the API). Wildcard origins (``*``)
    are refused; each entry must be ``scheme://host[:port]``.
    """
    from flask import Flask
    app = Flask("eopx_pwa")
    app.register_blueprint(create_pwa_api())

    if allow_origins:
        validated = [_validate_cors_origin(o) for o in allow_origins]
        try:
            from flask_cors import CORS
            CORS(app, origins=validated,
                  expose_headers=[REVEAL_HEADER],
                  allow_headers=["Content-Type", REVEAL_HEADER])
        except ImportError:
            _log.warning(
                "flask_cors not installed — CORS disabled. "
                "Install with `pip install flask-cors` if your PWA runs "
                "on a different origin."
            )
    return app


__all__ = [
    "create_pwa_api",
    "create_app",
    "REVEAL_HEADER",
    "MAX_IMAGE_BYTES",
    "MAX_IMAGE_PIXELS",
]
