"""Esoptron live-scan Flask app (DEV / DEMO ONLY).

.. warning::

    This module is a single-tenant developer demo. It is NOT suitable for
    multi-user production deployments:

    * The decoded vault state is held as one shared in-memory ``ServerState``
      object — every concurrent caller sees the latest scan from any user.
    * ``ServerConfig.spinor_hex`` / ``known_seed_hex`` are set once at boot,
      so the process is bound to a single vault.
    * ``/api/frame`` is rate-limited but has no auth, and writes diagnostic
      images to ``out/`` when ``ESOPTRON_DEBUG_DUMP_FRAMES=1`` -- never in
      ``private`` mode, whatever the operator asks for.

    For production multi-tenant deployments use :mod:`eopx.server.pwa_api`
    behind a reverse proxy + auth layer, or roll your own service that
    consumes :mod:`eopx.flows`.

Routes
------
GET  /              Dashboard (PC). Shows the QR code with the phone URL
                    and the live decode status.
GET  /scan          Redirects to the PWA (``ESOPTRON_PWA_URL``), else 410.
                    The inline scanner that used to live here carried its own
                    KDF chain and was removed.
POST /api/frame     Accepts a multipart upload "frame": image bytes
                    (JPEG/PNG). Runs the full decode pipeline and stores
                    the result in shared state. Rate-limited (heavy).
GET  /api/status    Returns the latest decode result (JSON).
GET  /api/config    Returns the active server config (mode, etc.).

The decode pipeline is identical to scripts/live_scan.py: it reuses the
ArUco detector + homography + cube crop + extract_canonical.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import cv2
import numpy as np
import qrcode
from flask import Flask, jsonify, render_template_string, request, url_for
from PIL import Image

from ..metatron import (
    decode_private,
    encode_private,
    extract_canonical,
    extract_robust,
    erasures_from_confidences,
)
from ..metatron.aruco import (
    CUBE_DST_SIZE,
    detect_cube_aruco,
    detect_page_aruco,
    rectify_a4,
    rectify_cube_via_cube_aruco,
    rectify_cube_via_page_aruco,
)
from ..metatron.grid_detect import _extract_grid_colors
from ..metatron.grid_render import grid_layout, GRID_ROWS, GRID_COLS
from ..vault import (
    unlock_from_private_symbols, verify_card,
    new_challenge, respond, verify_response,
    enroll_from_card,
    card_fingerprint,
)

# Re-use layout constants from the print sheet generator.
_SCRIPTS_DIR = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from print_sheet import (  # type: ignore  # noqa: E402
    PAGE_W, PAGE_H, CUBE_SIDE_MM,
    FIDUCIAL_INSET_MM, FIDUCIAL_MM,
    cube_rect_in_page, mm as _mm,
)

def mm(v: float) -> int:
    """Alias for print_sheet.mm (convert mm to px at 300 DPI)."""
    return _mm(v)


DEFAULT_PORT = 8765


# ---------------------------------------------------------------------------
# Server state
# ---------------------------------------------------------------------------

@dataclass
class ServerConfig:
    mode: str = "private"                 # private / verify / sas / enroll / genesis
    spinor_hex: Optional[str] = None
    known_seed_hex: Optional[str] = None


@dataclass
class ServerState:
    config: ServerConfig
    last_result: Dict[str, Any] = field(default_factory=dict)
    last_update: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def update(self, result: Dict[str, Any]) -> None:
        with self.lock:
            self.last_result = result
            self.last_update = time.time()

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return dict(self.last_result), self.last_update


# ---------------------------------------------------------------------------
# Decode pipeline (shared with live_scan.py logic)
# ---------------------------------------------------------------------------

def _try_grid_decode(frame_bgr: np.ndarray,
                     cfg: ServerConfig) -> Optional[Dict[str, Any]]:
    """Try to decode via the chromatic grid (6-color base-6 encoding).

    Requires page-corner ArUco (IDs 0-3) for rectification, then extracts
    the grid region and classifies the 6 colors.
    """
    found = detect_page_aruco(frame_bgr)
    if found is None:
        return None

    rect_a4 = rectify_a4(frame_bgr, found)

    # Compute grid position on the A4 page
    inset = int(mm(FIDUCIAL_INSET_MM))
    fid_side = int(mm(FIDUCIAL_MM))
    quiet_px = int(mm(5.0))
    banner_y = inset + fid_side + quiet_px + int(mm(8.0))
    banner_h = int(mm(14.0))
    cube_px = int(mm(CUBE_SIDE_MM))
    cube_y = banner_y + banner_h + int(mm(10.0))
    scale_y = cube_y + cube_px + int(mm(5.0))
    foot_y = scale_y + int(mm(4.0)) + int(mm(3.0)) + int(mm(3.0))
    grid_y = foot_y + int(mm(2.0))

    cell_px = int(mm(3.5))
    layout = grid_layout(cell_px)
    grid_x = (PAGE_W - layout['grid_w']) // 2
    gh = layout['grid_h']
    gw = layout['grid_w']

    if grid_y + gh > PAGE_H or grid_x + gw > PAGE_W:
        return None  # grid doesn't fit

    region = rect_a4[grid_y:grid_y + gh, grid_x:grid_x + gw]
    if region.size == 0:
        return None

    # Convert BGR to RGB for grid extraction
    region_rgb = cv2.cvtColor(region, cv2.COLOR_BGR2RGB)

    try:
        syms = _extract_grid_colors(region_rgb, is_bgr=False, cell_px=cell_px)
    except Exception:
        return None

    if syms is None or len(syms) != 91:
        return None

    erasures = erasures_from_confidences([0.0] * 91)  # grid has no confidence yet
    base = {"method": "grid", "n_markers": len(found), "n_erasures": 0}
    try:
        return _run_protocol(syms, erasures, cfg, base)
    except Exception as e:
        n_mismatch = _count_mismatches(syms, cfg)
        return {**base, "status": "DECODE_FAIL", "detail": str(e),
                "n_mismatches": n_mismatch}


def _is_success_result(result: Optional[Dict[str, Any]]) -> bool:
    if not result:
        return False
    return result.get("status") in {
        "OK", "MATCH", "ENROLLED", "GENESIS"
    }


def _decode_frame(frame_bgr: np.ndarray, cfg: ServerConfig) -> Dict[str, Any]:
    # Strategy 0: CHROMATIC GRID (most robust for phone cameras).
    # The grid uses 6 ultra-contrast colors and is easy to read even with
    # heavy WB shift and JPEG compression. Requires page ArUco for rectification.
    grid_result = _try_grid_decode(frame_bgr, cfg)
    if _is_success_result(grid_result):
        return grid_result

    # Strategy 1: CUBE-ADJACENT ArUco markers (IDs 10-13).
    # These are at the 4 corners of the cube frame on the A4 sheet,
    # giving a much more precise rectification than page-corner markers.
    cube_aruco = detect_cube_aruco(frame_bgr)
    if cube_aruco is not None:
        try:
            pil = rectify_cube_via_cube_aruco(frame_bgr, cube_aruco)
            _save_diagnostic_img(pil, cfg, "diagnostic_cube_crop.png")
            result = _try_decode_cube(pil, cfg, method="cube_aruco",
                                       n_markers=len(cube_aruco))
            if _is_success_result(result):
                return result
        except Exception:
            pass

    # Strategy 2: PAGE-CORNER ArUco markers (IDs 0-3, on the A4 sheet).
    found = detect_page_aruco(frame_bgr)
    if found is not None:
        rect_a4 = rectify_a4(frame_bgr, found)
        _save_diagnostic(rect_a4, cfg)

        try:
            pil = rectify_cube_via_page_aruco(
                frame_bgr, found, dst_size=CUBE_DST_SIZE, normalize=True)

            # Try multiple decode strategies with increasing tolerance
            # Strategy A: standard extraction
            result = _try_decode_cube(pil, cfg, method="page_aruco",
                                       n_markers=len(found))
            if _is_success_result(result):
                return result

            # Strategy B: upsample 2x for better color sampling
            pil_2x = pil.resize((CUBE_DST_SIZE * 2, CUBE_DST_SIZE * 2),
                                 Image.Resampling.BICUBIC)
            result2 = _try_decode_cube(pil_2x, cfg,
                                        method="page_aruco_2x",
                                        n_markers=len(found),
                                        override_size=CUBE_DST_SIZE * 2)
            if _is_success_result(result2):
                return result2

            # Return the best failure result
            best = result or result2 or {"status": "DECODE_FAIL"}
            return best
        except Exception:
            pass

    # No markers found at all
    if cube_aruco is None and found is None:
        return {"status": "NO_MARKERS",
                "detail": "No ArUco markers detected (need cube IDs 10-13 or page IDs 0-3)."}

    # Markers found but decode failed
    n_cube = len(cube_aruco) if cube_aruco else 0
    n_page = len(found) if found else 0
    return {"status": "DECODE_FAIL",
            "detail": "All rectification methods failed",
            "n_cube_markers": n_cube,
            "n_page_markers": n_page}


def _try_decode_cube(pil: Image.Image, cfg: ServerConfig,
                      method: str = "unknown",
                      n_markers: int = 0,
                      override_size: int = 0) -> Optional[Dict[str, Any]]:
    """Try to extract + decode from a rectified cube image."""
    # If override_size is set, tell extract_canonical about the actual canvas size
    if override_size > 0:
        # The image is at override_size but the canonical layout assumes CUBE_DST_SIZE.
        # Resize back to canonical for extraction.
        pil = pil.resize((CUBE_DST_SIZE, CUBE_DST_SIZE), Image.Resampling.BICUBIC)
    def _try(symbols, erasures=None):
        base_local = {"method": method, "n_markers": n_markers}
        erasures = erasures or []
        base_local["n_erasures"] = len(erasures)
        try:
            return _run_protocol(symbols, erasures, cfg, base_local)
        except Exception:
            return None

    result = extract_robust(pil, decode_fn=_try)
    if isinstance(result, tuple) and len(result) == 2:
        syms, dists = result
        erasures = erasures_from_confidences(dists)
        base = {"method": method, "n_markers": n_markers,
                "n_erasures": len(erasures)}
        try:
            return _run_protocol(syms, erasures, cfg, base)
        except Exception as e:
            n_mismatch = _count_mismatches(syms, cfg)
            return {**base, "status": "DECODE_FAIL", "detail": str(e),
                    "n_mismatches": n_mismatch}

    symbols, dists = extract_canonical(pil)
    erasures = erasures_from_confidences(dists)
    base = {"method": method, "n_markers": n_markers,
            "n_erasures": len(erasures)}
    n_mismatch = _count_mismatches(symbols, cfg)
    try:
        return _run_protocol(symbols, erasures, cfg, base)
    except Exception as e:
        return {**base, "status": "DECODE_FAIL", "detail": str(e),
                "n_mismatches": n_mismatch}


def _diagnostics_allowed(cfg: ServerConfig) -> bool:
    """Whether a decoded frame may be written to ``out/`` for inspection.

    Off unless ``ESOPTRON_DEBUG_DUMP_FRAMES=1``, and never in ``private`` mode
    whatever the operator asked for. A private sheet reconstructs a 256-bit
    seed, and the two images written here are the rectified page and the cube
    crop -- the crop is precisely the decodable region. Writing it to a fixed,
    shared path under ``out/`` persists the secret for anyone with read access
    to the host and overwrites the previous scan's, so the mode check is not a
    convenience: it is the reason the gate exists.

    The upload path already refuses the same way (``api_frame``); this closes
    the decode path, which was writing unconditionally.
    """
    return _DEBUG_DUMP_FRAMES and getattr(cfg, "mode", None) != "private"


def _save_diagnostic_img(pil: Image.Image, cfg: ServerConfig,
                         filename: str) -> None:
    """Save a PIL image diagnostic, if diagnostics are allowed at all."""
    if not _diagnostics_allowed(cfg):
        return
    try:
        out = Path("out")
        out.mkdir(exist_ok=True)
        pil.save(str(out / filename), format="PNG")
    except Exception:
        pass


def _save_diagnostic(rect_a4_bgr: np.ndarray, cfg: ServerConfig) -> None:
    """Save the rectified A4 image for visual debugging, if allowed."""
    if not _diagnostics_allowed(cfg):
        return
    try:
        out = Path("out")
        out.mkdir(exist_ok=True)
        cv2.imwrite(str(out / "diagnostic_rectified_a4.png"), rect_a4_bgr)
        x, y, side = cube_rect_in_page()
        sub = rect_a4_bgr[y:y+side, x:x+side]
        if sub.size > 0:
            cv2.imwrite(str(out / "diagnostic_cube_crop.png"), sub)
    except Exception:
        pass  # non-critical


def _count_mismatches(symbols, cfg: ServerConfig) -> int:
    """Count how many of 91 symbols differ from the expected encoding,
    if we have a known seed. Returns -1 if no known seed."""
    if not cfg.known_seed_hex:
        return -1
    try:
        seed = bytes.fromhex(cfg.known_seed_hex)
        expected = encode_private(seed)
        return sum(1 for a, b in zip(symbols, expected) if a != b)
    except Exception:
        return -1


def _run_protocol(symbols, erasures, cfg, base):
    """Execute the selected vault protocol and return a result dict.
    Raises on failure so callers can try alternate strategies.
    """
    if cfg.mode == "private":
        seed, master = unlock_from_private_symbols(symbols,
                                                    erasures=erasures)
        out = {**base, "status": "OK", "seed_hex": seed.hex(),
                "master_key_hex": master.hex()}
        if cfg.known_seed_hex:
            out["seed_match"] = (seed.hex().lower()
                                 == cfg.known_seed_hex.lower())
        return out

    if cfg.mode == "verify":
        if not cfg.spinor_hex:
            return {**base, "status": "CONFIG_ERROR",
                     "detail": "server started without --spinor"}
        ok = verify_card(symbols, bytes.fromhex(cfg.spinor_hex))
        return {**base, "status": "MATCH" if ok else "MISMATCH"}

    if cfg.mode == "sas":
        if not cfg.spinor_hex:
            return {**base, "status": "CONFIG_ERROR"}
        spinor = bytes.fromhex(cfg.spinor_hex)
        vault_id = hashlib.sha3_256(spinor).digest()
        ch = new_challenge(vault_id)
        try:
            resp = respond(symbols, spinor, ch)
            sk = verify_response(resp, spinor, symbols)
        except ValueError as e:
            return {**base, "status": "REJECTED", "detail": str(e)}
        if sk is None:
            return {**base, "status": "VERIFY_FAIL"}
        return {**base, "status": "OK", "session_key_hex": sk.hex()}

    if cfg.mode == "enroll":
        rec = enroll_from_card(symbols)
        return {**base, "status": "ENROLLED",
                "vault_fp_hex": rec.vault_fp.hex(),
                "enrollment_fp_hex": rec.enrollment_fp.hex(),
                "public_tag_hex": rec.public_tag.hex(),
                "shadow_hex": rec.shadow_hologram.hex()}
    if cfg.mode == "genesis":
        ceremony_seed, _version = decode_private(symbols, erasures=erasures)
        ceremony_fp = card_fingerprint(symbols)
        return {**base, "status": "GENESIS",
                "ceremony_fp_hex": ceremony_fp.hex(),
                "ceremony_seed_hex": ceremony_seed.hex(),
                "client_onboarding": "phone_local"}

    return {**base, "status": "UNKNOWN_MODE"}


# ---------------------------------------------------------------------------
# Network utilities
# ---------------------------------------------------------------------------

def detect_lan_ip() -> str:
    """Best-effort: return the IPv4 address of the LAN interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def qr_png_base64(url: str) -> str:
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


# ---------------------------------------------------------------------------
# Public vault registry
# ---------------------------------------------------------------------------

_VAULT_ID_RE = re.compile(r"^vlt_[0-9a-f]{32}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
DASHBOARD_HTML = r"""
<!doctype html><html><head><meta charset="utf-8">
<title>Esoptron live scan (PC dashboard)</title>
<style>
 body { font-family: 'Segoe UI', system-ui, sans-serif; background:#101018;
        color:#e8e8ee; margin:0; padding:24px; }
 .wrap { max-width: 960px; margin: 0 auto; }
 h1 { font-weight: 400; letter-spacing:.5px; }
 .qr { display:flex; gap:24px; align-items:center; padding:16px;
       background:#1c1c28; border-radius:12px; margin-bottom:24px;}
 .qr img { width:240px; height:240px; background:#fff; padding:8px;
           border-radius:8px; }
 code, pre { font-family: Consolas, monospace; color:#a8d8ff; }
 .result { background:#161620; padding:18px; border-radius:12px; }
 .pill { display:inline-block; padding:4px 12px; border-radius:999px;
         font-weight:600; }
 .ok   { background:#0d3; color:#001; }
 .warn { background:#f93; color:#101; }
 .err  { background:#e34; color:#fff; }
 .idle { background:#446; color:#cce; }
 .row { display:flex; gap:8px; align-items:center; margin:6px 0;}
 .k { color:#9be; min-width:140px; }
 .v { color:#fff; word-break: break-all; font-family: Consolas, monospace; }
</style></head><body><div class="wrap">
<h1>Esoptron live scan — phone-as-scanner</h1>
<div class="qr">
  <img src="data:image/png;base64,{{ qr_b64 }}" alt="QR">
  <div>
    <p>1. Take your phone (same Wi-Fi as this PC).<br>
       2. Open the native camera app and scan this QR code.<br>
       3. Tap the link that pops up to open <code>/scan</code> in your phone browser.<br>
       4. Tap the big button on the phone, snap the Metatron sheet, wait for the result.</p>
    <p style="color:#9be"><b>Phone URL:</b> <code>{{ phone_url }}</code></p>
    <p>Mode: <span class="pill ok">{{ mode }}</span></p>
  </div>
</div>
<h2>Live result</h2>
<div id="result" class="result"><i>waiting for the first frame from the phone...</i></div>
<script>
async function poll() {
  try {
    const r = await fetch('/api/status'); const j = await r.json();
    const el = document.getElementById('result');
    if (!j.last_update) { el.innerHTML = '<i>waiting for the first frame from the phone...</i>'; return; }
    let pillClass = 'idle', status = j.result.status || '?';
    if (status === 'OK' || status === 'MATCH' || status === 'ENROLLED'
        || status === 'GENESIS') pillClass = 'ok';
    else if (status === 'NO_MARKERS' || status === 'CROP_FAIL') pillClass = 'warn';
    else pillClass = 'err';
    let rows = '';
    for (const [k, v] of Object.entries(j.result)) {
      if (k === 'status') continue;
      rows += `<div class="row"><span class="k">${k}</span><span class="v">${v}</span></div>`;
    }
    el.innerHTML = `<div class="row"><span class="k">status</span><span class="pill ${pillClass}">${status}</span></div>${rows}
       <div class="row"><span class="k">updated</span><span class="v">${new Date(j.last_update*1000).toLocaleTimeString()}</span></div>`;
  } catch (e) {}
}
setInterval(poll, 800); poll();
</script>
</div></body></html>
"""



# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------

from .rate_limit import rate_limit as _rate_limit

_MAX_FRAME_BYTES = 12 * 1024 * 1024  # 12 MB / upload (hard cap)
_MAX_IMAGE_PIXELS = 25_000_000        # 25 megapixels max
Image.MAX_IMAGE_PIXELS = _MAX_IMAGE_PIXELS

_DEBUG_DUMP_FRAMES = (
    os.environ.get("ESOPTRON_DEBUG_DUMP_FRAMES", "0") == "1"
)
_PWA_REDIRECT_URL = os.environ.get("ESOPTRON_PWA_URL", "")


def create_app(config: ServerConfig, port: int = DEFAULT_PORT) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = _MAX_FRAME_BYTES
    state = ServerState(config=config)
    lan_ip = detect_lan_ip()
    phone_url = f"http://{lan_ip}:{port}/scan"
    qr_b64 = qr_png_base64(phone_url)

    @app.route("/")
    def dashboard():
        return render_template_string(
            DASHBOARD_HTML,
            qr_b64=qr_b64,
            phone_url=phone_url,
            mode=config.mode,
        )

    @app.route("/scan")
    def scan_page():
        """Point the phone at the PWA. There is no second crypto chain here.

        This route used to serve ~390 lines of inline HTML carrying a
        hand-rolled SHA-256 and its own HKDF info strings
        (``esoptron.mobile.*``), bytewise incompatible with the canonical
        ``esoptron.vault.*`` SHA3-512 chain used by the Python core and the
        PWA. A ``.psnx`` produced by that page described the same vault
        differently from every other component.

        It was disabled behind an environment variable, which deferred the
        decision rather than making it: a second chain that a flag can revive
        is a second chain. It is deleted. One canonical KDF chain per vault,
        and the phone goes to the PWA.
        """
        if _PWA_REDIRECT_URL:
            return (
                f'<meta http-equiv="refresh" content="0; url={_PWA_REDIRECT_URL}">'
                f'<p>Redirecting to the PWA at <a href="{_PWA_REDIRECT_URL}">'
                f'{_PWA_REDIRECT_URL}</a></p>'
            ), 200
        return (
            "<h1>Scan from the PWA</h1>"
            "<p>The legacy inline scanner is gone: it shipped a KDF chain "
            "that disagreed with the rest of the system. Set "
            "<code>ESOPTRON_PWA_URL</code> so this endpoint redirects, or "
            "open the PWA directly.</p>"
        ), 410  # Gone

    @app.route("/api/config")
    def api_config():
        return jsonify({"mode": config.mode,
                         "has_spinor": bool(config.spinor_hex),
                         "has_known_seed": bool(config.known_seed_hex)})

    @app.route("/api/register_psnx", methods=["POST"])
    @_rate_limit("default")
    def api_register_psnx():
        """Gone with the legacy mobile flow that was its only client.

        This wrote caller-supplied JSON to an append-only registry under
        ``out/`` with no authentication and no quota (audit 2026-05-28, P1-7).
        Its only client was the inline ``/scan`` page, which shipped a KDF
        chain that disagreed with the rest of the system and has been removed.
        An unauthenticated write endpoint with no client is worse than no
        endpoint, so it answers 410 rather than lingering.

        If a public registry is wanted again it should come back
        authenticated, as the audit recommended.
        """
        return jsonify({
            "status": "GONE",
            "detail": "the public psnx registry was removed; it was "
                      "unauthenticated and served only the deleted legacy "
                      "mobile flow",
        }), 410

    @app.route("/api/status")
    def api_status():
        result, ts = state.snapshot()
        return jsonify({"result": result, "last_update": ts})

    @app.route("/api/frame", methods=["POST"])
    @_rate_limit("heavy")
    def api_frame():
        # Enforce content-length BEFORE reading the body (Flask already caps
        # via MAX_CONTENT_LENGTH but we double-check the header to fail fast).
        cl = request.content_length
        if cl is not None and cl > _MAX_FRAME_BYTES:
            return jsonify({"status": "PAYLOAD_TOO_LARGE",
                            "max_bytes": _MAX_FRAME_BYTES}), 413
        f = request.files.get("frame")
        if f is None:
            return jsonify({"status": "NO_FILE"}), 400
        data = f.read(_MAX_FRAME_BYTES + 1)
        if not data:
            return jsonify({"status": "EMPTY_FILE"}), 400
        if len(data) > _MAX_FRAME_BYTES:
            return jsonify({"status": "PAYLOAD_TOO_LARGE",
                            "max_bytes": _MAX_FRAME_BYTES}), 413
        # Frame persistence is OFF by default. PRIVATE-mode frames contain the
        # 256-bit vault seed and MUST NEVER be persisted across requests.
        if _DEBUG_DUMP_FRAMES and config.mode != "private":
            try:
                out = Path("out")
                out.mkdir(exist_ok=True)
                # Per-request temp file with restrictive mode where supported.
                tmp = out / f"frame_{int(time.time()*1000)}.bin"
                tmp.write_bytes(data)
                try:
                    os.chmod(tmp, 0o600)
                except OSError:
                    pass
            except Exception:
                pass
        arr = np.frombuffer(data, dtype=np.uint8)
        bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if bgr is None:
            return jsonify({"status": "DECODE_IMAGE_FAIL"}), 400
        # Validate decoded image dimensions to defend against decompression
        # bombs (oversized PNG/JPEG headers).
        h, w = bgr.shape[:2]
        if h * w > _MAX_IMAGE_PIXELS:
            return jsonify({"status": "IMAGE_TOO_LARGE",
                            "max_pixels": _MAX_IMAGE_PIXELS}), 413
        # Phone browsers may downsample uploads to 640x480.
        # ArUco detection needs at least ~2000px on the long side.
        min_dim = 2000
        if max(h, w) < min_dim:
            scale = min_dim / max(h, w)
            bgr = cv2.resize(bgr, (int(w * scale), int(h * scale)),
                              interpolation=cv2.INTER_CUBIC)
            logging.info(f"upsampled phone photo from {w}x{h} to {bgr.shape[1]}x{bgr.shape[0]}")
        try:
            result = _decode_frame(bgr, config)
        except Exception as e:
            logging.exception("decode failed")
            return jsonify({"status": "SERVER_EXCEPTION",
                              "detail": str(e)}), 500
        state.update(result)
        return jsonify(result)

    return app
