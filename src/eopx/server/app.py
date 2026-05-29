"""Esoptron live-scan Flask app (DEV / DEMO ONLY).

.. warning::

    This module is a single-tenant developer demo. It is NOT suitable for
    multi-user production deployments:

    * The decoded vault state is held as one shared in-memory ``ServerState``
      object — every concurrent caller sees the latest scan from any user.
    * ``ServerConfig.spinor_hex`` / ``known_seed_hex`` are set once at boot,
      so the process is bound to a single vault.
    * The ``/scan`` HTML route ships a deprecated mobile crypto chain that
      diverges from the canonical Python core / PWA chain. It is OFF by
      default and gated behind ``ESOPTRON_ENABLE_LEGACY_MOBILE_HTML=1``.
    * ``/api/register_psnx`` and ``/api/frame`` are rate-limited but have no
      auth and write to local files when debug dumping is enabled.

    For production multi-tenant deployments use :mod:`eopx.server.pwa_api`
    behind a reverse proxy + auth layer, or roll your own service that
    consumes :mod:`eopx.flows`.

Routes
------
GET  /              Dashboard (PC). Shows the QR code with the phone URL
                    and the live decode status.
GET  /scan          Mobile-friendly page that opens the phone's native
                    camera and uploads each snapshot to /api/frame.
                    DISABLED by default; set
                    ``ESOPTRON_ENABLE_LEGACY_MOBILE_HTML=1`` to re-enable.
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
import json
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
            _save_diagnostic_img(pil, "diagnostic_cube_crop.png")
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


def _save_diagnostic_img(pil: Image.Image, filename: str) -> None:
    """Save a PIL image diagnostic."""
    try:
        out = Path("out")
        out.mkdir(exist_ok=True)
        pil.save(str(out / filename), format="PNG")
    except Exception:
        pass


def _save_diagnostic(rect_a4_bgr: np.ndarray, cfg: ServerConfig) -> None:
    """Save the rectified A4 image for visual debugging."""
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
_PRIVATE_FIELD_MARKERS = (
    "secret", "seed", "master", "blend", "entropy", "private",
)


def _contains_private_field(obj: Any, path: str = "") -> Optional[str]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_l = str(key).lower()
            if any(marker in key_l for marker in _PRIVATE_FIELD_MARKERS):
                if key_l not in {"security"}:
                    return f"{path}.{key}" if path else str(key)
            found = _contains_private_field(
                value, f"{path}.{key}" if path else str(key))
            if found:
                return found
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            found = _contains_private_field(value, f"{path}[{idx}]")
            if found:
                return found
    return None


def _validate_public_psnx(psnx: Dict[str, Any]) -> Optional[str]:
    if not isinstance(psnx, dict):
        return "payload must be a JSON object"
    if psnx.get("format") != "psnx":
        return "format must be psnx"
    if psnx.get("version") != 1:
        return "version must be 1"
    if psnx.get("security") != "public":
        return "security must be public"
    vault_id = psnx.get("vault_id")
    if not isinstance(vault_id, str) or not _VAULT_ID_RE.match(vault_id):
        return "vault_id must match vlt_<32hex>"
    for key in ("ceremony_fp_hex", "vault_fp_hex", "enrollment_fp_hex"):
        value = psnx.get(key)
        if not isinstance(value, str) or not _HEX64_RE.match(value):
            return f"{key} must be 64 lowercase hex chars"
    public_tag = psnx.get("public_tag_hex")
    if not isinstance(public_tag, str) or not _HEX32_RE.match(public_tag):
        return "public_tag_hex must be 32 lowercase hex chars"
    private_path = _contains_private_field(psnx)
    if private_path:
        return f"private-looking field rejected: {private_path}"
    return None


def _register_public_psnx(psnx: Dict[str, Any]) -> Dict[str, Any]:
    error = _validate_public_psnx(psnx)
    if error:
        return {"status": "REJECTED", "detail": error}

    registry_dir = Path("out") / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)

    vault_id = psnx["vault_id"]
    psnx_path = registry_dir / f"{vault_id}.psnx.json"
    record = {
        "registered_at": time.time(),
        "vault_id": vault_id,
        "ceremony_fp_hex": psnx["ceremony_fp_hex"],
        "vault_fp_hex": psnx["vault_fp_hex"],
        "enrollment_fp_hex": psnx["enrollment_fp_hex"],
        "public_tag_hex": psnx["public_tag_hex"],
        "psnx_sha256_hex": hashlib.sha256(
            json.dumps(psnx, sort_keys=True).encode("utf-8")).hexdigest(),
    }

    psnx_path.write_text(
        json.dumps(psnx, indent=2, sort_keys=True), encoding="utf-8")
    with (registry_dir / "vault_registry.jsonl").open(
            "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")

    return {"status": "REGISTERED", **record,
            "path": str(psnx_path).replace("\\", "/")}


# ---------------------------------------------------------------------------
# HTML templates (inlined to keep the prototype single-file)
# ---------------------------------------------------------------------------

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

SCAN_HTML = r"""
<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Esoptron scan</title>
<style>
 *{box-sizing:border-box}
 body { font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
        background:#101018; color:#e8e8ee; margin:0; padding:16px; }
 h1 { font-weight:400; font-size:22px; margin:8px 0 18px; }
 .card { background:#1c1c28; border-radius:14px; padding:16px;
         margin-bottom:14px; }
 button, label.btn {
   display:block; width:100%; padding:18px; border:none;
   border-radius:14px; background:#3060ff; color:#fff;
   font-size:20px; font-weight:600; text-align:center;
 }
 .btn-alt { background:#2a2a3a; margin-top:10px; }
 input[type=file] { display:none; }
 #preview { width:100%; border-radius:10px; margin-top:12px; display:none;}
 .row { display:flex; justify-content:space-between; margin:5px 0; }
 .k { color:#9be; }
 .v { color:#fff; font-family: Menlo, Consolas, monospace; font-size:13px;
      word-break:break-all; text-align:right; max-width:60%; }
 .pill { padding:4px 10px; border-radius:99px; font-weight:700; }
 .ok   { background:#0d3; color:#001; }
 .warn { background:#f93; color:#101; }
 .err  { background:#e34; color:#fff; }
 .small { color:#b8b8c8; font-size:13px; line-height:1.35; }
 .secret { background:#12121b; border:1px solid #34344a; border-radius:10px;
           color:#fff; font-family:Menlo,Consolas,monospace; padding:10px;
           word-break:break-all; margin-top:8px; }
 input[type=password] { width:100%; padding:14px; border-radius:10px;
                        border:1px solid #34344a; background:#101018;
                        color:#fff; margin:10px 0; font-size:16px; }
</style></head><body>
<h1>Esoptron — phone scan ({{ mode }})</h1>

<div class="card">
  <button id="camBtn" class="btn">📷 Ouvrir la caméra</button>
  <video id="video" style="display:none;width:100%;border-radius:10px" playsinline></video>
  <canvas id="canvas" style="display:none"></canvas>
  <button id="snapBtn" class="btn btn-alt" style="display:none">📸 Capturer</button>
  <form id="form" method="post" action="/api/frame" enctype="multipart/form-data" style="display:none">
    <label class="btn" for="file">📷 Capturer depuis la galerie</label>
    <input id="file" name="frame" type="file" accept="image/*" capture="environment">
  </form>
  <img id="preview" alt="">
</div>

<div class="card" id="result">
  <i>Appuie sur "Ouvrir la caméra" puis pointe vers la feuille et capture.</i>
</div>

<script>
const result = document.getElementById('result');
const preview = document.getElementById('preview');
const camBtn = document.getElementById('camBtn');
const snapBtn = document.getElementById('snapBtn');
const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const form = document.getElementById('form');
const fileEl = document.getElementById('file');

// --- Camera stream method (full resolution) ---
let stream = null;
camBtn.onclick = async () => {
  try {
    // Request high-resolution back camera
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment',
               width: { ideal: 4032 },
               height: { ideal: 3024 } }
    });
    video.srcObject = stream;
    video.style.display = 'block';
    snapBtn.style.display = 'block';
    camBtn.textContent = '📷 Caméra active';
    camBtn.disabled = true;
    await video.play();
  } catch(e) {
    // Fallback to file input
    result.innerHTML = '<span class="warn pill">Caméra non disponible</span> Utilise le bouton galerie ci-dessous.';
    form.style.display = 'block';
    camBtn.style.display = 'none';
  }
};

snapBtn.onclick = () => {
  if (!video.videoWidth) return;
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext('2d').drawImage(video, 0, 0);
  preview.src = canvas.toDataURL('image/jpeg', 0.92);
  preview.style.display = 'block';

  result.innerHTML = '<i>analyzing... (ArUco + decode)</i>';

  // Send as blob for full resolution
  canvas.toBlob(blob => {
    const fd = new FormData(); fd.append('frame', blob, 'capture.jpg');
    fetch('/api/frame', { method: 'POST', body: fd })
      .then(r => r.json()).then(j => render(j))
      .catch(e => { result.innerHTML = '<span class="err pill">network error</span> ' + e; });
  }, 'image/jpeg', 0.95);

  // Stop camera
  if (stream) { stream.getTracks().forEach(t => t.stop()); }
  video.style.display = 'none';
  snapBtn.style.display = 'none';
  camBtn.textContent = '📷 Ouvrir la caméra';
  camBtn.disabled = false;
};

// --- File upload fallback ---
fileEl.addEventListener('change', async () => {
  if (!fileEl.files.length) return;
  const f = fileEl.files[0];
  const url = URL.createObjectURL(f);
  preview.src = url; preview.style.display = 'block';
  const tmp = new Image();
  tmp.onload = () => {
    if (Math.max(tmp.width, tmp.height) < 1500) {
      result.innerHTML = '<span class="err pill">Photo trop petite!</span> Utilise le bouton "Ouvrir la caméra" pour une meilleure résolution.';
      return;
    }
    result.innerHTML = '<i>analyzing...</i>';
    const fd = new FormData(); fd.append('frame', f);
    fetch('/api/frame', { method: 'POST', body: fd })
      .then(r => r.json()).then(j => render(j))
      .catch(e => { result.innerHTML = '<span class="err pill">network error</span> ' + e; });
  };
  tmp.src = url;
  fileEl.value = '';
});

function utf8(s) { return new TextEncoder().encode(s); }
function concatBytes(...arrays) {
  let n = arrays.reduce((acc, a) => acc + a.length, 0);
  let out = new Uint8Array(n), p = 0;
  for (const a of arrays) { out.set(a, p); p += a.length; }
  return out;
}
function hexToBytes(hex) {
  if (hex.length % 2) throw new Error('hex length must be even');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
function randomBytes(n) {
  if (!window.crypto || !crypto.getRandomValues) {
    throw new Error('crypto.getRandomValues indisponible sur ce navigateur');
  }
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

const K256 = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
function sha256(bytes) {
  const bitLen = bytes.length * 8;
  const paddedLen = (((bytes.length + 9 + 63) >> 6) << 6);
  const msg = new Uint8Array(paddedLen);
  msg.set(bytes);
  msg[bytes.length] = 0x80;
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  msg[paddedLen-8] = (hi >>> 24) & 255; msg[paddedLen-7] = (hi >>> 16) & 255;
  msg[paddedLen-6] = (hi >>> 8) & 255;  msg[paddedLen-5] = hi & 255;
  msg[paddedLen-4] = (lo >>> 24) & 255; msg[paddedLen-3] = (lo >>> 16) & 255;
  msg[paddedLen-2] = (lo >>> 8) & 255;  msg[paddedLen-1] = lo & 255;
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
      h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = new Uint32Array(64);
  for (let off = 0; off < msg.length; off += 64) {
    for (let i=0; i<16; i++) {
      const j = off + i*4;
      w[i] = ((msg[j]<<24) | (msg[j+1]<<16) | (msg[j+2]<<8) | msg[j+3]) >>> 0;
    }
    for (let i=16; i<64; i++) {
      const s0 = (rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>>3)) >>> 0;
      const s1 = (rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>>10)) >>> 0;
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i=0; i<64; i++) {
      const S1 = (rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = (rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d + temp1) >>> 0; d=c; c=b; b=a; a=(temp1 + temp2) >>> 0;
    }
    h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
    h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
  }
  const hs = [h0,h1,h2,h3,h4,h5,h6,h7];
  const out = new Uint8Array(32);
  hs.forEach((v, i) => {
    out[i*4] = (v>>>24)&255; out[i*4+1] = (v>>>16)&255;
    out[i*4+2] = (v>>>8)&255; out[i*4+3] = v&255;
  });
  return out;
}
function hmacSha256(key, msg) {
  if (key.length > 64) key = sha256(key);
  const k = new Uint8Array(64); k.set(key);
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i=0; i<64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
  return sha256(concatBytes(opad, sha256(concatBytes(ipad, msg))));
}
function hkdfSha256(ikm, salt, info, length) {
  if (!salt || !salt.length) salt = new Uint8Array(32);
  const prk = hmacSha256(salt, ikm);
  let okm = new Uint8Array(0), t = new Uint8Array(0), c = 1;
  while (okm.length < length) {
    t = hmacSha256(prk, concatBytes(t, info, new Uint8Array([c++])));
    okm = concatBytes(okm, t);
  }
  return okm.slice(0, length);
}
function downloadJson(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
async function registerPublicPsnx(psnx) {
  const r = await fetch('/api/register_psnx', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(psnx)
  });
  const j = await r.json();
  if (!r.ok || j.status !== 'REGISTERED') {
    throw new Error(j.detail || j.status || 'registration failed');
  }
  return j;
}
function recoveryCode(bytes) {
  return bytesToHex(bytes).match(/.{1,4}/g).join(' ');
}
async function encryptBlendData(passphrase, payload) {
  if (!window.crypto || !crypto.subtle) {
    throw new Error('Chiffrement AES-GCM indisponible: utilise HTTPS ou laisse le mot de passe vide pour exporter le fichier privé non chiffré.');
  }
  const salt = randomBytes(16), iv = randomBytes(12);
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:210000, hash:'SHA-256'},
    keyMaterial, {name:'AES-GCM', length:256}, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    {name:'AES-GCM', iv}, key, enc.encode(JSON.stringify(payload))));
  return {
    format: 'blend_data.encrypted',
    version: 1,
    cipher: 'AES-256-GCM',
    kdf: {name:'PBKDF2-HMAC-SHA256', iterations:210000,
          salt_hex: bytesToHex(salt)},
    iv_hex: bytesToHex(iv),
    ciphertext_hex: bytesToHex(ct)
  };
}
async function createOnboardingPackage(scan) {
  const out = document.getElementById('onboardOut');
  try {
    const passEl = document.getElementById('vaultPass');
    const passphrase = passEl ? passEl.value : '';
    const ceremonySeed = hexToBytes(scan.ceremony_seed_hex);
    const ceremonyFp = hexToBytes(scan.ceremony_fp_hex);
    const deviceEntropy = randomBytes(32);
    const vaultSeed = hkdfSha256(
      concatBytes(ceremonySeed, deviceEntropy), new Uint8Array(0),
      utf8('esoptron.mobile.genesis.vault_seed.sha256.v1'), 32);
    const masterKey = hkdfSha256(
      vaultSeed, new Uint8Array(0),
      utf8('esoptron.mobile.vault.master_key.sha256.v1'), 32);
    const vaultFp = sha256(concatBytes(
      utf8('esoptron.mobile.vault_fp.sha256.v1\n'), vaultSeed));
    const enrollmentFp = hkdfSha256(
      concatBytes(vaultFp, deviceEntropy), new Uint8Array(0),
      utf8('esoptron.mobile.enrollment_fp.sha256.v1'), 32);
    const publicTag = hkdfSha256(
      masterKey, ceremonyFp,
      utf8('esoptron.mobile.public_tag.sha256.v1'), 16);
    const vaultId = 'vlt_' + bytesToHex(vaultFp.slice(0, 16));
    const now = new Date().toISOString();
    const psnx = {
      format: 'psnx',
      version: 1,
      vault_id: vaultId,
      created_at: now,
      ceremony_fp_hex: scan.ceremony_fp_hex,
      vault_fp_hex: bytesToHex(vaultFp),
      enrollment_fp_hex: bytesToHex(enrollmentFp),
      public_tag_hex: bytesToHex(publicTag),
      kdf: 'HKDF-HMAC-SHA256 browser-local v1',
      security: 'public'
    };
    const psnxHash = bytesToHex(sha256(utf8(JSON.stringify(psnx))));
    const blendPlain = {
      format: 'blend_data',
      version: 1,
      security: 'private',
      vault_id: vaultId,
      created_at: now,
      linked_psnx_sha256_hex: psnxHash,
      recovery: {
        mode: 'genesis_sheet_plus_device_entropy',
        device_entropy_recovery_code: recoveryCode(deviceEntropy)
      },
      secrets: {
        device_entropy_hex: bytesToHex(deviceEntropy),
        vault_seed_hex: bytesToHex(vaultSeed),
        master_key_hex: bytesToHex(masterKey)
      }
    };
    let blend = blendPlain, blendName = `${vaultId}.blend_data.json`;
    if (passphrase.length) {
      blend = await encryptBlendData(passphrase, blendPlain);
      blend.format = 'blend_data.encrypted';
      blend.vault_id = vaultId;
      blend.linked_psnx_sha256_hex = psnxHash;
      blendName = `${vaultId}.blend_data.enc.json`;
    }
    downloadJson(`${vaultId}.psnx.json`, psnx);
    downloadJson(blendName, blend);
    const registered = await registerPublicPsnx(psnx);
    out.innerHTML =
      `<div class="row"><span class="k">vault_id</span><span class="v">${vaultId}</span></div>` +
      `<div class="row"><span class="k">registry</span><span class="pill ok">${registered.status}</span></div>` +
      `<div class="row"><span class="k">vault_fp</span><span class="v">${psnx.vault_fp_hex}</span></div>` +
      `<p class="small"><b>Code de récupération appareil:</b></p>` +
      `<div class="secret">${blendPlain.recovery.device_entropy_recovery_code}</div>` +
      `<p class="small">Sauvegarde ce code hors ligne. Pour récupérer: rescanner la feuille Genesis + saisir ce code.</p>`;
  } catch (e) {
    out.innerHTML = `<span class="err pill">onboarding error</span> ${e.message || e}`;
  }
}

function render(j) {
  let cls = 'warn'; const s = j.status || '?';
  if (s === 'OK' || s === 'MATCH' || s === 'ENROLLED'
      || s === 'GENESIS') cls = 'ok';
  else if (s === 'NO_MARKERS') cls = 'warn';
  else if (s === 'CROP_FAIL' || s === 'DECODE_FAIL'
            || s === 'MISMATCH' || s === 'REJECTED'
            || s === 'VERIFY_FAIL') cls = 'err';
  let html = `<div class="row"><span class="k">status</span><span class="pill ${cls}">${s}</span></div>`;
  for (const [k, v] of Object.entries(j)) {
    if (k === 'status') continue;
    if (k === 'ceremony_seed_hex') continue;
    html += `<div class="row"><span class="k">${k}</span><span class="v">${v}</span></div>`;
  }
  if (s === 'GENESIS' && j.ceremony_seed_hex) {
    html += `<div class="card" style="margin:14px 0 0;padding:12px;background:#161620">
      <p class="small"><b>Onboarding local:</b> le serveur a seulement décodé la feuille.
      Le téléphone va générer son secret, créer <code>.psnx</code> public et
      <code>.blend_data</code> privé localement.</p>
      <input id="vaultPass" type="password" autocomplete="new-password"
             placeholder="Mot de passe optionnel pour chiffrer blend_data">
      <button id="makeVaultBtn" class="btn">Créer mon vault local</button>
      <div id="onboardOut" class="small" style="margin-top:12px"></div>
    </div>`;
  }
  result.innerHTML = html;
  if (s === 'GENESIS' && j.ceremony_seed_hex) {
    document.getElementById('makeVaultBtn').onclick = () => createOnboardingPackage(j);
  }
}
</script>
</body></html>
"""


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------

from .rate_limit import rate_limit as _rate_limit

_MAX_FRAME_BYTES = 12 * 1024 * 1024  # 12 MB / upload (hard cap)
_MAX_IMAGE_PIXELS = 25_000_000        # 25 megapixels max
Image.MAX_IMAGE_PIXELS = _MAX_IMAGE_PIXELS

_ENABLE_LEGACY_MOBILE_HTML = (
    os.environ.get("ESOPTRON_ENABLE_LEGACY_MOBILE_HTML", "0") == "1"
)
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
        # The inline mobile HTML uses a divergent SHA-256 KDF chain
        # (`esoptron.mobile.*`) that is bytewise incompatible with the canonical
        # Python core / PWA chain (`esoptron.vault.*`, SHA3-512). It is kept
        # only as a developer demo and is OFF by default.
        if not _ENABLE_LEGACY_MOBILE_HTML:
            if _PWA_REDIRECT_URL:
                return (
                    f'<meta http-equiv="refresh" content="0; url={_PWA_REDIRECT_URL}">'
                    f'<p>Redirecting to PWA at <a href="{_PWA_REDIRECT_URL}">'
                    f'{_PWA_REDIRECT_URL}</a></p>'
                ), 200
            return (
                "<h1>Legacy mobile scan disabled</h1>"
                "<p>This endpoint uses a deprecated KDF chain. "
                "Set <code>ESOPTRON_PWA_URL</code> to redirect, or "
                "<code>ESOPTRON_ENABLE_LEGACY_MOBILE_HTML=1</code> "
                "to re-enable (dev only).</p>"
            ), 410  # Gone
        return render_template_string(SCAN_HTML, mode=config.mode)

    @app.route("/api/config")
    def api_config():
        return jsonify({"mode": config.mode,
                         "has_spinor": bool(config.spinor_hex),
                         "has_known_seed": bool(config.known_seed_hex)})

    @app.route("/api/register_psnx", methods=["POST"])
    @_rate_limit("default")
    def api_register_psnx():
        if not _ENABLE_LEGACY_MOBILE_HTML:
            return jsonify({"status": "DISABLED",
                            "detail": "legacy mobile flow disabled"}), 410
        psnx = request.get_json(silent=True)
        result = _register_public_psnx(psnx)
        status_code = 200 if result.get("status") == "REGISTERED" else 400
        return jsonify(result), status_code

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
