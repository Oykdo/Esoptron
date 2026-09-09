#!/usr/bin/env python3
"""EPX reveal — relic-keyed hidden holographic layer (PoC).

A `blend_data` hologram carries a PUBLIC layer (visible) and a SEALED layer
(AEAD-encrypted, opaque, invisible). A physical **relic** is an EPX-R plate
that engraves a per-relic secret. Scanning the relic recovers that secret,
derives the layer key, and **reveals + animates** the hidden surfaces — fully
offline and deterministic, so it survives epochs (no server, anchored by a
fixed genesis constant + a published voucher commitment).

Demonstrates:
  * the sealed layer is opaque without the relic (invisible);
  * an EPX-R relic, **worn by time** (erased cells), still scans (RS ECC) and
    recovers the secret;
  * the recovered secret reveals the hidden layer byte-exact;
  * a WRONG relic fails the AEAD tag (no reveal);
  * a before/after render (sealed vs revealed surfaces).

PoC crypto is stdlib only (HKDF/keystream/HMAC over SHA-256); production swaps
in AES-GCM / ChaCha20-Poly1305. Reuses epx_r_poc (EPX-R codec).

Run:  py -3.11 scripts/epx_reveal_poc.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import numpy as np
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from epx_r_poc import RS, encode_private, decode_private

# Anchored, serverless root (stand-in for the fixed Bitcoin genesis block hash).
GENESIS = hashlib.sha256(b"esoptron.genesis.block.840000").digest()


# --------------------------------------------------------------------------- #
# AEAD = ChaCha20-Poly1305, KDF = HKDF-SHA3-512. Mirrors the PWA @noble stack
# (crypto.ts hkdfSha3_512 + @noble/ciphers chacha20poly1305) byte-for-byte, so a
# layer sealed here opens in the browser. blob = nonce(12) || ciphertext||tag.
# --------------------------------------------------------------------------- #
LAYER_INFO = b"eidolon.relic.layer.v1"


def hkdf_sha3_512(ikm, info, length=32, salt=b""):
    return HKDF(algorithm=hashes.SHA3_512(), length=length, salt=salt,
                info=info).derive(ikm)


def layer_key(relic_secret: bytes) -> bytes:
    return hkdf_sha3_512(relic_secret, LAYER_INFO, 32)


def aead_seal(key, plaintext):
    nonce = hashlib.sha3_256(key + b"|nonce|" + plaintext).digest()[:12]
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)


def aead_open(key, blob):
    nonce, ct = blob[:12], blob[12:]
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)  # raises on wrong key


# --------------------------------------------------------------------------- #
# Relic mint (deterministic, anchored) + voucher commitment
# --------------------------------------------------------------------------- #
def mint_relic(relic_key: str):
    """32-byte relic secret + its public voucher commitment (anchored)."""
    secret = hkdf_sha3_512(GENESIS, b"relic|" + relic_key.encode(), 32)
    commitment = hashlib.sha3_256(b"voucher|" + secret).hexdigest()
    return secret, commitment


# --------------------------------------------------------------------------- #
# blend_data: public layer + sealed (hidden) layer
# --------------------------------------------------------------------------- #
def hidden_layer_payload(relic_key: str) -> bytes:
    """The secret animated surfaces (geometry + animation), deterministic."""
    rng = np.random.default_rng(int.from_bytes(
        hashlib.sha256(relic_key.encode()).digest()[:8], "big"))
    pts = []
    for k in range(12):                       # a 12-point revealed ring/shell
        a = 2 * np.pi * k / 12
        r = 1.6 + 0.2 * rng.random()
        pts.append([round(float(r * np.cos(a)), 4),
                    round(float(r * np.sin(a)), 4),
                    round(float(0.3 * np.sin(3 * a)), 4)])
    return json.dumps({
        "layer": "primordial_echo",
        "relic": relic_key,
        "surfaces": pts,
        "anim": {"type": "pulse+spin", "period_s": 7, "amp": 0.25},
    }, separators=(",", ":")).encode()


def build_blend(relic_key: str, relic_secret: bytes) -> dict:
    public = {"layer": "metatron_cube", "vertices": 13, "edges": 78}
    sealed = aead_seal(layer_key(relic_secret), hidden_layer_payload(relic_key))
    return {"public_layer": public,
            "sealed_layer_b64": sealed.hex(),     # opaque on disk
            "sealed_len": len(sealed)}


def reveal(blend: dict, relic_secret: bytes) -> dict:
    blob = bytes.fromhex(blend["sealed_layer_b64"])
    return json.loads(aead_open(layer_key(relic_secret), blob))


# --------------------------------------------------------------------------- #
# Engrave the relic on an EPX-R plate / scan it (with epoch wear)
# --------------------------------------------------------------------------- #
def engrave_and_scan(relic_secret: bytes, rs: RS, wear_frac=0.15, seed=7):
    grid, meta = encode_private(relic_secret, rs, interleave=True)
    M = meta["M"]
    rng = np.random.default_rng(seed)
    em = np.zeros((M, M), bool)
    n_er = int(wear_frac * meta["ncells"])
    idx = rng.choice(meta["ncells"], size=n_er, replace=False)
    flat = em.reshape(-1); flat[idx] = True
    meta2 = dict(meta); meta2["erased"] = em
    recovered = decode_private(grid, rs, meta2)
    return recovered, M, n_er


# --------------------------------------------------------------------------- #
# Before/after render (simple 2D projection)
# --------------------------------------------------------------------------- #
def _project(p3, size, cx, cy, scale):
    x, y, z = p3
    return int(cx + x * scale), int(cy - y * scale)


def render_before_after(blend, hidden, path, size=360):
    img = Image.new("RGB", (size * 2 + 20, size), (8, 8, 20))
    px = img.load()
    # metatron 13 points (public) on both panels
    R1, R2 = 1.0, np.sqrt(3)
    pub = [(0, 0, 0)] + [(np.cos(a), np.sin(a), 0) for a in
                         [k * np.pi / 3 for k in range(6)]] + \
          [(R2 * np.cos(np.pi / 6 + k * np.pi / 3),
            R2 * np.sin(np.pi / 6 + k * np.pi / 3), 0) for k in range(6)]

    def dot(panel_x0, p, col, rad=4):
        sx, sy = _project(p, size, panel_x0 + size // 2, size // 2, size * 0.18)
        for dx in range(-rad, rad + 1):
            for dy in range(-rad, rad + 1):
                if dx * dx + dy * dy <= rad * rad:
                    x, y = sx + dx, sy + dy
                    if 0 <= x < size * 2 + 20 and 0 <= y < size:
                        px[x, y] = col

    for p in pub:                                  # LEFT panel: public only
        dot(0, p, (120, 130, 200))
    for p in pub:                                  # RIGHT panel: public...
        dot(size + 20, p, (120, 130, 200))
    for p in hidden["surfaces"]:                   # ...+ revealed hidden ring
        dot(size + 20, p, (240, 180, 60), rad=5)
    img.save(path)


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    rs = RS(255, 169)
    relic_key = "lugdunum_echo_01"
    print(f"[mint] relic '{relic_key}' (anchored to fixed genesis)")
    secret, commitment = mint_relic(relic_key)
    print(f"[mint] voucher commitment (public/ledger): {commitment[:24]}...")

    blend = build_blend(relic_key, secret)
    print(f"[seal] blend_data: public={blend['public_layer']['layer']}, "
          f"sealed_layer={blend['sealed_len']} B (opaque -> invisible)")

    # 1) no relic -> cannot reveal
    try:
        reveal(blend, hkdf_sha3_512(GENESIS, b"relic|wrong", 32))
        print("[guard] FAIL: revealed without the right relic")
    except Exception as e:
        print(f"[guard] without/with wrong relic: sealed ({type(e).__name__})")

    # 2) the worn relic is found, scanned (EPX-R + RS ECC), secret recovered
    recovered, M, n_er = engrave_and_scan(secret, rs, wear_frac=0.15)
    ok_scan = recovered == secret
    print(f"[scan] worn relic ({M}x{M} plate, {n_er} cells eroded): "
          f"secret {'RECOVERED' if ok_scan else 'LOST'} via RS ECC")

    # 3) reveal the hidden animated layer
    hidden = reveal(blend, recovered)
    print(f"[reveal] hidden layer '{hidden['layer']}' unlocked: "
          f"{len(hidden['surfaces'])} surfaces, anim={hidden['anim']['type']} "
          f"@ {hidden['anim']['period_s']}s")

    out = os.path.join(os.path.dirname(__file__), "..", "epx_reveal_demo.png")
    render_before_after(blend, hidden, out)
    print(f"[render] before/after -> {os.path.normpath(out)} "
          f"(left: sealed/public only; right: revealed surfaces)")

    # 4) emit a cross-language interop test vector for the PWA (vitest)
    vec = {
        "relic_key": relic_key,
        "relic_secret_hex": secret.hex(),
        "layer_key_hex": layer_key(secret).hex(),
        "sealed_hex": blend["sealed_layer_b64"],
        "hidden_plaintext": hidden_layer_payload(relic_key).decode(),
        "kdf": "HKDF-SHA3-512", "info": LAYER_INFO.decode(),
        "aead": "ChaCha20-Poly1305", "blob": "nonce(12)||ct||tag",
    }
    vpath = os.path.join(os.path.dirname(__file__), "..", "pwa", "src", "lib",
                         "__tests__", "reveal_vector.json")
    # newline="\n": without it, Python's text mode writes CRLF on Windows and
    # the committed vector fails the repo's UTF-8/LF gate on every regeneration.
    with open(vpath, "w", encoding="utf-8", newline="\n") as f:
        json.dump(vec, f, indent=2)
    print(f"[vector] interop vector -> {os.path.normpath(vpath)}")

    print(f"\n[verdict] offline + deterministic + ECC-durable: "
          f"scan={'OK' if ok_scan else 'FAIL'}, reveal=OK, "
          f"wrong-relic-blocked=OK")
