"""Genesis Card PNG renderer — Python / Pillow backend.

Mirror of :mod:`pwa/src/lib/genesisCard.ts`. Both renderers consume the
same inputs (sequence, archetype, BTC block info, signed seal,
deployment pubkey) and produce a near-identical 1200×1800 portrait
card. Layout values are kept in lockstep with the TS module so a card
exported via the CLI is visually compatible with one exported by the
PWA.

Use cases:
  * Eidolon CLI ``--export-genesis-png`` post-provisioning hook
  * Server-side rendering for users without canvas (printed mailer)
  * Smoke tests with golden image diffs

The QR payload carries only the lightweight pointer (no Dilithium
signature) — see :func:`build_qr_payload`. Offline verification needs
the companion sidecar produced by :func:`build_seal_envelope`.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from typing import Optional

import qrcode
from qrcode.constants import ERROR_CORRECT_Q
from PIL import Image, ImageDraw, ImageFont

from .genesis_token import (
    Archetype,
    GenesisSeal,
    archetype_of,
    archetypes_commitment_hex,
)


# ---------------------------------------------------------------------------
# Inputs / payloads
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GenesisCardInputs:
    vault_fp_hex: str
    sequence: int
    btc_block_hash_hex: str
    btc_block_height: int
    deployment_pk_hex: str
    genesis_seal: GenesisSeal
    archetype: Optional[Archetype] = None
    anchor_url: Optional[str] = None
    minted_at: Optional[str] = None


def _resolve_archetype(inputs: GenesisCardInputs) -> Archetype:
    expected = archetype_of(inputs.genesis_seal.archetype_id)
    if inputs.archetype is None:
        return expected
    if inputs.archetype.id != inputs.genesis_seal.archetype_id:
        raise ValueError(
            "archetype.id does not match seal.archetype_id "
            f"({inputs.archetype.id} != {inputs.genesis_seal.archetype_id})"
        )
    return inputs.archetype


def build_qr_payload(inputs: GenesisCardInputs) -> dict:
    """Lightweight pointer payload — same shape as ``buildGenesisQrPayload``
    in the TS module. Fits in a printable QR (≤ 500 bytes JSON)."""
    payload: dict = {
        "type": "esoptron-genesis-card",
        "schema_version": inputs.genesis_seal.schema_version,
        "vault_fp_hex": inputs.vault_fp_hex,
        "sequence": inputs.sequence,
        "archetype_id": inputs.genesis_seal.archetype_id,
        "btc_block_hash_hex": inputs.btc_block_hash_hex,
        "btc_block_height": inputs.btc_block_height,
        "signer_pk_fp_hex": inputs.genesis_seal.signer_pk_fp_hex,
        "archetypes_commitment_hex": archetypes_commitment_hex(),
    }
    if inputs.anchor_url:
        payload["anchor_url"] = inputs.anchor_url
    return payload


def build_seal_envelope(inputs: GenesisCardInputs) -> dict:
    """Sidecar envelope carrying the full Dilithium5 signature for
    offline verification. Pair with the PNG card."""
    return {
        "type": "esoptron-genesis-seal",
        "schema_version": inputs.genesis_seal.schema_version,
        "pointer": build_qr_payload(inputs),
        "deployment_pk_hex": inputs.deployment_pk_hex,
        "signature_hex": inputs.genesis_seal.signature_hex,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


CARD_W = 1200
CARD_H = 1800
BAND_H = 100
QR_SIZE = 500
QR_TOP = 1080
QR_LEFT = (CARD_W - QR_SIZE) // 2


def _hsl_to_rgb(hue: float, sat: float, light: float) -> tuple[int, int, int]:
    """Convert HSL (0..360, 0..100, 0..100) to RGB (0..255). Mirrors the
    canvas CSS color resolution so PNG output matches the TS renderer."""
    h = hue / 360.0
    s = sat / 100.0
    li = light / 100.0
    if s == 0:
        v = int(round(li * 255))
        return v, v, v

    def hue_to_rgb(p: float, q: float, t: float) -> float:
        if t < 0:
            t += 1
        if t > 1:
            t -= 1
        if t < 1 / 6:
            return p + (q - p) * 6 * t
        if t < 1 / 2:
            return q
        if t < 2 / 3:
            return p + (q - p) * (2 / 3 - t) * 6
        return p

    q = li * (1 + s) if li < 0.5 else li + s - li * s
    p = 2 * li - q
    r = hue_to_rgb(p, q, h + 1 / 3)
    g = hue_to_rgb(p, q, h)
    b = hue_to_rgb(p, q, h - 1 / 3)
    return int(round(r * 255)), int(round(g * 255)), int(round(b * 255))


def _font(size: int, *, bold: bool = False) -> ImageFont.ImageFont:
    """Best-effort font loader. Falls back to default PIL font when no
    system fonts are present (e.g. headless CI). The card still renders,
    just with simpler glyphs."""
    candidates_bold = [
        "Inter-Bold.ttf", "Arial Bold.ttf", "DejaVuSans-Bold.ttf",
        "Verdana Bold.ttf", "arialbd.ttf",
    ]
    candidates_regular = [
        "Inter-Regular.ttf", "Arial.ttf", "DejaVuSans.ttf",
        "Verdana.ttf", "arial.ttf",
    ]
    candidates = candidates_bold if bold else candidates_regular
    for name in candidates:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _fmt_fp(hex_str: str, head: int = 12, tail: int = 8) -> str:
    if len(hex_str) <= head + tail:
        return hex_str
    return f"{hex_str[:head]}…{hex_str[-tail:]}"


def _draw_council_star(draw: ImageDraw.ImageDraw,
                       cx: int, cy: int,
                       outer_r: int, inner_r: int,
                       hue: float) -> None:
    """88-point star around the giant glyph; matches the canvas version."""
    import math
    r, g, b = _hsl_to_rgb(hue, 70, 50)
    color = (r, g, b, 56)  # alpha ≈ 0.22
    points = 88
    for i in range(points):
        angle = (i / points) * 2 * math.pi - math.pi / 2
        rad = outer_r if (i % 8 == 0) else inner_r
        x = cx + math.cos(angle) * rad
        y = cy + math.sin(angle) * rad
        draw.line([(cx, cy), (x, y)], fill=color, width=1)


def render_genesis_card_png(inputs: GenesisCardInputs) -> bytes:
    """Render the Genesis card as a PNG byte string.

    Always returns RGBA-flattened-to-RGB PNG. The output is byte-stable
    given the same inputs, modulo system font availability (the
    PIL-default fallback produces tiny text but no missing pixels).
    """
    archetype = _resolve_archetype(inputs)
    hue = float(archetype.color_hue)
    payload = build_qr_payload(inputs)

    bg_rgb = _hsl_to_rgb(hue, 30, 96)
    img = Image.new("RGB", (CARD_W, CARD_H), bg_rgb)
    overlay = Image.new("RGBA", (CARD_W, CARD_H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    odraw = ImageDraw.Draw(overlay)

    # Frame
    draw.rectangle([(30, 30), (CARD_W - 30, CARD_H - 30)],
                   outline=(26, 26, 38), width=6)
    draw.rectangle([(50, 50), (CARD_W - 50, CARD_H - 50)],
                   outline=(26, 26, 38), width=1)

    # Top hue band with horizontal gradient
    band = Image.new("RGB", (CARD_W - 120, BAND_H), (0, 0, 0))
    bd = ImageDraw.Draw(band)
    for x in range(band.width):
        t = x / max(1, band.width - 1)
        # Mid-stop at t=0.5 dips into more-saturated darker variant
        sat = 80 - 30 * (1 - abs(0.5 - t) * 2)
        light = 55 - 10 * (1 - abs(0.5 - t) * 2)
        bd.line([(x, 0), (x, band.height)],
                fill=_hsl_to_rgb(hue, sat, light))
    img.paste(band, (60, 60))

    # Title overlay
    title_font = _font(36, bold=True)
    title = "GENESIS · COUNCIL OF 88"
    tw = draw.textlength(title, font=title_font)
    draw.text(((CARD_W - tw) / 2, 60 + (BAND_H - 36) / 2),
              title, fill=(255, 255, 255), font=title_font)

    # Seat sub-title
    seat_font = _font(32, bold=False)
    seat = f"Seat {archetype.id + 1} of 88"
    sw = draw.textlength(seat, font=seat_font)
    draw.text(((CARD_W - sw) / 2, 220), seat,
              fill=_hsl_to_rgb(hue, 50, 30), font=seat_font)

    # Council star behind glyph (overlay layer for alpha)
    _draw_council_star(odraw, CARD_W // 2, 540, 360, 260, hue)

    # Composite overlay onto the main image so far
    img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
    draw = ImageDraw.Draw(img)

    # Giant glyph
    glyph_font = _font(124, bold=True)
    g_text = archetype.glyph
    gw = draw.textlength(g_text, font=glyph_font)
    draw.text(((CARD_W - gw) / 2, 540 - 62),
              g_text, fill=_hsl_to_rgb(hue, 70, 35), font=glyph_font)

    # Archetype name + element/pattern caption
    name_font = _font(44, bold=True)
    name = archetype.name
    nw = draw.textlength(name, font=name_font)
    draw.text(((CARD_W - nw) / 2, 855), name,
              fill=(26, 26, 38), font=name_font)
    cap_font = _font(22, bold=False)
    caption = f"{archetype.element.upper()} · {archetype.pattern.upper()}"
    cw = draw.textlength(caption, font=cap_font)
    draw.text(((CARD_W - cw) / 2, 920), caption,
              fill=_hsl_to_rgb(hue, 30, 35), font=cap_font)

    # QR plate + QR
    draw.rectangle([(QR_LEFT - 12, QR_TOP - 12),
                    (QR_LEFT + QR_SIZE + 12, QR_TOP + QR_SIZE + 12)],
                   fill=(255, 255, 255))
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_Q,
        box_size=10,
        border=1,
    )
    qr.add_data(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="#1a1a26",
                           back_color="#ffffff").convert("RGB")
    qr_img = qr_img.resize((QR_SIZE, QR_SIZE), Image.NEAREST)
    img.paste(qr_img, (QR_LEFT, QR_TOP))

    # Metadata block
    meta_top = QR_TOP + QR_SIZE + 60
    meta_left_label = 140
    meta_left_value = meta_left_label + 220
    line_h = 40
    label_font = _font(20, bold=False)
    value_font = _font(22, bold=False)

    lines = [
        ("Sequence", f"#{inputs.sequence:,}".replace(",", ",")),
        ("Block height", f"{inputs.btc_block_height:,}"),
        ("Block hash", _fmt_fp(inputs.btc_block_hash_hex)),
        ("Vault", _fmt_fp(inputs.vault_fp_hex)),
        ("Signer", _fmt_fp(inputs.genesis_seal.signer_pk_fp_hex)),
    ]
    for i, (label, value) in enumerate(lines):
        y = meta_top + i * line_h
        draw.text((meta_left_label, y), label,
                  fill=(90, 90, 106), font=label_font)
        draw.text((meta_left_value, y), value,
                  fill=(26, 26, 38), font=value_font)

    # Footer
    foot_font = _font(18, bold=False)
    footer = (
        "Verify offline · scan QR with the Esoptron app or esoptron.app/verify"
    )
    fw = draw.textlength(footer, font=foot_font)
    draw.text(((CARD_W - fw) / 2, CARD_H - 100),
              footer, fill=_hsl_to_rgb(hue, 40, 30), font=foot_font)
    sub_font = _font(16, bold=False)
    sub = f"Schema v{payload['schema_version']} · Dilithium5 ML-DSA-87"
    sw2 = draw.textlength(sub, font=sub_font)
    draw.text(((CARD_W - sw2) / 2, CARD_H - 70),
              sub, fill=(122, 122, 138), font=sub_font)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def write_genesis_card_png(inputs: GenesisCardInputs, path: str) -> int:
    """Render the card and write it to ``path``. Returns bytes written."""
    data = render_genesis_card_png(inputs)
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)


def write_genesis_seal_envelope(inputs: GenesisCardInputs, path: str) -> int:
    """Render the sidecar seal envelope JSON file. Returns bytes written."""
    blob = json.dumps(build_seal_envelope(inputs), indent=2).encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(blob)
    return len(blob)
