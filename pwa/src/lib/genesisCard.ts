/**
 * Genesis Card — printable PNG celebrating a vault's Council-of-88 seat.
 *
 * Distinct from {@link recoveryCard.ts}: the recovery card is one of
 * three secret shares that reconstruct a vault. The Genesis card is a
 * *public* attestation that this vault landed on one of the 88
 * archetype positions among the first ``GENESIS_WINDOW`` vaults of the
 * ecosystem. It is verifiable offline because it embeds the Dilithium5
 * signed seal as a QR payload, plus the deployment pubkey fingerprint.
 *
 * Layout (1200 × 1800 px, portrait, ~4×6 inches at 300 DPI):
 *
 *   ┌──────────────────────────────────┐
 *   │ ▓▓▓▓ ARCHETYPE HUE BAND ▓▓▓▓     │  100 px
 *   │ GENESIS · COUNCIL OF 88          │
 *   │ Seat NN of 88                    │
 *   │            (glyph)               │  big, hue-tinted
 *   │      Pattern of Element          │
 *   │            (QR)                  │  500 × 500
 *   │ Sequence: #7674                  │
 *   │ Block height: 925,112            │
 *   │ Vault: fd83…a91c                 │
 *   │ Signer: <pk_fp[0:12]>            │
 *   │ esoptron.app/verify              │
 *   └──────────────────────────────────┘
 *
 * The QR payload mirrors the on-disk seal envelope: any consumer with
 * the deployment pubkey can re-verify the card without internet.
 */

import QRCode from "qrcode";

import {
  Archetype,
  GenesisSeal,
  archetypeName,
  archetypeOf,
  archetypesCommitmentHex,
} from "./genesisToken";

export interface GenesisCardInputs {
  /** Hex fingerprint of the vault that owns this card. */
  vaultFpHex: string;
  /** Position 1..GENESIS_WINDOW assigned by the anchor service. */
  sequence: number;
  /** Bitcoin block providing entropy for the 88 positions. */
  btcBlockHashHex: string;
  /** Bitcoin block height for the same. */
  btcBlockHeight: number;
  /** Deployment Dilithium5 public key (hex). */
  deploymentPkHex: string;
  /** The signed Genesis seal (Dilithium5). */
  genesisSeal: GenesisSeal;
  /** Optional explicit archetype; resolved via seal.archetype_id otherwise. */
  archetype?: Archetype;
  /** ISO-8601 timestamp; defaults to "now". */
  mintedAt?: string;
  /** Anchor service base URL embedded in the QR for online verifiers. */
  anchorUrl?: string;
}

/**
 * QR payload is a lightweight verifiable pointer, *not* the full seal.
 * Dilithium5 signatures are 4627 bytes (9254 hex chars) and deployment
 * pubkeys are 2592 bytes; embedding both in a single QR would blow
 * past version 40 / level-Q capacity. The pointer carries every
 * coordinate needed to re-fetch and verify the seal from the anchor
 * service (or a cached local copy of the deployment context):
 *
 *   - ``signer_pk_fp_hex`` pins the trust anchor
 *   - ``sequence`` locates the seal on the anchor service
 *   - ``archetypes_commitment_hex`` proves the archetype catalog
 *     against the schema-frozen 88-entry list
 *
 * For fully offline verification, ship the seal as a sidecar
 * ``.eopx.seal`` JSON file alongside the card PNG via
 * {@link buildGenesisSealEnvelope}.
 */
export interface GenesisCardQrPayload {
  type: "esoptron-genesis-card";
  schema_version: number;
  vault_fp_hex: string;
  sequence: number;
  archetype_id: number;
  btc_block_hash_hex: string;
  btc_block_height: number;
  signer_pk_fp_hex: string;
  archetypes_commitment_hex: string;
  anchor_url?: string;
}

/**
 * Companion sidecar that DOES embed the full Dilithium5 signature for
 * offline verification. Exported as a separate ``.eopx.seal`` JSON
 * file because it does not fit in a printable QR.
 */
export interface GenesisSealEnvelope {
  type: "esoptron-genesis-seal";
  schema_version: number;
  pointer: GenesisCardQrPayload;
  deployment_pk_hex: string;
  signature_hex: string;
}

const CARD_W = 1200;
const CARD_H = 1800;
const BAND_H = 100;
const QR_SIZE = 500;
const QR_TOP = 1080;
const QR_LEFT = (CARD_W - QR_SIZE) / 2;

/**
 * Build the QR-embeddable pointer payload — small enough to fit in a
 * printable QR but rich enough to drive a verifier that already knows
 * the deployment pubkey (or can fetch it by ``signer_pk_fp_hex``).
 */
export function buildGenesisQrPayload(
  inputs: GenesisCardInputs,
): GenesisCardQrPayload {
  const payload: GenesisCardQrPayload = {
    type: "esoptron-genesis-card",
    schema_version: inputs.genesisSeal.schema_version,
    vault_fp_hex: inputs.vaultFpHex,
    sequence: inputs.sequence,
    archetype_id: inputs.genesisSeal.archetype_id,
    btc_block_hash_hex: inputs.btcBlockHashHex,
    btc_block_height: inputs.btcBlockHeight,
    signer_pk_fp_hex: inputs.genesisSeal.signer_pk_fp_hex,
    archetypes_commitment_hex: archetypesCommitmentHex(),
  };
  if (inputs.anchorUrl) payload.anchor_url = inputs.anchorUrl;
  return payload;
}

/**
 * Build the sidecar envelope. Pair this with the rendered PNG to
 * obtain a fully self-contained, offline-verifiable artifact.
 */
export function buildGenesisSealEnvelope(
  inputs: GenesisCardInputs,
): GenesisSealEnvelope {
  return {
    type: "esoptron-genesis-seal",
    schema_version: inputs.genesisSeal.schema_version,
    pointer: buildGenesisQrPayload(inputs),
    deployment_pk_hex: inputs.deploymentPkHex,
    signature_hex: inputs.genesisSeal.signature_hex,
  };
}

function hslHue(hue: number, sat: number, light: number): string {
  return `hsl(${hue} ${sat}% ${light}%)`;
}

function fmtFp(hex: string, head = 8, tail = 4): string {
  if (hex.length <= head + tail) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

function drawText(
  ctx: CanvasRenderingContext2D,
  text: string,
  x: number,
  y: number,
  font: string,
  color = "#1a1a26",
  align: CanvasTextAlign = "left",
): void {
  ctx.font = font;
  ctx.fillStyle = color;
  ctx.textAlign = align;
  ctx.textBaseline = "alphabetic";
  ctx.fillText(text, x, y);
}

/**
 * Draw an 88-pointed star whose radius pulses with the archetype hue;
 * acts as the sacred-geometry decoration behind the giant glyph.
 */
function drawCouncilStar(
  ctx: CanvasRenderingContext2D,
  cx: number,
  cy: number,
  outerR: number,
  innerR: number,
  hue: number,
): void {
  const points = 88;
  ctx.save();
  ctx.translate(cx, cy);
  ctx.strokeStyle = hslHue(hue, 70, 50);
  ctx.globalAlpha = 0.22;
  ctx.lineWidth = 1.2;
  for (let i = 0; i < points; i++) {
    const angle = (i / points) * Math.PI * 2 - Math.PI / 2;
    const r = i % 8 === 0 ? outerR : innerR;
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(Math.cos(angle) * r, Math.sin(angle) * r);
    ctx.stroke();
  }
  ctx.restore();
}

/**
 * Render the Genesis card to a PNG blob.
 *
 * Throws if the inputs are inconsistent (archetype id mismatch with
 * the resolved seal-derived archetype). Callers should pass the
 * payload returned by the anchor service directly: every field is
 * already aligned with the seal contract.
 */
export async function renderGenesisCardPng(
  inputs: GenesisCardInputs,
): Promise<Blob> {
  const archetype = inputs.archetype
    ?? archetypeOf(inputs.genesisSeal.archetype_id);
  if (archetype.id !== inputs.genesisSeal.archetype_id) {
    throw new Error(
      "archetype.id does not match seal.archetype_id",
    );
  }
  const hue = archetype.colorHue;
  const payload = buildGenesisQrPayload(inputs);

  const canvas = document.createElement("canvas");
  canvas.width = CARD_W;
  canvas.height = CARD_H;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("canvas 2d context unavailable");

  // Parchment background tinted very lightly with the archetype hue
  ctx.fillStyle = hslHue(hue, 30, 96);
  ctx.fillRect(0, 0, CARD_W, CARD_H);

  // Outer frame
  ctx.strokeStyle = "#1a1a26";
  ctx.lineWidth = 6;
  ctx.strokeRect(30, 30, CARD_W - 60, CARD_H - 60);
  ctx.strokeStyle = "#1a1a26";
  ctx.lineWidth = 1;
  ctx.strokeRect(50, 50, CARD_W - 100, CARD_H - 100);

  // Top hue band — solid archetype color
  const grd = ctx.createLinearGradient(60, 0, CARD_W - 60, 0);
  grd.addColorStop(0, hslHue(hue, 80, 55));
  grd.addColorStop(0.5, hslHue(hue, 65, 45));
  grd.addColorStop(1, hslHue(hue, 80, 55));
  ctx.fillStyle = grd;
  ctx.fillRect(60, 60, CARD_W - 120, BAND_H);

  // Title overlay on the band
  drawText(ctx, "GENESIS · COUNCIL OF 88",
    CARD_W / 2, 60 + BAND_H / 2 + 12,
    "700 36px 'Inter', sans-serif", "#fff", "center");

  drawText(ctx, `Seat ${archetype.id + 1} of 88`,
    CARD_W / 2, 230,
    "500 32px 'Inter', sans-serif",
    hslHue(hue, 50, 30), "center");

  // Council-star behind the giant glyph
  const glyphCx = CARD_W / 2;
  const glyphCy = 540;
  drawCouncilStar(ctx, glyphCx, glyphCy, 360, 260, hue);

  // Giant glyph token
  drawText(ctx, archetype.glyph,
    glyphCx, glyphCy + 40,
    "800 124px 'SF Mono', 'Menlo', monospace",
    hslHue(hue, 70, 35), "center");

  // Archetype name
  drawText(ctx, archetypeName(archetype),
    CARD_W / 2, 880,
    "600 44px 'Inter', sans-serif", "#1a1a26", "center");
  drawText(ctx, archetype.element.toUpperCase()
    + " · " + archetype.pattern.toUpperCase(),
    CARD_W / 2, 930,
    "500 22px 'Inter', sans-serif",
    hslHue(hue, 30, 35), "center");

  // QR background plate
  ctx.fillStyle = "white";
  ctx.fillRect(QR_LEFT - 12, QR_TOP - 12, QR_SIZE + 24, QR_SIZE + 24);

  // QR
  const qrCanvas = document.createElement("canvas");
  await QRCode.toCanvas(qrCanvas, JSON.stringify(payload), {
    width: QR_SIZE,
    margin: 1,
    errorCorrectionLevel: "Q",
    color: { dark: "#1a1a26", light: "#ffffff" },
  });
  ctx.drawImage(qrCanvas, QR_LEFT, QR_TOP, QR_SIZE, QR_SIZE);

  // Metadata block under the QR
  const metaTop = QR_TOP + QR_SIZE + 60;
  const metaLeftLabel = 140;
  const metaLeftValue = metaLeftLabel + 220;
  const lineH = 40;
  const lines: [string, string][] = [
    ["Sequence", `#${inputs.sequence.toLocaleString("en-US")}`],
    ["Block height", inputs.btcBlockHeight.toLocaleString("en-US")],
    ["Block hash", fmtFp(inputs.btcBlockHashHex, 12, 8)],
    ["Vault", fmtFp(inputs.vaultFpHex, 12, 8)],
    ["Signer", fmtFp(inputs.genesisSeal.signer_pk_fp_hex, 12, 8)],
  ];
  ctx.textAlign = "left";
  ctx.textBaseline = "alphabetic";
  for (const [i, [label, value]] of lines.entries()) {
    drawText(ctx, label,
      metaLeftLabel, metaTop + i * lineH,
      "500 20px 'Inter', sans-serif", "#5a5a6a", "left");
    drawText(ctx, value,
      metaLeftValue, metaTop + i * lineH,
      "500 22px 'SF Mono', 'Menlo', monospace", "#1a1a26", "left");
  }

  // Footer — verifier hint
  drawText(ctx,
    "Verify offline · scan QR with the Esoptron app or esoptron.app/verify",
    CARD_W / 2, CARD_H - 100,
    "500 18px 'Inter', sans-serif",
    hslHue(hue, 40, 30), "center");
  drawText(ctx,
    `Schema v${payload.schema_version} · Dilithium5 ML-DSA-87`,
    CARD_W / 2, CARD_H - 70,
    "400 16px 'Inter', sans-serif", "#7a7a8a", "center");

  return await new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(
      (b) => {
        if (b) resolve(b);
        else reject(new Error("canvas.toBlob returned null"));
      },
      "image/png",
    );
  });
}

/**
 * Trigger a download of the rendered Genesis card.
 */
export async function downloadGenesisCardPng(
  inputs: GenesisCardInputs,
): Promise<void> {
  const blob = await renderGenesisCardPng(inputs);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `esoptron-genesis-seat-${
    inputs.genesisSeal.archetype_id + 1
  }.png`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Trigger a download of the sidecar seal envelope for offline
 * verification (paired with the PNG card).
 */
export function downloadGenesisSealEnvelope(
  inputs: GenesisCardInputs,
): void {
  const envelope = buildGenesisSealEnvelope(inputs);
  const blob = new Blob([JSON.stringify(envelope, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `esoptron-genesis-seat-${
    inputs.genesisSeal.archetype_id + 1
  }.eopx.seal.json`;
  a.click();
  URL.revokeObjectURL(url);
}
