/**
 * Recovery Card #2 — client-side rendering of a printable PNG that
 * carries the PIN-protected share envelope as a QR code.
 *
 * Layout (1200 × 1800 px ≈ 4×6 inches at 300 DPI):
 *
 *   ┌────────────────────────────────────────┐
 *   │  ▓▓▓▓▓ vault color band ▓▓▓▓▓          │  80 px
 *   │  ESOPTRON · RECOVERY CARD              │
 *   │  Share 1 of 3 — Card / PIN             │
 *   │                                        │
 *   │            ╔══════════╗                │
 *   │            ║          ║                │
 *   │            ║   QR     ║                │  (800 × 800)
 *   │            ║          ║                │
 *   │            ╚══════════╝                │
 *   │                                        │
 *   │  Vault:    fd83…a91c                   │
 *   │  Group:    7a4b…02e9                   │
 *   │  Created:  2026-05-28T00:00:00Z        │
 *   │  Open:     Esoptron app → Restore      │
 *   │            (requires the 6-digit PIN)  │
 *   └────────────────────────────────────────┘
 *
 * The QR payload is a compact JSON document carrying ONLY the
 * card_pin share envelope plus the group_id, schema_version, threshold
 * and total. Without the PIN this payload is useless (Argon2id +
 * ChaCha20-Poly1305 with AAD bound to the group_id). With it, the user
 * recovers share #1 and combines with either the cloud passphrase or
 * the contact's Kyber sk.
 */

import QRCode from "qrcode";

import {
  CardPinShareEnvelope,
  RecoveryPackage,
} from "./recovery";
import { toHex } from "./crypto";

export interface RecoveryCardQrPayload {
  type: "esoptron-recovery-card";
  schema_version: number;
  group_id: string;
  vault_fp_hex: string;
  threshold: number;
  total: number;
  share: {
    index: number;
    kind: "card_pin";
    nonce_hex: string;
    ciphertext_hex: string;
    salt_hex: string;
    kdf: string;
  };
}

/**
 * Build the compact JSON that goes into the QR. We keep field names
 * identical to the on-disk recovery package so a future "smart scan"
 * can paste the QR content straight into the recovery flow.
 */
export function buildQrPayload(
  pkg: RecoveryPackage,
): RecoveryCardQrPayload {
  const cardShare = pkg.shares.find(
    (s) => s.kind === "card_pin",
  ) as CardPinShareEnvelope | undefined;
  if (!cardShare)
    throw new Error("recovery package has no card_pin share");
  return {
    type: "esoptron-recovery-card",
    schema_version: pkg.schemaVersion,
    group_id: pkg.groupId,
    vault_fp_hex: pkg.vaultFpHex,
    threshold: pkg.threshold,
    total: pkg.total,
    share: {
      index: cardShare.index,
      kind: "card_pin",
      nonce_hex: toHex(cardShare.nonce),
      ciphertext_hex: toHex(cardShare.ciphertext),
      salt_hex: toHex(cardShare.salt),
      kdf: cardShare.kdf,
    },
  };
}

const CARD_W = 1200;
const CARD_H = 1800;
const BAND_H = 80;
const QR_SIZE = 800;
const QR_TOP = 480;
const QR_LEFT = (CARD_W - QR_SIZE) / 2;

/**
 * Convert vault fingerprint hex into a deterministic two-color gradient
 * so the user can visually recognise their own card.
 */
function vaultColorPair(vaultFpHex: string): [string, string] {
  // Use the first 6 bytes (12 hex chars) for two HSL hues.
  const seed = vaultFpHex.padEnd(12, "0");
  const h1 = parseInt(seed.slice(0, 4), 16) % 360;
  const h2 = (h1 + 60 + (parseInt(seed.slice(4, 8), 16) % 120)) % 360;
  return [`hsl(${h1} 80% 55%)`, `hsl(${h2} 65% 45%)`];
}

function drawTextBlock(
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
 * Render the printable recovery card to a Blob (PNG).
 */
export async function renderRecoveryCardPng(
  pkg: RecoveryPackage,
): Promise<Blob> {
  const payload = buildQrPayload(pkg);

  // 1. Compose the canvas
  const canvas = document.createElement("canvas");
  canvas.width = CARD_W;
  canvas.height = CARD_H;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("canvas 2d context unavailable");

  // Background — soft parchment off-white
  ctx.fillStyle = "#f7f4ec";
  ctx.fillRect(0, 0, CARD_W, CARD_H);

  // Outer frame
  ctx.strokeStyle = "#1a1a26";
  ctx.lineWidth = 6;
  ctx.strokeRect(30, 30, CARD_W - 60, CARD_H - 60);

  // Inner thin frame
  ctx.strokeStyle = "#1a1a26";
  ctx.lineWidth = 1;
  ctx.strokeRect(50, 50, CARD_W - 100, CARD_H - 100);

  // Vault color band (gradient bound to vault_fp_hex)
  const [c1, c2] = vaultColorPair(pkg.vaultFpHex);
  const grd = ctx.createLinearGradient(60, 0, CARD_W - 60, 0);
  grd.addColorStop(0, c1);
  grd.addColorStop(1, c2);
  ctx.fillStyle = grd;
  ctx.fillRect(60, 60, CARD_W - 120, BAND_H);

  // Title block
  drawTextBlock(ctx, "ESOPTRON",
    CARD_W / 2, 200, "700 56px 'Inter', sans-serif", "#1a1a26", "center");
  drawTextBlock(ctx, "RECOVERY CARD",
    CARD_W / 2, 250, "500 30px 'Inter', sans-serif", "#3a3a4a", "center");
  drawTextBlock(ctx, `Share ${payload.share.index} of ${pkg.total} — PIN protected`,
    CARD_W / 2, 300, "400 22px 'Inter', sans-serif", "#5a5a6a", "center");

  // Sacred-geometry decoration: 7 concentric circles behind the QR
  const cx = CARD_W / 2;
  const cy = QR_TOP + QR_SIZE / 2;
  ctx.strokeStyle = "rgba(155, 89, 182, 0.18)";
  ctx.lineWidth = 2;
  for (let i = 1; i <= 7; i++) {
    ctx.beginPath();
    ctx.arc(cx, cy, QR_SIZE / 2 + i * 16, 0, Math.PI * 2);
    ctx.stroke();
  }

  // QR background plate (so the QR has a clean white background)
  ctx.fillStyle = "white";
  ctx.fillRect(QR_LEFT - 16, QR_TOP - 16, QR_SIZE + 32, QR_SIZE + 32);

  // Generate the QR onto a tmp canvas, then composite
  const qrCanvas = document.createElement("canvas");
  await QRCode.toCanvas(qrCanvas, JSON.stringify(payload), {
    width: QR_SIZE,
    margin: 1,
    errorCorrectionLevel: "M",
    color: { dark: "#1a1a26", light: "#ffffff" },
  });
  ctx.drawImage(qrCanvas, QR_LEFT, QR_TOP, QR_SIZE, QR_SIZE);

  // Metadata block under the QR
  const metaTop = QR_TOP + QR_SIZE + 80;
  const metaX = 120;
  const lineH = 44;
  const value = (s: string, y: number) =>
    drawTextBlock(ctx, s, metaX + 200, y,
                    "500 24px 'SF Mono', 'Menlo', monospace",
                    "#1a1a26", "left");

  ctx.font = "500 22px 'Inter', sans-serif";
  ctx.fillStyle = "#5a5a6a";
  ctx.textAlign = "left";
  for (const [i, l] of ["Vault", "Group", "Created", "Open"].entries()) {
    ctx.fillText(l, metaX, metaTop + i * lineH);
  }

  value(pkg.vaultFpHex.slice(0, 8) + "…" + pkg.vaultFpHex.slice(-4),
         metaTop + 0 * lineH);
  value(pkg.groupId.slice(0, 8) + "…" + pkg.groupId.slice(-4),
         metaTop + 1 * lineH);
  value(pkg.createdAt, metaTop + 2 * lineH);
  drawTextBlock(ctx,
    "Esoptron · Restore — needs the 6-digit PIN",
    metaX + 200, metaTop + 3 * lineH,
    "500 22px 'Inter', sans-serif", "#1a1a26", "left");

  // Footer warning
  drawTextBlock(ctx,
    "WITHOUT THE PIN THIS CARD IS USELESS. WITH IT, IT IS ONE OF YOUR " +
      "3 KEYS — KEEP IT PRIVATE.",
    CARD_W / 2, CARD_H - 90,
    "500 18px 'Inter', sans-serif", "#a83a3a", "center");

  // 2. Export as PNG
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
 * Trigger a download of the rendered card as a PNG.
 */
export async function downloadRecoveryCardPng(
  pkg: RecoveryPackage,
): Promise<void> {
  const blob = await renderRecoveryCardPng(pkg);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `esoptron-recovery-card-${pkg.groupId.slice(0, 8)}.png`;
  a.click();
  URL.revokeObjectURL(url);
}
