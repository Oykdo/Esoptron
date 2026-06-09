/**
 * EPX-L — relic-keyed hidden holographic layer (client reveal).
 *
 * Mirrors `scripts/epx_reveal_poc.py` byte-for-byte so a layer SEALED in Python
 * opens here:
 *   layer key = HKDF-SHA3-512(relic_secret, salt="", info="eidolon.relic.layer.v1", 32)
 *   AEAD      = ChaCha20-Poly1305,  blob = nonce(12) || ciphertext||tag
 *
 * The public hologram (RelicCanvas) renders without any relic; the sealed layer
 * is opaque until `openSealedLayer` succeeds with the scanned relic secret.
 */

import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdfSha3_512, fromHex } from "./crypto";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Frozen v1 domain — must match `LAYER_INFO` on the Python side. */
export const LAYER_INFO = utf8("eidolon.relic.layer.v1");

export interface HiddenLayer {
  layer: string;
  relic: string;
  surfaces: [number, number, number][];
  anim: { type: string; period_s: number; amp: number };
}

/** Derive the 32-byte layer key from a scanned relic secret. */
export function layerKey(relicSecret: Uint8Array): Uint8Array {
  return hkdfSha3_512(relicSecret, new Uint8Array(0), LAYER_INFO, 32);
}

/** Decrypt a sealed layer to its raw plaintext bytes (throws on wrong relic). */
export function openSealedRaw(relicSecret: Uint8Array, sealedHex: string): Uint8Array {
  const blob = fromHex(sealedHex);
  const nonce = blob.slice(0, 12);
  const ct = blob.slice(12);
  return chacha20poly1305(layerKey(relicSecret), nonce).decrypt(ct);
}

/** Decrypt + parse a sealed layer into a {@link HiddenLayer} (throws on wrong relic). */
export function openSealedLayer(relicSecret: Uint8Array, sealedHex: string): HiddenLayer {
  const raw = new TextDecoder().decode(openSealedRaw(relicSecret, sealedHex));
  return JSON.parse(raw) as HiddenLayer;
}

/**
 * Try to reveal; return the layer or `null` if no/invalid relic (sealed).
 * Never throws — convenient for the renderer's optional reveal path.
 */
export function tryReveal(
  relicSecret: Uint8Array | null | undefined,
  sealedHex: string | null | undefined,
): HiddenLayer | null {
  if (!relicSecret || !sealedHex) return null;
  try {
    return openSealedLayer(relicSecret, sealedHex);
  } catch {
    return null;
  }
}
