/**
 * Low-level crypto primitives mirroring the Python implementation.
 *
 * Backed by ``@noble/hashes`` which provides constant-time, audited
 * implementations of SHA-3 and HKDF. The wire format and domain
 * separation tags here are **frozen v1**: any change must be coordinated
 * with ``eopx.metatron.field`` and ``eopx.vault.enroll`` on the Python
 * side and bumped on both ends.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** HKDF (RFC 5869) instantiated with SHA3-512 — matches
 *  ``eopx.metatron.field.hkdf_sha3_512``. */
export function hkdfSha3_512(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdf(sha3_512, ikm, salt, info, length);
}

/** SHA3-256 wrapper. */
export function sha3_256_(data: Uint8Array): Uint8Array {
  return sha3_256(data);
}

export const CARD_FP_DOMAIN = utf8("esoptron.metatron.card_fingerprint.v1\n");

/** Stable 32-byte fingerprint of a scanned card. Mirrors
 *  ``eopx.vault.verify_card.card_fingerprint`` exactly: domain prefix +
 *  91 symbols, each required to be in ``[0, 13)``.
 *
 *  Out-of-range symbols throw rather than being silently reduced mod 13 —
 *  this catches decoder regressions and keeps parity tight across ports. */
export function cardFingerprint(symbols: ReadonlyArray<number>): Uint8Array {
  if (symbols.length !== 91)
    throw new Error(`expected 91 symbols, got ${symbols.length}`);
  const buf = new Uint8Array(CARD_FP_DOMAIN.length + 91);
  buf.set(CARD_FP_DOMAIN, 0);
  for (let i = 0; i < 91; i++) {
    const v = symbols[i];
    if (!Number.isInteger(v) || v < 0 || v >= 13) {
      throw new Error(
        `symbol at index ${i} out of range: ${v} (must be 0 <= s < 13)`,
      );
    }
    buf[CARD_FP_DOMAIN.length + i] = v;
  }
  return sha3_256(buf);
}

/** Convert a Uint8Array to a lowercase hex string. */
export function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

/** Decode a lowercase hex string to a Uint8Array. */
export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Concatenate Uint8Arrays. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
