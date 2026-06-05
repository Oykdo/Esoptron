/**
 * EPX-V voucher claim — client side.
 *
 * Lets a vault claim a huntable relic it has scanned: derive a per-relic
 * controller from the vault's device_secret, sign a ClaimProof, and POST it
 * to the anchor. The wire format mirrors `eopx.transfer.voucher` exactly
 * (verified interoperable: noble ML-DSA-87 signatures verify under the
 * Python pqcrypto anchor).
 *
 * The controller is **derived** (not stored): a deterministic seed from
 * HKDF(device_secret, salt=artifact_id) feeds noble's seeded keygen, so the
 * vault re-derives the same controller anytime — holding the vault = holding
 * the relic, with no extra secret to persist.
 */

import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";
import { hkdf } from "@noble/hashes/hkdf";
import { sha3_256 } from "@noble/hashes/sha3";

const enc = new TextEncoder();

// Frozen domain separators — must match eopx/transfer/voucher.py byte-for-byte.
const EPXT_VOUCHER_POP = enc.encode("epx-v.claim.pop.v1");
const INFO_DSA = enc.encode("esoptron.relic.controller.dsa.v1");
const INFO_KEM = enc.encode("esoptron.relic.controller.kem.v1");

export function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Unambiguous length-prefixed concat: uint32-BE length || bytes, per part. */
function lp(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, p) => a + 4 + p.length, 0);
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  let o = 0;
  for (const p of parts) {
    dv.setUint32(o, p.length, false); // big-endian
    o += 4;
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((a, x) => a + x.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const x of arrs) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}

export interface RelicController {
  dilithiumPub: Uint8Array;
  dilithiumSec: Uint8Array;
  kyberPub: Uint8Array;
}

/**
 * Derive this vault's controller for a relic from its device_secret.
 * Deterministic: the same (deviceSecret, artifactId) always yields the same
 * keypair, so the vault never needs to store the controller secret.
 */
export function deriveController(
  deviceSecret: Uint8Array,
  artifactId: Uint8Array,
): RelicController {
  const seedDsa = hkdf(sha3_256, deviceSecret, artifactId, INFO_DSA, 32);
  const dsa = ml_dsa87.keygen(seedDsa);
  const seedKem = hkdf(sha3_256, deviceSecret, artifactId, INFO_KEM, 64);
  const kem = ml_kem1024.keygen(seedKem);
  return {
    dilithiumPub: dsa.publicKey,
    dilithiumSec: dsa.secretKey,
    kyberPub: kem.publicKey,
  };
}

export interface ClaimProofDTO {
  artifact_id_hex: string;
  new_controller_pub_hex: string;
  new_controller_kyber_pub_hex: string;
  secret_hex: string;
  sig_hex: string;
}

/** Build a signed ClaimProof binding the secret to this controller. */
export function makeClaimProof(
  controller: RelicController,
  artifactId: Uint8Array,
  secret: Uint8Array,
): ClaimProofDTO {
  const payload = concat(
    EPXT_VOUCHER_POP,
    lp(artifactId, controller.dilithiumPub, secret),
  );
  const sig = ml_dsa87.sign(controller.dilithiumSec, payload);
  return {
    artifact_id_hex: toHex(artifactId),
    new_controller_pub_hex: toHex(controller.dilithiumPub),
    new_controller_kyber_pub_hex: toHex(controller.kyberPub),
    secret_hex: toHex(secret),
    sig_hex: toHex(sig),
  };
}
