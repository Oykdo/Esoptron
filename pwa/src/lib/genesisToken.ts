/**
 * Genesis Token — TypeScript port of ``eopx.genesis_token``.
 *
 * Mirrors the Python module byte-for-byte:
 * * Constants ``LATTICE_PATTERNS``, ``LATTICE_ELEMENTS``,
 *   ``ELEMENT_HUES`` are identical → archetypes commitment hash matches.
 * * HKDF-SHA3-256 multi-block expansion matches Python.
 * * Position derivation uses the same rejection sampling threshold and
 *   the same canonical info string.
 * * Genesis seal verification uses ML-DSA-87 (Dilithium5).
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha3_256 } from "@noble/hashes/sha3";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";

import { fromHex, toHex } from "./crypto";

export const SCHEMA_VERSION = 1;
export const TOTAL_GENESIS = 88;
export const TOTAL_VAULTS = 1_000_000;
export const GENESIS_WINDOW = Math.floor(TOTAL_VAULTS / 3); // 333_333
export const BTC_BLOCK_TARGET = 900_000;

const GENESIS_DOMAIN = new TextEncoder().encode("esoptron.genesis.v1");
const GENESIS_POSITIONS_INFO = new TextEncoder().encode(
  "esoptron.genesis.positions.v1",
);
const GENESIS_SEAL_INFO = new TextEncoder().encode(
  "esoptron.genesis.seal.v1",
);

// ---------------------------------------------------------------------------
// Archetype catalog — MUST match Python eopx.genesis_token
// ---------------------------------------------------------------------------

export const LATTICE_PATTERNS: readonly string[] = [
  "Source", "Mirror", "Crown", "Star", "Tower", "Veil", "Bridge",
  "Spiral", "Octave", "Lantern", "Threshold", "Pillar", "Reed",
  "Compass", "Anchor", "Echo", "Loom", "Furnace", "Garden", "Codex",
  "Cipher", "Lotus",
] as const;

export const LATTICE_ELEMENTS: readonly string[] = [
  "Air", "Fire", "Water", "Earth",
] as const;

export const ELEMENT_HUES: Readonly<Record<string, number>> = {
  Air:   200,
  Fire:  15,
  Water: 240,
  Earth: 95,
};

export interface Archetype {
  id: number;
  pattern: string;
  element: string;
  glyph: string;
  colorHue: number;
}

let _archetypeCache: Archetype[] | null = null;

export function allArchetypes(): Archetype[] {
  if (_archetypeCache) return _archetypeCache;
  const out: Archetype[] = [];
  for (let p = 0; p < LATTICE_PATTERNS.length; p++) {
    for (let e = 0; e < LATTICE_ELEMENTS.length; e++) {
      const pattern = LATTICE_PATTERNS[p];
      const element = LATTICE_ELEMENTS[e];
      out.push({
        id: p * 4 + e,
        pattern, element,
        glyph: `${pattern.slice(0, 3).toUpperCase()}-${element.slice(0, 3).toUpperCase()}`,
        colorHue: ELEMENT_HUES[element],
      });
    }
  }
  _archetypeCache = out;
  return out;
}

export function archetypeOf(archetypeId: number): Archetype {
  if (!Number.isInteger(archetypeId) ||
       archetypeId < 0 || archetypeId >= TOTAL_GENESIS)
    throw new Error(`archetype_id must be in 0..${TOTAL_GENESIS - 1}`);
  return allArchetypes()[archetypeId];
}

export function archetypeName(a: Archetype): string {
  return `${a.pattern} of ${a.element}`;
}

/**
 * SHA3-256 over the canonical archetype list. MUST equal Python's
 * ``archetypes_commitment_hex()`` byte-for-byte — this is enforced by
 * the parity test vector.
 *
 * To match Python ``json.dumps(..., sort_keys=True)`` exactly we must
 * emit the keys in alphabetical order and match Python's default
 * separators (``", "`` between items and ``": "`` between key/value).
 */
export function archetypesCommitmentHex(): string {
  const archs = allArchetypes();
  const items = archs.map((a) =>
    "{" +
    `"color_hue": ${a.colorHue}, ` +
    `"element": ${JSON.stringify(a.element)}, ` +
    `"glyph": ${JSON.stringify(a.glyph)}, ` +
    `"id": ${a.id}, ` +
    `"pattern": ${JSON.stringify(a.pattern)}` +
    "}",
  );
  const payload = "[" + items.join(", ") + "]";
  return toHex(sha3_256(new TextEncoder().encode(payload)));
}

// ---------------------------------------------------------------------------
// HKDF-SHA3-256 — same primitive as recovery.ts but multi-block.
// ---------------------------------------------------------------------------

function hkdfSha3_256MultiBlock(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  // @noble/hashes/hkdf already handles multi-block expansion correctly.
  return hkdf(sha3_256, ikm, salt, info, length);
}

// ---------------------------------------------------------------------------
// Position derivation
// ---------------------------------------------------------------------------

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/**
 * Derive ``total`` distinct genesis positions in ``[1, window]`` from
 * a Bitcoin block hash.
 *
 * Matches the rejection-sampling kernel in
 * ``eopx.genesis_token.derive_positions`` exactly.
 */
export function derivePositions(
  btcBlockHash: Uint8Array,
  options: {
    btcBlockHeight?: number;
    total?: number;
    window?: number;
  } = {},
): number[] {
  const btcBlockHeight = options.btcBlockHeight ?? BTC_BLOCK_TARGET;
  const total = options.total ?? TOTAL_GENESIS;
  const window = options.window ?? GENESIS_WINDOW;

  if (btcBlockHash.length !== 32)
    throw new Error("btc_block_hash must be 32 bytes");
  if (total <= 0 || window < total)
    throw new Error(`need 0 < total <= window; got ${total}, ${window}`);

  const info = concatBytes(
    GENESIS_POSITIONS_INFO,
    new TextEncoder().encode(`|h=${btcBlockHeight}|w=${window}|n=${total}`),
  );
  let okm = hkdfSha3_256MultiBlock(
    GENESIS_DOMAIN, btcBlockHash, info, total * 16,
  );

  // JS bitwise ops are signed 32-bit; use BigInt to avoid mistakes.
  const winBig = BigInt(window);
  const threshold = (1n << 32n) / winBig * winBig;
  const positions: number[] = [];
  const seen = new Set<number>();
  let off = 0;

  while (positions.length < total) {
    if (off + 4 > okm.length) {
      const extendedInfo = concatBytes(
        info, new TextEncoder().encode(`|off=${off}`),
      );
      const more = hkdfSha3_256MultiBlock(
        concatBytes(GENESIS_DOMAIN, new TextEncoder().encode("|extend")),
        btcBlockHash, extendedInfo, total * 16,
      );
      const grown = new Uint8Array(okm.length + more.length);
      grown.set(okm, 0);
      grown.set(more, okm.length);
      okm = grown;
    }
    const x =
      (BigInt(okm[off]) << 24n) |
      (BigInt(okm[off + 1]) << 16n) |
      (BigInt(okm[off + 2]) << 8n) |
      BigInt(okm[off + 3]);
    off += 4;
    if (x >= threshold) continue;
    const pos = Number(x % winBig) + 1;
    if (seen.has(pos)) continue;
    seen.add(pos);
    positions.push(pos);
  }

  return positions.sort((a, b) => a - b);
}

export function isGenesis(sequence: number, positions: number[]): boolean {
  return positions.includes(sequence);
}

export function archetypeForSequence(
  sequence: number, positions: number[],
): Archetype | null {
  const sorted = [...positions].sort((a, b) => a - b);
  const rank = sorted.indexOf(sequence);
  if (rank < 0) return null;
  return archetypeOf(rank);
}

// ---------------------------------------------------------------------------
// Genesis seal — Dilithium5 (ML-DSA-87) verification
// ---------------------------------------------------------------------------

export interface GenesisSeal {
  schema_version: number;
  vault_fp_hex: string;
  sequence: number;
  archetype_id: number;
  btc_block_height: number;
  btc_block_hash_hex: string;
  signer_pk_fp_hex: string;
  signature_hex: string;
}

function sealMessage(args: {
  vaultFp: Uint8Array;
  sequence: number;
  archetypeId: number;
  btcBlockHeight: number;
  btcBlockHash: Uint8Array;
}): Uint8Array {
  const enc = new TextEncoder();
  return concatBytes(
    GENESIS_SEAL_INFO,
    enc.encode("|"),
    enc.encode(String(SCHEMA_VERSION)),
    enc.encode("|"),
    args.vaultFp,
    enc.encode("|"),
    enc.encode(String(args.sequence)),
    enc.encode("|"),
    enc.encode(String(args.archetypeId)),
    enc.encode("|"),
    enc.encode(String(args.btcBlockHeight)),
    enc.encode("|"),
    args.btcBlockHash,
  );
}

/**
 * Verify a Genesis seal against the published deployment pubkey.
 * Mirrors ``eopx.genesis_token.verify_genesis_seal``.
 */
export function verifyGenesisSeal(
  seal: GenesisSeal,
  deploymentPk: Uint8Array,
  positions: number[],
): boolean {
  if (seal.schema_version !== SCHEMA_VERSION) return false;
  const expectedFp = toHex(sha3_256(deploymentPk));
  if (seal.signer_pk_fp_hex !== expectedFp) return false;
  if (!isGenesis(seal.sequence, positions)) return false;
  const expectedArch = archetypeForSequence(seal.sequence, positions);
  if (!expectedArch || expectedArch.id !== seal.archetype_id) return false;
  const msg = sealMessage({
    vaultFp: fromHex(seal.vault_fp_hex),
    sequence: seal.sequence,
    archetypeId: seal.archetype_id,
    btcBlockHeight: seal.btc_block_height,
    btcBlockHash: fromHex(seal.btc_block_hash_hex),
  });
  let sig: Uint8Array;
  try {
    sig = fromHex(seal.signature_hex);
  } catch {
    return false;
  }
  try {
    return ml_dsa87.verify(deploymentPk, msg, sig);
  } catch {
    return false;
  }
}
