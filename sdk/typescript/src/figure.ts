/**
 * EPX-F — the artifact figure, for the standalone verifier.
 *
 * A `.eopx` verifier already holds everything the figure needs: the two
 * pre-image manifest fields are covered by the same ML-DSA-87 signature it just
 * checked. Recomputing the figure here completes EPX-F §7 without a second
 * trust root, a second key, or a network call.
 *
 * ```
 * 1. verify the .eopx signature            (verify(), unchanged)
 * 2. read merkle_root and dilithium_pk_fp  from the verified manifest
 * 3. grid = F(merkle_root, dilithium_pk_fp)
 * 4. compare figureTag(grid) with what is printed on the object
 * ```
 *
 * Step 1 establishes trust. Steps 2–4 establish that the face belongs to that
 * artifact. **Looking at the figure is not a step**, and nothing here is
 * evidence of anything the signature does not already establish.
 *
 * FROZEN at v1 (EPX-F §8): the domain strings carry the version, and the §9
 * vectors are normative. This file is a port and must reproduce them byte for
 * byte — a failing vector is a regression or a deliberate version bump, never
 * an expected-value edit.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export const FIGURE_VERSION = 1;

const INFO_CONTENT = utf8("esoptron.figure.content.v1");
const INFO_EPOCH = utf8("esoptron.figure.epoch.v1");

/** 16 × 8 = 128 cells of 4 bits = 512 bits, exactly one SHA3-512 width. */
export const GRID_W = 16;
export const GRID_H = 8;
export const CONTENT_ROWS = 6;
export const EPOCH_ROWS = GRID_H - CONTENT_ROWS;
export const LEVELS = 16;

/** Reference presentation, light → dense (EPX-F §6). */
export const ASCII_RAMP = " .`',:;!~+=*%#@$";

const FP_LEN = 32;

/** What a verifier can say about an artifact's face. */
export interface Figure {
  grid: number[][];
  /** One lowercase hex digit per cell, rows joined by "\n". */
  canonicalText: string;
  /** First 4 bytes of SHA3-256(canonicalText), hex — the printable tag. */
  tag: string;
  /** First 4 bytes of dilithium_pk_fp, hex — the issuing key's epoch. */
  epoch: string;
}

function hexToBytes(hex: string, name: string): Uint8Array {
  const s = hex.trim();
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error(`${name} must be valid hex`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

function check(name: string, value: Uint8Array): Uint8Array {
  if (value.length !== FP_LEN) {
    throw new Error(`${name} must be ${FP_LEN} bytes, got ${value.length}`);
  }
  return value;
}

function nibbles(data: Uint8Array): number[] {
  const out: number[] = [];
  for (const b of data) {
    out.push(b >> 4);
    out.push(b & 0x0f);
  }
  return out;
}

/**
 * The artifact's cell grid, from the two raw 32-byte manifest fields.
 *
 * Rows 0..5 are the **content band** and depend on `merkleRoot` alone, so an
 * artifact keeps its face for life. Rows 6..7 are the **epoch band** and also
 * take `dilithiumPkFp`, so a key rotation is legible without making the object
 * a stranger (EPX-F §3.1).
 */
export function figureGrid(
  merkleRoot: Uint8Array,
  dilithiumPkFp: Uint8Array
): number[][] {
  check("merkle_root", merkleRoot);
  check("dilithium_pk_fp", dilithiumPkFp);

  const empty = new Uint8Array(0);
  const content = hkdf(
    sha3_512,
    merkleRoot,
    empty,
    INFO_CONTENT,
    (CONTENT_ROWS * GRID_W) / 2
  );

  const ikm = new Uint8Array(merkleRoot.length + dilithiumPkFp.length);
  ikm.set(merkleRoot, 0);
  ikm.set(dilithiumPkFp, merkleRoot.length);
  const epoch = hkdf(
    sha3_512,
    ikm,
    empty,
    INFO_EPOCH,
    (EPOCH_ROWS * GRID_W) / 2
  );

  const cells = nibbles(content).concat(nibbles(epoch));
  const grid: number[][] = [];
  for (let r = 0; r < GRID_H; r++) {
    grid.push(cells.slice(r * GRID_W, (r + 1) * GRID_W));
  }
  return grid;
}

/** The hashed form: one lowercase hex digit per cell, rows joined by "\n". */
export function canonicalText(grid: ReadonlyArray<ReadonlyArray<number>>): string {
  if (grid.length !== GRID_H || grid.some((r) => r.length !== GRID_W)) {
    throw new Error(`grid must be ${GRID_H}x${GRID_W}`);
  }
  for (const row of grid) {
    for (const c of row) {
      if (!Number.isInteger(c) || c < 0 || c >= LEVELS) {
        throw new Error(`cell levels must be integers in [0, ${LEVELS})`);
      }
    }
  }
  return grid.map((row) => row.map((c) => c.toString(16)).join("")).join("\n");
}

/** SHA3-256 over {@link canonicalText} — the figure's own fingerprint. */
export function figureDigest(
  grid: ReadonlyArray<ReadonlyArray<number>>
): Uint8Array {
  return sha3_256(utf8(canonicalText(grid)));
}

/**
 * The 8-character tag a reader compares against the object.
 *
 * A comparison aid, not evidence: only recomputation from the `.eopx` decides.
 */
export function figureTag(grid: ReadonlyArray<ReadonlyArray<number>>): string {
  return toHex(figureDigest(grid).slice(0, 4));
}

/** The issuing key's epoch tag — a legible signal, never a proof of authority. */
export function epochId(dilithiumPkFp: Uint8Array): string {
  return toHex(check("dilithium_pk_fp", dilithiumPkFp).slice(0, 4));
}

/** Present a grid with a glyph ramp; changes what a reader sees and nothing else. */
export function renderRows(
  grid: ReadonlyArray<ReadonlyArray<number>>,
  ramp: string = ASCII_RAMP
): string[] {
  const glyphs = Array.from(ramp);
  if (glyphs.length !== LEVELS) {
    throw new Error(`ramp must have exactly ${LEVELS} glyphs`);
  }
  canonicalText(grid); // reuse the same validation
  return grid.map((row) => row.map((c) => glyphs[c]).join(""));
}

/**
 * The figure of a verified manifest — EPX-F §7 steps 2–4 in one call.
 *
 * Takes the hex fields as the manifest carries them. Call it on a manifest
 * whose signature has already verified: a figure recomputed from unverified
 * fields tells you what an attacker chose, not what the issuer signed.
 */
export function figureOf(manifest: {
  merkleRoot: string;
  dilithiumPkFp: string;
}): Figure {
  const fp = hexToBytes(manifest.dilithiumPkFp, "dilithium_pk_fp");
  const grid = figureGrid(hexToBytes(manifest.merkleRoot, "merkle_root"), fp);
  return {
    grid,
    canonicalText: canonicalText(grid),
    tag: figureTag(grid),
    epoch: epochId(fp),
  };
}
