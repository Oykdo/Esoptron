/**
 * EPX-F — TypeScript port of ``eopx.artifact_figure``.
 *
 * The artifact figure is a **cell grid**, not a picture: ``GRID_H`` rows of
 * ``GRID_W`` integer levels that any renderer may draw with any glyph set.
 * A phone recomputes it from a verified `.eopx` manifest and compares the tag
 * against what is printed on the object (EPX-F §7). Looking at the picture is
 * not a step.
 *
 * Two properties are load-bearing and must survive the port:
 *
 * * **Pre-image inputs only.** The grid derives from ``merkle_root`` and
 *   ``dilithium_pk_fp``, both fixed before the image exists. ``payload_hash``
 *   and ``image_sha3_512`` are downstream of the pixels, so a figure drawn
 *   into the image and derived from them is a fixed point with no solution
 *   (EPX-F §1).
 * * **Two bands.** Rows 0..5 depend on ``merkle_root`` alone, so an artifact
 *   keeps its face for life; rows 6..7 also take ``dilithium_pk_fp``, so a key
 *   rotation is legible without making the object a stranger (EPX-F §3.1).
 *
 * FROZEN at v1: ``FIGURE_VERSION`` is baked into the domain strings, and the
 * §9 vectors are normative. A failing vector is a regression or a deliberate
 * version bump — never an expected-value edit (EPX-F §8).
 */

import { concat, fromHex, hkdfSha3_512, sha3_256_, toHex } from "./crypto";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Derivation version, baked into the domain strings below. */
export const FIGURE_VERSION = 1;

export const INFO_CONTENT = utf8("esoptron.figure.content.v1");
export const INFO_EPOCH = utf8("esoptron.figure.epoch.v1");

/** Grid geometry. 16 × 8 = 128 cells of 4 bits = 512 bits, exactly one
 *  SHA3-512 width: no counter mode, no truncation bias, one output one grid. */
export const GRID_W = 16;
export const GRID_H = 8;
export const CONTENT_ROWS = 6;
export const EPOCH_ROWS = GRID_H - CONTENT_ROWS;

/** One hex nibble per cell. */
export const LEVELS = 16;

/** Reference presentation, light → dense. Normative *as a rendering*: two
 *  implementations printing the same grid with it must agree character for
 *  character. The digest covers the levels, never these glyphs. */
export const ASCII_RAMP = " .`',:;!~+=*%#@$";

const FP_LEN = 32;

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
 * The artifact's cell grid: ``GRID_H`` rows of ``GRID_W`` levels.
 *
 * ``merkleRoot`` and ``dilithiumPkFp`` are the raw 32-byte values carried
 * hex-encoded by the `.eopx` manifest — decode them before calling.
 */
export function figureGrid(
  merkleRoot: Uint8Array,
  dilithiumPkFp: Uint8Array,
): number[][] {
  check("merkle_root", merkleRoot);
  check("dilithium_pk_fp", dilithiumPkFp);

  const contentCells = CONTENT_ROWS * GRID_W;
  const epochCells = EPOCH_ROWS * GRID_W;
  const empty = new Uint8Array(0);

  const content = hkdfSha3_512(merkleRoot, empty, INFO_CONTENT, contentCells / 2);
  const epoch = hkdfSha3_512(
    concat(merkleRoot, dilithiumPkFp),
    empty,
    INFO_EPOCH,
    epochCells / 2,
  );

  const cells = nibbles(content).concat(nibbles(epoch));
  const grid: number[][] = [];
  for (let r = 0; r < GRID_H; r += 1) {
    grid.push(cells.slice(r * GRID_W, (r + 1) * GRID_W));
  }
  return grid;
}

function assertGrid(grid: ReadonlyArray<ReadonlyArray<number>>): void {
  if (grid.length !== GRID_H || grid.some((row) => row.length !== GRID_W)) {
    throw new Error(`grid must be ${GRID_H}x${GRID_W}`);
  }
  for (const row of grid) {
    for (const c of row) {
      if (!Number.isInteger(c) || c < 0 || c >= LEVELS) {
        throw new Error(`cell levels must be integers in [0, ${LEVELS})`);
      }
    }
  }
}

/**
 * The hashed form: one lowercase hex digit per cell, rows joined by ``\n``,
 * no trailing newline. Glyph-independent by construction — this, and not any
 * rendering, is what {@link figureDigest} covers.
 */
export function canonicalText(
  grid: ReadonlyArray<ReadonlyArray<number>>,
): string {
  assertGrid(grid);
  return grid.map((row) => row.map((c) => c.toString(16)).join("")).join("\n");
}

/** SHA3-256 over {@link canonicalText} — the figure's own fingerprint. */
export function figureDigest(
  grid: ReadonlyArray<ReadonlyArray<number>>,
): Uint8Array {
  return sha3_256_(utf8(canonicalText(grid)));
}

/**
 * Short human-comparable form of {@link figureDigest} — 8 hex characters.
 *
 * A *comparison aid*, never evidence: only recomputation from the `.eopx`
 * decides. It is what a reader checks against the tag printed on the object.
 */
export function figureTag(
  grid: ReadonlyArray<ReadonlyArray<number>>,
): string {
  return toHex(figureDigest(grid).slice(0, 4));
}

/**
 * The issuing key's epoch tag — first 4 bytes of its fingerprint, hex.
 *
 * Two artifacts sharing an epoch id were signed under the same key. A legible
 * signal, never a proof of authority: that is the cosigned attestation chain's
 * job (EPX-F §5).
 */
export function epochId(dilithiumPkFp: Uint8Array): string {
  return toHex(check("dilithium_pk_fp", dilithiumPkFp).slice(0, 4));
}

/**
 * Present a grid with a glyph ramp (default {@link ASCII_RAMP}).
 *
 * ``ramp`` must have exactly {@link LEVELS} glyphs. Substituting a ramp
 * changes what a reader sees and nothing else: the grid, the digest and the
 * tag are untouched.
 *
 * The ramp is indexed by code point, not by UTF-16 unit, so a ramp containing
 * astral-plane glyphs still maps one glyph to one level.
 */
export function renderRows(
  grid: ReadonlyArray<ReadonlyArray<number>>,
  ramp: string = ASCII_RAMP,
): string[] {
  const glyphs = Array.from(ramp);
  if (glyphs.length !== LEVELS) {
    throw new Error(`ramp must have exactly ${LEVELS} glyphs`);
  }
  assertGrid(grid);
  return grid.map((row) => row.map((c) => glyphs[c]).join(""));
}

/**
 * Recompute the figure of a `.eopx` from its manifest fields, as hex strings.
 *
 * Convenience for the verifier path (EPX-F §7 steps 2–4): the manifest carries
 * these fields hex-encoded, and this is the shape a caller already holds after
 * a signature check.
 */
export function figureFromManifest(
  merkleRootHex: string,
  dilithiumPkFpHex: string,
): { grid: number[][]; tag: string; epoch: string } {
  const fp = fromHex(dilithiumPkFpHex.trim());
  const grid = figureGrid(fromHex(merkleRootHex.trim()), fp);
  return { grid, tag: figureTag(grid), epoch: epochId(fp) };
}
