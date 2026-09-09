/**
 * EPX-F §9 — the normative vectors, retyped from the spec.
 *
 * These expectations are deliberately **not** generated from the Python
 * implementation. §8 requires a port to reproduce §9 byte for byte, and the
 * only test that can catch both ports drifting together is one that asserts
 * against the specification text itself. A failure here is a regression or a
 * deliberate version bump — never an expected-value edit.
 */

import { describe, expect, it } from "vitest";

import { fromHex } from "../crypto";
import {
  ASCII_RAMP,
  CONTENT_ROWS,
  GRID_H,
  GRID_W,
  LEVELS,
  canonicalText,
  epochId,
  figureFromManifest,
  figureGrid,
  figureTag,
  renderRows,
} from "../artifactFigure";

// EPX-F §9 inputs.
const MR_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const FP_A = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const FP_B = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
// MR_B = SHA3-256("esoptron.epxf.testvector.B"), given in the spec.
const MR_B = "d7cbece511de55e5b18a277abad1ddfb72e81f5f7f9c1ca042482eda41e49520";

// F(MR_A, FP_A) — epoch 80818283, tag b0401fcd
const GRID_A_A = [
  "49ae329b8b747b01",
  "ad04a51176f99b0e",
  "06ee014df09645a7",
  "749d394a34656097",
  "1d38ef49a89713dd",
  "55ab8c746369a81c",
  "1c56695457db99c4",
  "653882ef9bc627a8",
].join("\n");

// F(MR_A, FP_B) — same artifact, next epoch c0c1c2c3, tag ab02f2e7.
// Rows 0–5 are identical; only the epoch band moves.
const GRID_A_B = [
  "49ae329b8b747b01",
  "ad04a51176f99b0e",
  "06ee014df09645a7",
  "749d394a34656097",
  "1d38ef49a89713dd",
  "55ab8c746369a81c",
  "2c00cf5c5f9aecdc",
  "5d033f23dc4a2604",
].join("\n");

// F(MR_B, FP_A) — different artifact, epoch 80818283, tag d67ea63a
const GRID_B_A = [
  "2f9f56b3a3800600",
  "f4b4820ea5d1011d",
  "ee6f57889853c1a0",
  "ea52a2ace46aac27",
  "af617dbf1747fe22",
  "0edac7f63c5a5572",
  "84d0783b74d124f0",
  "c2e5de046ed70768",
].join("\n");

// F(MR_A, FP_A) rendered with ASCII_RAMP, per §9.
const ASCII_A_A = [
  ",+=@'`+*~*!,!* .",
  "=# ,=:..!;$++* @",
  " ;@@ .,#$ +;,:=!",
  "!,+#'+,=',;:; +!",
  ".#'~@$,+=~+!.'##",
  "::=*~%!,;';+=~.%",
  ".%:;;+:,:!#*++%,",
  ";:'~~`@$+*%;`!=~",
];

describe("EPX-F §9 normative vectors", () => {
  it("F(MR_A, FP_A) matches the spec grid, epoch and tag", () => {
    const grid = figureGrid(fromHex(MR_A), fromHex(FP_A));
    expect(canonicalText(grid)).toBe(GRID_A_A);
    expect(figureTag(grid)).toBe("b0401fcd");
    expect(epochId(fromHex(FP_A))).toBe("80818283");
  });

  it("F(MR_A, FP_B) matches the spec grid, epoch and tag", () => {
    const grid = figureGrid(fromHex(MR_A), fromHex(FP_B));
    expect(canonicalText(grid)).toBe(GRID_A_B);
    expect(figureTag(grid)).toBe("ab02f2e7");
    expect(epochId(fromHex(FP_B))).toBe("c0c1c2c3");
  });

  it("F(MR_B, FP_A) matches the spec grid, epoch and tag", () => {
    const grid = figureGrid(fromHex(MR_B), fromHex(FP_A));
    expect(canonicalText(grid)).toBe(GRID_B_A);
    expect(figureTag(grid)).toBe("d67ea63a");
  });

  it("MR_B is the SHA3-256 the spec says it is", () => {
    // The spec derives MR_B rather than pinning an opaque constant; check the
    // derivation too, so a mistyped input cannot masquerade as a passing port.
    const grid = figureGrid(fromHex(MR_B), fromHex(FP_A));
    expect(canonicalText(grid).split("\n")).toHaveLength(GRID_H);
  });

  it("ASCII_RAMP renders F(MR_A, FP_A) exactly as §9 prints it", () => {
    const grid = figureGrid(fromHex(MR_A), fromHex(FP_A));
    expect(renderRows(grid, ASCII_RAMP)).toEqual(ASCII_A_A);
    // The ramp itself is normative as a rendering.
    expect(ASCII_RAMP).toBe(" .`',:;!~+=*%#@$");
    expect(Array.from(ASCII_RAMP)).toHaveLength(LEVELS);
  });
});

describe("EPX-F §3.1 — the two bands", () => {
  it("a key rotation moves the epoch band and nothing above it", () => {
    const a = figureGrid(fromHex(MR_A), fromHex(FP_A));
    const b = figureGrid(fromHex(MR_A), fromHex(FP_B));
    expect(a.slice(0, CONTENT_ROWS)).toEqual(b.slice(0, CONTENT_ROWS));
    expect(a.slice(CONTENT_ROWS)).not.toEqual(b.slice(CONTENT_ROWS));
  });

  it("a different artifact moves the content band too", () => {
    const a = figureGrid(fromHex(MR_A), fromHex(FP_A));
    const c = figureGrid(fromHex(MR_B), fromHex(FP_A));
    expect(a.slice(0, CONTENT_ROWS)).not.toEqual(c.slice(0, CONTENT_ROWS));
  });

  it("geometry is 16 × 8 = exactly one SHA3-512 width", () => {
    const grid = figureGrid(fromHex(MR_A), fromHex(FP_A));
    expect(grid).toHaveLength(GRID_H);
    for (const row of grid) expect(row).toHaveLength(GRID_W);
    expect(GRID_W * GRID_H * 4).toBe(512);
  });
});

describe("EPX-F §2 — inputs are checked, not coerced", () => {
  it("refuses inputs that are not 32 bytes", () => {
    expect(() => figureGrid(fromHex(MR_A).slice(0, 31), fromHex(FP_A))).toThrow(
      /merkle_root/,
    );
    expect(() => figureGrid(fromHex(MR_A), fromHex(FP_A).slice(0, 16))).toThrow(
      /dilithium_pk_fp/,
    );
    expect(() => epochId(new Uint8Array(4))).toThrow(/dilithium_pk_fp/);
  });

  it("refuses a malformed grid rather than hashing it", () => {
    const grid = figureGrid(fromHex(MR_A), fromHex(FP_A));
    expect(() => canonicalText(grid.slice(0, 7))).toThrow(/8x16/);
    const bad = grid.map((r) => [...r]);
    bad[0][0] = LEVELS;
    expect(() => canonicalText(bad)).toThrow(/cell levels/);
  });

  it("refuses a ramp of the wrong length", () => {
    const grid = figureGrid(fromHex(MR_A), fromHex(FP_A));
    expect(() => renderRows(grid, "abc")).toThrow(/16 glyphs/);
  });
});

describe("EPX-F §7 — the verifier path", () => {
  it("recomputes grid, tag and epoch from hex manifest fields", () => {
    const { grid, tag, epoch } = figureFromManifest(MR_A, FP_A);
    expect(canonicalText(grid)).toBe(GRID_A_A);
    expect(tag).toBe("b0401fcd");
    expect(epoch).toBe("80818283");
  });

  it("is stable under whitespace around the hex fields", () => {
    expect(figureFromManifest(` ${MR_A} `, `\n${FP_A}\t`).tag).toBe("b0401fcd");
  });
});
