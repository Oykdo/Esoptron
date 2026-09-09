/**
 * EPX-F §9 — the normative vectors, for the standalone SDK port.
 *
 * §8 requires the TypeScript SDK *and* the PWA to reproduce §9 byte for byte.
 * The two ports share no code, so they are checked separately against the same
 * spec text rather than against each other: a test that compared them would
 * pass just as happily if both had drifted the same way.
 */

import { describe, expect, it } from "vitest";

import {
  ASCII_RAMP,
  CONTENT_ROWS,
  GRID_H,
  GRID_W,
  canonicalText,
  epochId,
  figureGrid,
  figureOf,
  figureTag,
  renderRows,
} from "./figure.js";

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

// EPX-F §9 inputs.
const MR_A = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const FP_A = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const FP_B = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
const MR_B = "d7cbece511de55e5b18a277abad1ddfb72e81f5f7f9c1ca042482eda41e49520";

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

describe("EPX-F §9 vectors (SDK port)", () => {
  it("F(MR_A, FP_A)", () => {
    const grid = figureGrid(hex(MR_A), hex(FP_A));
    expect(canonicalText(grid)).toBe(GRID_A_A);
    expect(figureTag(grid)).toBe("b0401fcd");
    expect(epochId(hex(FP_A))).toBe("80818283");
    expect(renderRows(grid, ASCII_RAMP)).toEqual(ASCII_A_A);
  });

  it("F(MR_A, FP_B) — same artifact, next epoch", () => {
    const grid = figureGrid(hex(MR_A), hex(FP_B));
    expect(canonicalText(grid)).toBe(GRID_A_B);
    expect(figureTag(grid)).toBe("ab02f2e7");
    expect(epochId(hex(FP_B))).toBe("c0c1c2c3");
  });

  it("F(MR_B, FP_A) — different artifact", () => {
    const grid = figureGrid(hex(MR_B), hex(FP_A));
    expect(canonicalText(grid)).toBe(GRID_B_A);
    expect(figureTag(grid)).toBe("d67ea63a");
  });
});

describe("EPX-F §3.1 — two bands (SDK port)", () => {
  it("a key rotation moves the epoch band and nothing above it", () => {
    const a = figureGrid(hex(MR_A), hex(FP_A));
    const b = figureGrid(hex(MR_A), hex(FP_B));
    expect(a.slice(0, CONTENT_ROWS)).toEqual(b.slice(0, CONTENT_ROWS));
    expect(a.slice(CONTENT_ROWS)).not.toEqual(b.slice(CONTENT_ROWS));
  });

  it("geometry is 16 × 8 = one SHA3-512 width", () => {
    const grid = figureGrid(hex(MR_A), hex(FP_A));
    expect(grid).toHaveLength(GRID_H);
    for (const row of grid) expect(row).toHaveLength(GRID_W);
    expect(GRID_W * GRID_H * 4).toBe(512);
  });
});

describe("EPX-F §7 — the verifier path (SDK port)", () => {
  it("figureOf takes the manifest fields as the manifest carries them", () => {
    const f = figureOf({ merkleRoot: MR_A, dilithiumPkFp: FP_A });
    expect(f.canonicalText).toBe(GRID_A_A);
    expect(f.tag).toBe("b0401fcd");
    expect(f.epoch).toBe("80818283");
  });

  it("refuses malformed inputs rather than coercing them", () => {
    expect(() => figureOf({ merkleRoot: "zz", dilithiumPkFp: FP_A })).toThrow(
      /valid hex/
    );
    expect(() =>
      figureOf({ merkleRoot: MR_A.slice(0, 40), dilithiumPkFp: FP_A })
    ).toThrow(/32 bytes/);
    expect(() => epochId(new Uint8Array(4))).toThrow(/dilithium_pk_fp/);
  });
});
