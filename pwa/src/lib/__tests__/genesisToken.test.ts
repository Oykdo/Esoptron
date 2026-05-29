/**
 * Genesis Token — Python ↔ TypeScript parity tests.
 *
 * Three groups of checks:
 *   1. Archetype catalog commitment hash must match Python byte-for-byte.
 *   2. Position derivation from a Bitcoin block hash must produce the
 *      same 88 sorted positions on both sides.
 *   3. Genesis seal signed by Python's ``ml_dsa_87`` must verify in
 *      TypeScript via ``@noble/post-quantum/ml-dsa.ml_dsa87``.
 */

import { describe, expect, it } from "vitest";

import vectors from "./vectors.json";
import { fromHex, toHex } from "../crypto";
import {
  allArchetypes,
  archetypeForSequence,
  archetypeOf,
  archetypesCommitmentHex,
  derivePositions,
  GenesisSeal,
  isGenesis,
  LATTICE_ELEMENTS,
  LATTICE_PATTERNS,
  TOTAL_GENESIS,
  verifyGenesisSeal,
} from "../genesisToken";

interface DerivationVec {
  btc_block_hash_hex: string;
  btc_block_height: number;
  positions: number[];
}

interface SealVec {
  deployment_pk_hex: string;
  btc_block_hash_hex: string;
  btc_block_height: number;
  positions: number[];
  seal: GenesisSeal;
}

interface GenesisVectors {
  archetypes_commitment_hex: string;
  derivations: DerivationVec[];
  seal: SealVec;
}

const G = (vectors as { genesis: GenesisVectors }).genesis;

describe("Archetype catalog parity", () => {
  it("has 22 patterns × 4 elements = 88 archetypes", () => {
    expect(LATTICE_PATTERNS.length).toBe(22);
    expect(LATTICE_ELEMENTS.length).toBe(4);
    expect(TOTAL_GENESIS).toBe(88);
    expect(allArchetypes().length).toBe(88);
  });

  it("commitment hash matches Python byte-for-byte", () => {
    expect(archetypesCommitmentHex()).toBe(G.archetypes_commitment_hex);
  });

  it("archetype 0 is Source of Air with hue 200", () => {
    const a = archetypeOf(0);
    expect(a.pattern).toBe("Source");
    expect(a.element).toBe("Air");
    expect(a.glyph).toBe("SOU-AIR");
    expect(a.colorHue).toBe(200);
  });

  it("archetype 87 is Lotus of Earth with hue 95", () => {
    const a = archetypeOf(87);
    expect(a.pattern).toBe("Lotus");
    expect(a.element).toBe("Earth");
    expect(a.glyph).toBe("LOT-EAR");
    expect(a.colorHue).toBe(95);
  });

  it("rejects out-of-range archetype ids", () => {
    expect(() => archetypeOf(-1)).toThrow();
    expect(() => archetypeOf(88)).toThrow();
  });
});

describe("Position derivation parity", () => {
  for (const [i, v] of G.derivations.entries()) {
    it(`derivation ${i} matches Python (height=${v.btc_block_height})`, () => {
      const positions = derivePositions(fromHex(v.btc_block_hash_hex), {
        btcBlockHeight: v.btc_block_height,
      });
      expect(positions).toEqual(v.positions);
    });
  }

  it("produces 88 distinct sorted positions in [1, 333333]", () => {
    const v = G.derivations[0];
    const positions = derivePositions(fromHex(v.btc_block_hash_hex), {
      btcBlockHeight: v.btc_block_height,
    });
    expect(positions.length).toBe(88);
    expect(new Set(positions).size).toBe(88);
    expect([...positions]).toEqual([...positions].sort((a, b) => a - b));
    expect(positions.every((p) => p >= 1 && p <= 333_333)).toBe(true);
  });

  it("changes completely when block hash changes by one bit", () => {
    const v = G.derivations[0];
    const original = fromHex(v.btc_block_hash_hex);
    const flipped = new Uint8Array(original);
    flipped[0] ^= 0x01;
    const a = derivePositions(original, { btcBlockHeight: v.btc_block_height });
    const b = derivePositions(flipped, { btcBlockHeight: v.btc_block_height });
    // Almost certain disjoint sets; require at least 80 different.
    const common = new Set(a).size + new Set(b).size -
      new Set([...a, ...b]).size;
    expect(common).toBeLessThan(8);
  });

  it("rejects non-32-byte block hashes", () => {
    expect(() => derivePositions(new Uint8Array(31))).toThrow();
    expect(() => derivePositions(new Uint8Array(33))).toThrow();
  });
});

describe("isGenesis and archetypeForSequence", () => {
  const v = G.derivations[0];
  const positions = v.positions;

  it("isGenesis hits each of the 88 positions", () => {
    for (const p of positions) expect(isGenesis(p, positions)).toBe(true);
  });

  it("isGenesis misses non-positions", () => {
    const bag = new Set(positions);
    let cnt = 0;
    for (let cand = 1; cnt < 20 && cand < 333_333; cand++) {
      if (bag.has(cand)) continue;
      expect(isGenesis(cand, positions)).toBe(false);
      cnt++;
    }
  });

  it("archetypeForSequence assigns ids in sorted order", () => {
    const sorted = [...positions].sort((a, b) => a - b);
    sorted.forEach((p, rank) => {
      const a = archetypeForSequence(p, positions);
      expect(a).not.toBeNull();
      expect(a!.id).toBe(rank);
    });
  });

  it("archetypeForSequence returns null for non-genesis", () => {
    const bag = new Set(positions);
    const cand = [...Array(333_333).keys()].find((c) => !bag.has(c + 1))! + 1;
    expect(archetypeForSequence(cand, positions)).toBeNull();
  });
});

describe("Genesis seal — Python → TS interop", () => {
  it("verifies a Dilithium5-signed seal from Python", () => {
    const deploymentPk = fromHex(G.seal.deployment_pk_hex);
    const ok = verifyGenesisSeal(G.seal.seal, deploymentPk, G.seal.positions);
    expect(ok).toBe(true);
  });

  it("rejects a tampered archetype_id", () => {
    const tampered: GenesisSeal = {
      ...G.seal.seal,
      archetype_id: (G.seal.seal.archetype_id + 1) % 88,
    };
    const ok = verifyGenesisSeal(tampered,
      fromHex(G.seal.deployment_pk_hex), G.seal.positions);
    expect(ok).toBe(false);
  });

  it("rejects a tampered vault_fp_hex", () => {
    const tampered: GenesisSeal = {
      ...G.seal.seal,
      vault_fp_hex: "ff".repeat(32),
    };
    expect(verifyGenesisSeal(tampered,
      fromHex(G.seal.deployment_pk_hex), G.seal.positions)).toBe(false);
  });

  it("rejects a tampered signature", () => {
    const sig = fromHex(G.seal.seal.signature_hex);
    sig[10] ^= 0xff;
    const tampered: GenesisSeal = {
      ...G.seal.seal,
      signature_hex: toHex(sig),
    };
    expect(verifyGenesisSeal(tampered,
      fromHex(G.seal.deployment_pk_hex), G.seal.positions)).toBe(false);
  });

  it("rejects a wrong deployment public key", () => {
    const pk = fromHex(G.seal.deployment_pk_hex);
    pk[0] ^= 0xff;
    expect(verifyGenesisSeal(G.seal.seal, pk, G.seal.positions)).toBe(false);
  });

  it("rejects a seal whose sequence is not in positions", () => {
    const bag = new Set(G.seal.positions);
    const fakePositions = G.seal.positions.filter(
      (_, i) => i !== G.seal.positions.indexOf(G.seal.seal.sequence),
    );
    // Make sure the seal's sequence really is no longer present
    expect(bag.size).toBe(88);
    expect(fakePositions.length).toBe(87);
    expect(verifyGenesisSeal(G.seal.seal,
      fromHex(G.seal.deployment_pk_hex), fakePositions)).toBe(false);
  });

  it("rejects a wrong schema_version", () => {
    const tampered: GenesisSeal = {
      ...G.seal.seal,
      schema_version: 999,
    };
    expect(verifyGenesisSeal(tampered,
      fromHex(G.seal.deployment_pk_hex), G.seal.positions)).toBe(false);
  });
});
