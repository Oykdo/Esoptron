/**
 * Shamir GF(2^8) parity tests against Python ``eopx.format.shamir``.
 *
 * For each deterministic vector we:
 *   1. Reproduce the exact shares by injecting the Python-recorded
 *      polynomial coefficients via the ``randomCoeff`` hook.
 *   2. Verify that any ``k`` of the ``n`` shares reconstruct the secret.
 */

import { describe, expect, it } from "vitest";

import vectors from "./vectors.json";
import { fromHex, toHex } from "../crypto";
import { combine, gfDiv, gfInv, gfMul, split } from "../shamir";

interface ShareVec {
  index: number;
  bytes_hex: string;
}
interface ShamirVec {
  secret_hex: string;
  k: number;
  n: number;
  coeffs: number[][];   // [pos][j-1]
  shares: ShareVec[];
}

describe("GF(2^8) low-level identities", () => {
  it("0x53 * 0xCA == 0x01 (Rijndael AES inv example)", () => {
    expect(gfMul(0x53, 0xca)).toBe(0x01);
  });
  it("gfMul(0, x) == 0", () => {
    for (let x = 0; x < 256; x++) expect(gfMul(0, x)).toBe(0);
  });
  it("gfInv(gfMul(a, b)) round-trip", () => {
    for (let a = 1; a < 256; a++) {
      expect(gfDiv(a, a)).toBe(1);
      expect(gfMul(a, gfInv(a))).toBe(1);
    }
  });
});

describe("Shamir Python ↔ TS parity", () => {
  for (const [i, v] of (vectors.shamir as ShamirVec[]).entries()) {
    it(`vector ${i} (${v.secret_hex.length / 2} bytes, k=${v.k}, n=${v.n})`,
      () => {
        const secret = fromHex(v.secret_hex);
        // Inject the recorded coefficients to make the split deterministic.
        const shares = split(secret, v.k, v.n, (pos, j) => v.coeffs[pos][j - 1]);
        // Compare share-by-share with the Python output.
        expect(shares).toHaveLength(v.shares.length);
        for (let s = 0; s < shares.length; s++) {
          expect(shares[s].index).toBe(v.shares[s].index);
          expect(toHex(shares[s].bytes)).toBe(v.shares[s].bytes_hex);
        }
        // Now combine any k of them and recover the secret.
        const subset = shares.slice(0, v.k);
        expect(toHex(combine(subset))).toBe(v.secret_hex);
        // Combining a different k-subset must yield the same secret.
        if (v.n > v.k) {
          const subset2 = shares.slice(shares.length - v.k);
          expect(toHex(combine(subset2))).toBe(v.secret_hex);
        }
      });
  }
});

describe("Shamir invariants", () => {
  it("k=1 split yields identical share bytes", () => {
    const secret = new Uint8Array([1, 2, 3, 4]);
    const shares = split(secret, 1, 3, () => 0); // no random coeffs needed
    for (const sh of shares) expect(Array.from(sh.bytes)).toEqual([1, 2, 3, 4]);
    expect(Array.from(combine([shares[0]]))).toEqual([1, 2, 3, 4]);
  });

  it("rejects empty secret", () => {
    expect(() => split(new Uint8Array(0), 2, 3)).toThrow();
  });
  it("rejects k > n", () => {
    expect(() => split(new Uint8Array([1]), 4, 3)).toThrow();
  });
  it("rejects duplicate indices in combine", () => {
    expect(() => combine([
      { index: 1, bytes: new Uint8Array([1]) },
      { index: 1, bytes: new Uint8Array([2]) },
    ])).toThrow();
  });
});
