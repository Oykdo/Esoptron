/**
 * Cross-language parity tests for the TypeScript enrollment port.
 *
 * Each fixture in ``vectors.json`` was produced by the canonical Python
 * implementation; running this file asserts that the TS code computes
 * **byte-for-byte identical** outputs. Any drift fails CI.
 *
 * Regenerate vectors with::
 *
 *     py scripts/gen_test_vectors.py
 */

import { describe, expect, it } from "vitest";

import vectors from "./vectors.json";
import { cardFingerprint, fromHex, hkdfSha3_512, toHex } from "../crypto";
import { enrollFromCard } from "../enrollment";

describe("HKDF-SHA3-512 parity", () => {
  for (const [i, v] of vectors.hkdf_sha3_512.entries()) {
    it(`vector ${i} (length=${v.length})`, () => {
      const out = hkdfSha3_512(
        fromHex(v.ikm_hex),
        fromHex(v.salt_hex),
        fromHex(v.info_hex),
        v.length,
      );
      expect(toHex(out)).toBe(v.expected_hex);
    });
  }
});

describe("card_fingerprint parity", () => {
  for (const [i, v] of vectors.card_fingerprint.entries()) {
    it(`vector ${i}`, () => {
      const fp = cardFingerprint(v.symbols);
      expect(toHex(fp)).toBe(v.expected_hex);
    });
  }
});

describe("enroll_from_card parity", () => {
  for (const [i, v] of vectors.enroll_from_card.entries()) {
    it(`vector ${i}`, () => {
      const rec = enrollFromCard(v.symbols, fromHex(v.device_entropy_hex));
      expect(toHex(rec.vaultFp)).toBe(v.expected.vault_fp_hex);
      expect(toHex(rec.deviceSecret)).toBe(v.expected.device_secret_hex);
      expect(toHex(rec.enrollmentFp)).toBe(v.expected.enrollment_fp_hex);
      expect(toHex(rec.publicTag)).toBe(v.expected.public_tag_hex);
      expect(toHex(rec.shadowHologram)).toBe(v.expected.shadow_hologram_hex);
    });
  }
});

describe("argument validation", () => {
  it("cardFingerprint rejects wrong symbol count", () => {
    expect(() => cardFingerprint([1, 2, 3])).toThrow();
  });
  it("enrollFromCard rejects wrong entropy length", () => {
    const sym = Array.from({ length: 91 }, (_, i) => i % 13);
    expect(() => enrollFromCard(sym, new Uint8Array(16))).toThrow();
  });
  it("enrollFromCard rejects wrong symbol count", () => {
    expect(() => enrollFromCard([1, 2, 3], new Uint8Array(32))).toThrow();
  });
});

describe("symbol range validation matches Python", () => {
  // Both ports now reject out-of-range symbols rather than silently
  // reducing mod 13. This catches decoder regressions early.
  it("rejects symbols >= 13", () => {
    const wrapAround = Array.from({ length: 91 }, () => 13);
    expect(() => cardFingerprint(wrapAround)).toThrow(/out of range/);
  });
  it("rejects negative symbols", () => {
    const neg = Array.from({ length: 91 }, () => -1);
    expect(() => cardFingerprint(neg)).toThrow(/out of range/);
  });
});
