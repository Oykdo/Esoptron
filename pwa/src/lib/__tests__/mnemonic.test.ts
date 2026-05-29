/**
 * BIP-39 parity tests: the TypeScript ``@scure/bip39`` implementation
 * must match the Python ``mnemonic`` library output for every vector.
 */

import { describe, expect, it } from "vitest";

import vectors from "./vectors.json";
import { fromHex, toHex } from "../crypto";
import { entropyToMnemonic, mnemonicToEntropy } from "../mnemonic";

describe("BIP-39 Python ↔ TS parity", () => {
  for (const [i, v] of vectors.bip39.entries()) {
    const lenBytes = v.entropy_hex.length / 2;
    const lenWords = v.words.length;
    it(`vector ${i} (${lenBytes} bytes → ${lenWords} words)`, () => {
      const entropy = fromHex(v.entropy_hex);
      const words = entropyToMnemonic(entropy);
      expect(words).toEqual(v.words);
      const back = mnemonicToEntropy(words);
      expect(toHex(back)).toBe(v.entropy_hex);
    });
  }
});

describe("BIP-39 official zero vector", () => {
  it("32 zero bytes → 23×abandon + art", () => {
    const words = entropyToMnemonic(new Uint8Array(32));
    expect(words[23]).toBe("art");
    expect(words.slice(0, 23).every((w) => w === "abandon")).toBe(true);
  });
});

describe("BIP-39 checksum validation", () => {
  it("rejects a permutation that breaks the checksum", () => {
    // Use a non-uniform entropy so distinct positions hold distinct words.
    const entropy = fromHex(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    const words = entropyToMnemonic(entropy);
    // Swap word #0 with the last word (which is the one carrying the
    // checksum bits and is virtually guaranteed to differ).
    const swapped = [...words];
    [swapped[0], swapped[words.length - 1]] = [
      swapped[words.length - 1],
      swapped[0],
    ];
    expect(swapped[0]).not.toBe(words[0]);
    expect(() => mnemonicToEntropy(swapped)).toThrow();
  });

  it("rejects an unknown word", () => {
    const words = entropyToMnemonic(new Uint8Array(32));
    words[0] = "notarealbip39word";
    expect(() => mnemonicToEntropy(words)).toThrow();
  });
});
