/**
 * BIP-39 mnemonic helpers, mirroring the Python ``mnemonic`` package
 * usage in ``eopx.vault.genesis``.
 *
 * Backed by ``@scure/bip39`` with the official English wordlist. Any
 * mnemonic produced here decodes correctly via Python
 * ``Mnemonic('english').to_entropy(...)`` and vice-versa.
 */

import {
  entropyToMnemonic as scureEntropyToMnemonic,
  mnemonicToEntropy as scureMnemonicToEntropy,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english";

/** 32 bytes of entropy → 24-word BIP-39 phrase (English). */
export function entropyToMnemonic(entropy: Uint8Array): string[] {
  const phrase = scureEntropyToMnemonic(entropy, english);
  return phrase.split(" ");
}

/** 24-word phrase → 32-byte entropy. Throws on checksum failure. */
export function mnemonicToEntropy(words: string[] | string): Uint8Array {
  const phrase = Array.isArray(words)
    ? words.map((w) => w.trim().toLowerCase()).join(" ")
    : words.trim().toLowerCase();
  if (!validateMnemonic(phrase, english))
    throw new Error("invalid BIP-39 mnemonic (bad checksum or word)");
  return scureMnemonicToEntropy(phrase, english);
}
