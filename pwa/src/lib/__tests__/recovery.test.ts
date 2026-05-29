/**
 * Cross-language Holographic Recovery tests.
 *
 * Each vector contains a ``RecoveryPackage`` produced by the Python
 * implementation. Since Argon2id, ChaCha20-Poly1305 and ML-KEM-1024
 * are all deterministic given inputs, the TypeScript port MUST decrypt
 * the package and recover the original entropy bit-for-bit.
 *
 * The card_pin × passphrase pair runs first because it is the fastest
 * (no ML-KEM decapsulation); the kyber × passphrase pair confirms the
 * post-quantum interop end-to-end.
 */

import { describe, expect, it } from "vitest";

import vectors from "./vectors.json";
import { fromHex, toHex } from "../crypto";
import {
  FlexibleCredentials,
  packageFromJson,
  packageToJson,
  recoverEntropy,
  recoverEntropyFlexible,
  RecoveryCredentials,
  RecoveryPackage,
  setupRecovery,
  setupRecoveryFlexible,
  ShareConfig,
} from "../recovery";

interface RecoveryVec {
  entropy_hex: string;
  card_pin: string;
  cloud_passphrase: string;
  contact_pk_hex: string;
  contact_sk_hex: string;
  package: Record<string, unknown>;
}

describe("Holographic Recovery — Python → TS interop", () => {
  for (const [i, vRaw] of (vectors.recovery as RecoveryVec[]).entries()) {
    const v = vRaw;

    describe(`vector ${i}`, () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const pkg = packageFromJson(v.package as any);

      it("recovers via PIN + passphrase", () => {
        const out = recoverEntropy(pkg, {
          cardPin: v.card_pin,
          cloudPassphrase: v.cloud_passphrase,
        });
        expect(toHex(out)).toBe(v.entropy_hex);
      });

      it("recovers via Kyber sk + passphrase", () => {
        const out = recoverEntropy(pkg, {
          contactKyberSk: fromHex(v.contact_sk_hex),
          cloudPassphrase: v.cloud_passphrase,
        });
        expect(toHex(out)).toBe(v.entropy_hex);
      });

      it("recovers via PIN + Kyber sk", () => {
        const out = recoverEntropy(pkg, {
          cardPin: v.card_pin,
          contactKyberSk: fromHex(v.contact_sk_hex),
        });
        expect(toHex(out)).toBe(v.entropy_hex);
      });

      it("fails with only one credential", () => {
        expect(() => recoverEntropy(pkg,
          { cardPin: v.card_pin })).toThrow();
        expect(() => recoverEntropy(pkg,
          { cloudPassphrase: v.cloud_passphrase })).toThrow();
        expect(() => recoverEntropy(pkg,
          { contactKyberSk: fromHex(v.contact_sk_hex) })).toThrow();
      });

      it("fails with wrong PIN even paired with right passphrase", () => {
        expect(() => recoverEntropy(pkg, {
          cardPin: "999999",
          cloudPassphrase: v.cloud_passphrase,
        })).toThrow(); // only passphrase opens → threshold not met
      });

      it("JSON round-trip preserves recovery", () => {
        const back = packageFromJson(packageToJson(pkg));
        const out = recoverEntropy(back, {
          cardPin: v.card_pin,
          cloudPassphrase: v.cloud_passphrase,
        });
        expect(toHex(out)).toBe(v.entropy_hex);
      });
    });
  }
});

describe("Holographic Recovery — TS-only round-trip", () => {
  /**
   * Sanity test that the TS implementation can also create a package
   * (with its own randomness) and recover from it locally. This catches
   * any divergence in the TS setup path that the cross-language test
   * would miss (since it only exercises the recover path).
   */
  it("setupRecovery → recoverEntropy round-trips for fresh randomness",
    async () => {
      const { ml_kem1024 } = await import("@noble/post-quantum/ml-kem");
      const kp = ml_kem1024.keygen();
      const entropy = new Uint8Array(32);
      crypto.getRandomValues(entropy);

      const pkg: RecoveryPackage = setupRecovery({
        deviceEntropy: entropy,
        cardPin: "424242",
        contactKyberPk: kp.publicKey,
        cloudPassphrase: "correct horse battery staple",
        vaultFpHex: "00".repeat(32),
      });

      // All three pairings must recover.
      for (const creds of [
        { cardPin: "424242", cloudPassphrase: "correct horse battery staple" },
        { cardPin: "424242", contactKyberSk: kp.secretKey },
        { contactKyberSk: kp.secretKey, cloudPassphrase: "correct horse battery staple" },
      ] as RecoveryCredentials[]) {
        const out = recoverEntropy(pkg, creds);
        expect(toHex(out)).toBe(toHex(entropy));
      }
    });
});

describe("Flexible k-of-n Recovery", () => {
  it("3-of-5 mixed shares round-trips", async () => {
    const { ml_kem1024 } = await import("@noble/post-quantum/ml-kem");
    const alice = ml_kem1024.keygen();
    const bob = ml_kem1024.keygen();

    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);

    const configs: ShareConfig[] = [
      { kind: "card_pin", secret: "111111" },
      { kind: "card_pin", secret: "222222" },
      { kind: "kyber_pk", recipientPk: alice.publicKey },
      { kind: "kyber_pk", recipientPk: bob.publicKey },
      { kind: "passphrase", secret: "long secret phrase here" },
    ];

    const pkg = setupRecoveryFlexible({
      deviceEntropy: entropy,
      shareConfigs: configs,
      vaultFpHex: "ab".repeat(32),
      threshold: 3,
    });

    expect(pkg.threshold).toBe(3);
    expect(pkg.total).toBe(5);
    expect(pkg.shares.length).toBe(5);

    // Recover with shares 1, 3, 5
    const creds: FlexibleCredentials = {
      pins: new Map([[1, "111111"]]),
      kyberSks: new Map([[3, alice.secretKey]]),
      passphrases: new Map([[5, "long secret phrase here"]]),
    };
    const recovered = recoverEntropyFlexible(pkg, creds);
    expect(toHex(recovered)).toBe(toHex(entropy));
  });

  it("2-of-4 all passphrases round-trips", () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);

    const pkg = setupRecoveryFlexible({
      deviceEntropy: entropy,
      shareConfigs: [
        { kind: "passphrase", secret: "phrase one here!" },
        { kind: "passphrase", secret: "phrase two here!" },
        { kind: "passphrase", secret: "phrase three here" },
        { kind: "passphrase", secret: "phrase four here!" },
      ],
      vaultFpHex: "cd".repeat(32),
      threshold: 2,
    });

    expect(pkg.threshold).toBe(2);
    expect(pkg.total).toBe(4);

    const creds: FlexibleCredentials = {
      pins: new Map(),
      kyberSks: new Map(),
      passphrases: new Map([
        [2, "phrase two here!"],
        [4, "phrase four here!"],
      ]),
    };
    const recovered = recoverEntropyFlexible(pkg, creds);
    expect(toHex(recovered)).toBe(toHex(entropy));
  });

  it("rejects threshold > total", () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);

    expect(() => setupRecoveryFlexible({
      deviceEntropy: entropy,
      shareConfigs: [
        { kind: "passphrase", secret: "12345678" },
        { kind: "passphrase", secret: "87654321" },
      ],
      vaultFpHex: "00".repeat(32),
      threshold: 3,
    })).toThrow(/threshold.*>.*total/i);
  });

  it("rejects short PIN", () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);

    expect(() => setupRecoveryFlexible({
      deviceEntropy: entropy,
      shareConfigs: [
        { kind: "card_pin", secret: "123" }, // too short
        { kind: "passphrase", secret: "12345678" },
      ],
      vaultFpHex: "00".repeat(32),
      threshold: 2,
    })).toThrow(/card_pin must be >= 4/);
  });

  it("rejects short passphrase", () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);

    expect(() => setupRecoveryFlexible({
      deviceEntropy: entropy,
      shareConfigs: [
        { kind: "passphrase", secret: "short" }, // too short
        { kind: "passphrase", secret: "12345678" },
      ],
      vaultFpHex: "00".repeat(32),
      threshold: 2,
    })).toThrow(/passphrase must be >= 8/);
  });

  it("fails if not enough shares provided", () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);

    const pkg = setupRecoveryFlexible({
      deviceEntropy: entropy,
      shareConfigs: [
        { kind: "passphrase", secret: "phrase one!" },
        { kind: "passphrase", secret: "phrase two!" },
        { kind: "passphrase", secret: "phrase three" },
      ],
      vaultFpHex: "00".repeat(32),
      threshold: 2,
    });

    // Only provide 1 credential
    const creds: FlexibleCredentials = {
      pins: new Map(),
      kyberSks: new Map(),
      passphrases: new Map([[1, "phrase one!"]]),
    };
    expect(() => recoverEntropyFlexible(pkg, creds))
      .toThrow(/could not open enough shares/);
  });
});
