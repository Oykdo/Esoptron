/**
 * Genesis card payload + input validation tests.
 *
 * Visual rendering (canvas → PNG) requires a browser DOM and is left
 * to manual/e2e validation. These tests exercise the pure data path:
 * payload shape, archetype id consistency, and verifier interop.
 */

import { describe, expect, it } from "vitest";

import {
  GenesisSeal,
  TOTAL_GENESIS,
  archetypeForSequence,
  archetypeOf,
  archetypesCommitmentHex,
  derivePositions,
} from "../genesisToken";
import {
  GenesisCardInputs,
  buildGenesisQrPayload,
  buildGenesisSealEnvelope,
  renderGenesisCardPng,
} from "../genesisCard";

function buildInputs(): GenesisCardInputs {
  const btcHash = new Uint8Array(32).fill(0xab);
  const btcHashHex = "ab".repeat(32);
  const positions = derivePositions(btcHash, { btcBlockHeight: 925_000 });
  const sequence = positions[0];
  const archetype = archetypeForSequence(sequence, positions)!;
  const seal: GenesisSeal = {
    schema_version: 1,
    vault_fp_hex: "fd83".padEnd(64, "0"),
    sequence,
    archetype_id: archetype.id,
    btc_block_height: 925_000,
    btc_block_hash_hex: btcHashHex,
    signer_pk_fp_hex: "01".repeat(32),
    signature_hex: "00".repeat(4627),
  };
  return {
    vaultFpHex: seal.vault_fp_hex,
    sequence,
    btcBlockHashHex: btcHashHex,
    btcBlockHeight: 925_000,
    deploymentPkHex: "02".repeat(2592),
    genesisSeal: seal,
  };
}

describe("buildGenesisQrPayload", () => {
  it("produces a pointer aligned with the seal contract", () => {
    const inputs = buildInputs();
    const payload = buildGenesisQrPayload(inputs);
    expect(payload.type).toBe("esoptron-genesis-card");
    expect(payload.schema_version).toBe(1);
    expect(payload.sequence).toBe(inputs.sequence);
    expect(payload.archetype_id).toBe(inputs.genesisSeal.archetype_id);
    expect(payload.vault_fp_hex).toBe(inputs.vaultFpHex);
    expect(payload.btc_block_hash_hex).toBe(inputs.btcBlockHashHex);
    expect(payload.btc_block_height).toBe(inputs.btcBlockHeight);
    expect(payload.signer_pk_fp_hex)
      .toBe(inputs.genesisSeal.signer_pk_fp_hex);
  });

  it("does NOT embed the signature or deployment pk (capacity)", () => {
    const payload = buildGenesisQrPayload(buildInputs()) as unknown as
      Record<string, unknown>;
    expect(payload.signature_hex).toBeUndefined();
    expect(payload.deployment_pk_hex).toBeUndefined();
  });

  it("pins the archetypes commitment so renderers stay in lockstep", () => {
    const payload = buildGenesisQrPayload(buildInputs());
    expect(payload.archetypes_commitment_hex)
      .toBe(archetypesCommitmentHex());
  });

  it("round-trips through JSON.stringify without loss", () => {
    const payload = buildGenesisQrPayload(buildInputs());
    const round = JSON.parse(JSON.stringify(payload));
    expect(round).toEqual(payload);
  });

  it("payload fits comfortably inside a single QR (≤500 bytes JSON)", () => {
    // The pointer payload must stay small enough to print at level Q
    // error correction. 500 bytes leaves room for the type tag, the
    // hex fields (vault_fp + btc_hash + signer_fp + commitment = 4×
    // 64 = 256 chars) plus envelope.
    const json = JSON.stringify(buildGenesisQrPayload(buildInputs()));
    expect(json.length).toBeLessThanOrEqual(500);
  });

  it("includes anchor_url when provided", () => {
    const inputs = buildInputs();
    const payload = buildGenesisQrPayload({
      ...inputs, anchorUrl: "https://esoptron.app/api/v1",
    });
    expect(payload.anchor_url).toBe("https://esoptron.app/api/v1");
  });

  it("omits anchor_url when not provided", () => {
    const payload = buildGenesisQrPayload(buildInputs());
    expect(payload.anchor_url).toBeUndefined();
  });
});

describe("buildGenesisSealEnvelope", () => {
  it("carries the full signature for offline verification", () => {
    const inputs = buildInputs();
    const env = buildGenesisSealEnvelope(inputs);
    expect(env.type).toBe("esoptron-genesis-seal");
    expect(env.signature_hex).toBe(inputs.genesisSeal.signature_hex);
    expect(env.deployment_pk_hex).toBe(inputs.deploymentPkHex);
    expect(env.pointer.sequence).toBe(inputs.sequence);
    expect(env.pointer.archetype_id)
      .toBe(inputs.genesisSeal.archetype_id);
  });

  it("envelope size accommodates Dilithium5 signature payload", () => {
    // 4627 sig + 2592 pk = 7219 bytes ~ 14438 hex. The envelope JSON
    // should be ≥ 14 KB but ≤ 20 KB (with field names + nesting).
    const json = JSON.stringify(buildGenesisSealEnvelope(buildInputs()));
    expect(json.length).toBeGreaterThan(14_000);
    expect(json.length).toBeLessThan(20_000);
  });
});

describe("renderGenesisCardPng input validation", () => {
  it("rejects mismatched archetype id vs seal", async () => {
    const inputs = buildInputs();
    const wrongId = (inputs.genesisSeal.archetype_id + 1) % TOTAL_GENESIS;
    const wrongArchetype = archetypeOf(wrongId);
    await expect(
      renderGenesisCardPng({ ...inputs, archetype: wrongArchetype }),
    ).rejects.toThrow(/archetype\.id does not match seal\.archetype_id/);
  });
});
