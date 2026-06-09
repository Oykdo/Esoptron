import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { layerKey, openSealedRaw, openSealedLayer, tryReveal } from "../reveal";
import { fromHex, toHex } from "../crypto";

// Vector sealed by the Python PoC (scripts/epx_reveal_poc.py) — proves the
// browser opens a layer sealed in Python (HKDF-SHA3-512 + ChaCha20-Poly1305).
const dir = path.dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(path.join(dir, "reveal_vector.json"), "utf8"));
const relic = fromHex(V.relic_secret_hex);

describe("EPX-L reveal — interop with Python (epx_reveal_poc.py)", () => {
  it("derives the same HKDF-SHA3-512 layer key as Python", () => {
    expect(toHex(layerKey(relic))).toBe(V.layer_key_hex);
  });

  it("opens the Python ChaCha20-Poly1305 sealed layer byte-exact", () => {
    const raw = new TextDecoder().decode(openSealedRaw(relic, V.sealed_hex));
    expect(raw).toBe(V.hidden_plaintext);
  });

  it("parses the revealed hidden layer", () => {
    const h = openSealedLayer(relic, V.sealed_hex);
    expect(h.layer).toBe("primordial_echo");
    expect(h.surfaces.length).toBe(12);
    expect(h.anim.period_s).toBe(7);
  });

  it("rejects a wrong/absent relic (stays sealed)", () => {
    expect(() => openSealedLayer(new Uint8Array(32), V.sealed_hex)).toThrow();
    expect(tryReveal(new Uint8Array(32), V.sealed_hex)).toBeNull();
    expect(tryReveal(null, V.sealed_hex)).toBeNull();
  });
});
