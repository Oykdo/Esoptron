# EPX-L — Relic-Keyed Hidden Holographic Layer

**Status:** Draft (spec-first). Owner: Logos Project.
**Builds on:** EPX-V (voucher / treasure-hunt claim), EPX-R (runic plate +
scan), and the `blend_data` hologram (`RelicCanvas`).
**PoC:** `scripts/epx_reveal_poc.py` (validated — see §10).

A hologram's `blend_data` carries a **public layer** (always visible) and one or
more **sealed layers** — extra animated surfaces that are **AEAD-encrypted,
opaque, and invisible** until unlocked. A physical **relic** (an EPX-R plate,
durably engraved) carries a per-relic secret. **Scanning the relic** recovers
that secret, derives the layer key, and **reveals + animates** the hidden
surfaces — fully **offline, deterministic, and serverless**, so it survives
epochs.

---

## 1. Roles & terms

- **Relic.** A physical EPX-R plate engraving a 32-byte `relic_secret`.
  Found-and-scanned to claim/unlock (EPX-V treasure-hunt model).
- **Voucher commitment.** `SHA3/SHA256("voucher" || relic_secret)` — the public,
  anchorable proof of the relic's existence; reveals nothing.
- **Public layer.** The visible hologram (e.g. the Metatron cube).
- **Sealed layer.** An AEAD ciphertext of a hidden-surface payload, stored
  inline in `blend_data`; opaque (invisible) without the relic.
- **Layer key.** `HKDF(relic_secret, "eidolon.relic.layer.v1")`.

---

## 2. Anchoring (serverless, epoch-proof)

`relic_secret = HKDF(GENESIS, "relic" || relic_key)` where `GENESIS` is a fixed,
publicly known constant (the genesis Bitcoin block hash, as in
`eopx.genesis_token`). The whole derivation is **deterministic and reproducible
forever, with no server**: given the relic and the public `blend_data`, anyone
can unlock offline, today or in decades. The **voucher commitment** is published
(ledger / EPX-V) so the relic's authenticity is verifiable without revealing the
secret.

---

## 3. The sealed layer

```
sealed = AEAD_seal(layer_key(relic_secret), hidden_payload)
blend_data.sealed_layers += [ sealed ]      # opaque bytes, inert
```

`hidden_payload` describes the extra animated surfaces (geometry + an animation
descriptor, e.g. `{"surfaces":[...], "anim":{"type":"pulse+spin","period_s":7}}`).
Without the key it is indistinguishable from random — the layer is invisible.

AEAD = **ChaCha20-Poly1305**, KDF = **HKDF-SHA3-512** (`info` =
`"eidolon.relic.layer.v1"`), `blob = nonce(12) || ciphertext||tag`. The Python
sealer (`cryptography`) and the PWA opener (`@noble/ciphers` + `@noble/hashes`)
are **interoperable, proven byte-for-byte** (a layer sealed in Python opens in
the browser — see §10).

---

## 4. The relic medium (durability)

The relic engraves `relic_secret` as an **EPX-R plate** (`encode_private`). Two
durability mechanisms compound:

1. **Materials** — engrave on metal / ceramic / stone (not paper) for physical
   longevity. (Out of software scope.)
2. **Code (ECC)** — EPX-R's blocked Reed–Solomon recovers the secret from the
   surviving cells after **erosion** (scratches, chips, weathered runes), up to
   the budget (`≤ d−1` erasures per block, ~`(d−1)/n ≈ ⅓` of the plate). A relic
   may lose a third of its surface to time and still decode.

So "survives epochs" = durable substrate **+** the ECC margin — not an immortal
engraving.

---

## 5. Reveal pipeline

```
find relic  ->  scan (EPX-R detect: ArUco -> homography -> rectify -> classify)
            ->  RS errors-and-erasures decode  ->  recover relic_secret
            ->  layer_key = HKDF(relic_secret, ...)
            ->  AEAD_open(sealed_layer)  ->  hidden_payload
            ->  RelicCanvas renders + animates the revealed surfaces
```

All steps are local. The reveal needs only the relic and the (public)
`blend_data`.

---

## 6. Security & threat model

- **Capacity ≠ security.** The relic is a key, not a vault. The hidden content
  is protected by the AEAD, not by obscurity.
- **One door per relic.** Each relic unlocks only **its** layer; compromise of
  one reveals nothing about others (independent `relic_secret`s).
- **Wrong / absent relic → no reveal.** AEAD authentication fails on a wrong
  key; the layer stays sealed.
- **First-finder-wins (EPX-V).** A huntable relic is claimed by whoever finds
  and scans it first; once **claimed/published it is "spent"** — the secret is
  then public, so the layer it gated is no longer secret. Design layers as
  **one-shot reveals**, not durable secrets.
- **No plaintext on the relic.** The relic carries the *secret/key*, never the
  hidden content itself; the content lives (encrypted) in `blend_data`.

---

## 7. IP placement (per `IP-BOUNDARY.md`)

- **Tier 0/1 (open):** the EPX-L *format* — sealed-layer container, key
  derivation, reveal pipeline, this spec.
- **Tier 2 (closed):** any binding of `relic_secret` or `layer_key` to the
  **EEP-001 / poly-spinor** pipeline, and any proprietary hologram geometry the
  hidden payload may carry — compiled-only.

---

## 8. blend_data shape (additive, backward-compatible)

```jsonc
{
  "public_layer":  { "layer": "metatron_cube", "vertices": 13, "edges": 78 },
  "sealed_layers": [ { "alg": "aead-v1", "voucher": "<commitment>", "ct": "<hex>" } ]
}
```

A reader without a relic renders only `public_layer`; `sealed_layers` are inert.
The shape is additive, so existing v4 `blend_data` stays valid.

---

## 9. Open items

- ✅ **Done** — reveal ported into the PWA: `pwa/src/lib/reveal.ts`
  (`openSealedLayer` / `tryReveal`) + `RelicCanvas` renders & animates the
  revealed surfaces (pulse/spin) when a scanned relic secret is supplied.
- ✅ **Done** — real AEAD (ChaCha20-Poly1305 + HKDF-SHA3-512), Python↔PWA
  interop proven (vitest, §10).
- ⏳ Anchor the **voucher commitment** on the real ledger / EPX-V flow.
- ⏳ Wire the **scan → relic secret** path in the PWA (EPX-R `detect` → secret →
  `RelicCanvas`); today the PoC supplies the secret directly.
- ⏳ Multi-relic layers (a layer requiring `k`-of-`n` relics — Shamir over the
  layer key).

---

## 10. PoC status — `scripts/epx_reveal_poc.py` (2026-06-09)

```
[seal]   blend_data: public=metatron_cube, sealed_layer=407 B (opaque -> invisible)
[guard]  without/with wrong relic: sealed (AEAD authentication failed)
[scan]   worn relic (23x23 plate, 76 cells eroded ~15%): secret RECOVERED via RS ECC
[reveal] hidden layer 'primordial_echo' unlocked: 12 surfaces, anim=pulse+spin @ 7s
[verdict] offline + deterministic + ECC-durable: scan=OK, reveal=OK, wrong-relic-blocked=OK
```

Validated: opaque-without-relic, wrong-relic-blocked, ECC survival of an eroded
relic, and a deterministic offline reveal. Before/after render:
`epx_reveal_demo.png`.

**Cross-language interop** (`pwa/src/lib/__tests__/reveal.test.ts`, vitest):
the browser (`@noble`) opens the **Python-sealed** layer **byte-exact** — same
HKDF-SHA3-512 layer key, ChaCha20-Poly1305 decrypt exact, wrong relic rejected.
**4/4 pass** (typecheck OK). Vector: `reveal_vector.json`.
