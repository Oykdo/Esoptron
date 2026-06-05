<div align="center">

# Esoptron

**Visual Vault Identity · Post-Quantum Cryptography · Holographic Recovery**

[![Tests](https://img.shields.io/badge/tests-766%20(758%20passing)-brightgreen?style=flat-square)](.)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](.)
[![TypeScript](https://img.shields.io/badge/typescript-5.0%2B-blue?style=flat-square)](.)
[![PQ Crypto](https://img.shields.io/badge/PQ-ML--DSA--87%20%2B%20ML--KEM--1024-teal?style=flat-square)](.)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

*From the Greek **ἔσοπτρον** — the mirror in which identity is reflected.*

[Whitepaper](docs/whitepaper_esoptron.md) · [Specs](docs/specs/) · [Quick demo](#quick-demo)

</div>

---

## What is Esoptron?

Esoptron turns a cryptographic **vault identity** into a **Metatron's Cube** image
(91 symbols over the field 𝔽₁₃) and wraps it in a `.eopx` container — an ordinary
PNG whose `tEXt` chunks carry a self-contained, **ML-DSA-87-signed** manifest. A
photo of that image, run through the scan pipeline, drives a vault protocol
(unlock, verify, enroll, migrate, reclaim…). The SDK verifier is **standalone** —
no Eidolon install is needed to verify a `.eopx`, online or off.

**Think of it as a passport for your vault**: visually distinct, post-quantum
signed, and verifiable offline.

```
┌──────────────────────────────────────────────────────────────────┐
│  Eidolon vault  ──►  Esoptron  ──►  .eopx badge  ──►  scan / verify │
│  (.psnx + .blend)    (encode)       (shareable PNG)   (any device)  │
└──────────────────────────────────────────────────────────────────┘
```

> **Live:** the public anchor and the phone-as-scanner PWA run at
> [`eidolon-connect.xyz/anchor`](https://eidolon-connect.xyz/anchor) and
> [`eidolon-connect.xyz/pwa`](https://eidolon-connect.xyz/pwa).

---

## Highlights

### 🎨 Visual identity
- 91-symbol Metatron's Cube over 𝔽₁₃, with Reed–Solomon error correction.
- A **Theorem-2 algebraic test** distinguishes a *private inscription* from a
  *public card* — purely from the symbols, no metadata.
- Photo → canonical cube → 91 symbols via ArUco fiducials + local rectification.

### 🔐 Seven vault protocols (A–G)
`unlock` · `verify` · `SAS` challenge/response 2FA · `enroll` · `genesis`
(one ceremony sheet → N independent vaults via per-device entropy) · `migrate`
(NIZK proof of ownership bound to specific devices) · `reclaim` (re-derive an
enrollment on a new device from the public card + a BIP-39 phrase or a shard
quorum). A single entry point — `scan_and_route(image, ScanContext(intent=…))` —
dispatches a photo to the right protocol and **never raises**.

### 🛡️ Post-quantum security
ML-DSA-87 (Dilithium5) signatures · ML-KEM-1024 (Kyber) KEM · SHA3-512/256 ·
HKDF-SHA3-512 · ChaCha20-Poly1305 · Argon2id. Post-quantum **and**
offline-verifiable by design.

### 🔄 Holographic recovery
No 24-word seed phrase. A vault's recovery secret is split with Shamir into
**k-of-n shares** (default 2-of-3) bound to distinct factors (card, PIN,
passphrase, Kyber key). Lose one — recover with the rest; steal one — useless
alone.

### 🪙 Collection & ceremony layers
- **EPX-T** titled transfer — an artifact ledger (the *anchor*) with
  compare-and-swap, signed receipts, optional PostgreSQL backend.
- **EPX-C** the **Codex** — twelve titled relics, deterministically distributed
  from a committed Bitcoin block; possession verified against the anchor.
- **EPX-E** the 555 **Golden Eggs** — a per-vault collectible, fair founder draw.
- **EPX-K** **Keys of Office** — each relic confers one verifiable capability.
- **EPX-V** voucher claim · **EPX-H** the hexagram seal (brand, not security).

Every deterministic distribution is frozen by a single **committed Genesis
block** (`docs/GENESIS_COMMITMENT.md`), baked into the code as the default.

---

## Quick demo

```bash
# Python 3.11+
py -m pip install -e ".[dev,server,scanner]"

# The mandatory sanity check — pure-math encode→render→detect→decode loopback:
py scripts/loopback_canonical.py

# Full ecosystem walkthrough (no hardware):
py scripts/demo_ecosystem.py

# Tests
py -m pytest tests/ -v
```

---

## Architecture

Three parallel implementations of the same crypto, kept in **parity**: the
canonical Python `eopx` package, a TypeScript **PWA**, and a TypeScript/Python
**SDK** verifier. Crypto-touching changes update all ports and add parity tests.

```
src/eopx/
├── metatron/   visual encoding — 𝔽₁₃ field, Reed–Solomon, render, scan/detect,
│               seal reveal (EPX-H), the chromatic grid
├── format/     the .eopx container — pack/verify, EopxKey (Dilithium5+Kyber1024),
│               Shamir + visual sharding, RAM-wiped secrets
├── vault/      protocols A–G, each consuming a 91-symbol vector
├── transfer/   EPX-T titled transfer + §8 controller binding
├── collection/ the Codex relics (EPX-C) + ASCII sigil/figure brand assets
├── server/     Flask anchor + phone-as-scanner API, PostgreSQL ledger
├── flows.py    scan_and_route(...) — the single, never-raising entry point
└── genesis_token / egg_token / capabilities / recovery
```

### The `.eopx` wire format

Ordered `tEXt` chunks carry the signed manifest: `format_version`, `vault_id`,
`merkle_root`, `kyber_pk_fp`, `dilithium_pk_b64`, `dilithium_pk_fp`,
`timestamp_utc`, `image_sha3_512`, `payload_hash`, `sig_dilithium5_b64`.
`image_sha3_512` is computed over the **decoded RGB pixels**, so re-encoding the
PNG at a different compression level does *not* break the signature — only a
pixel change does.

---

## CLI tools

```bash
py scripts/eopx_keygen.py --out key.json          # ML-DSA + ML-KEM keypair
py scripts/eopx_pack.py img.png out.eopx key.json # sign an image into .eopx
py scripts/eopx_verify.py out.eopx                # verify (offline, standalone)
py scripts/eopx_shard.py vault.json --k 3 --n 5   # k-of-n visual shards
py scripts/show_relic_sigils.py                   # the 12 Codex relic figures
```

The TypeScript SDK and PWA live under `sdk/typescript/` and `pwa/`:

```bash
cd sdk/typescript && npm install && npm run build && npm test
cd pwa            && npm install && npm test && npm run build
```

---

## Security model

| Threat | Mitigation |
|---|---|
| Quantum adversary | ML-DSA-87 signatures, ML-KEM-1024 KEM — NIST PQC level 5 |
| Forged card | Reed–Solomon membership (Theorem 2) + Dilithium signature + registry |
| Tampered badge | `image_sha3_512` over decoded pixels; any pixel change fails verify |
| Single point of failure | Holographic k-of-n recovery (no lone seed phrase) |
| Stolen device | Controllers sealed to a device secret (§8); migration needs a NIZK proof |
| Offline verification | Standalone SDK — Pillow + pqcrypto only, no network, no Eidolon |

The hexagram **seal (EPX-H) is brand, not security**: it contributes ≈2 bits and
is verified by *re-rendering*, never by measuring the photo. All real trust comes
from the 91 symbols → signature → registry → ML-DSA layer.

---

## Integration with Eidolon

Esoptron is the **visual layer** of the Eidolon vault ecosystem. The canonical
root of trust is the **Eidolon vault** (`.psnx` + `.blend_data` key files);
Esoptron turns that identity into a scannable, signed badge and gives it a
collection, an anchor, and a recovery story. The PWA is a **viewer/verifier**;
its standalone enrollment serves people who do not yet run Eidolon.

---

## Documentation

- **Whitepapers** — `docs/whitepaper_esoptron.md`, `whitepaper_vault_protocols.md`,
  `migration_protocol.md`, `whitepaper_metatron*.md`
- **Protocol/format specs** — `docs/specs/EPX-*.md` (`EPX-2`, `EPX-C`, `EPX-E`,
  `EPX-H`, `EPX-K`, `EPX-T`, `EPX-V`)
- **Genesis commitment** — `docs/GENESIS_COMMITMENT.md`

Specs are hash-tracked in `SPECS.SHA3-256` and verified in CI
(`py tools/verify_spec.py --all`).

---

## Contributing

```bash
py -m pytest tests/ -v                       # tests
py scripts/loopback_canonical.py             # bit-exact round-trip (the contract)
py -m ruff check src tests && py -m black src/ && py -m mypy src/
python tools/check_encoding.py               # UTF-8 + LF gate
```

Crypto-touching changes must update the Python, TypeScript SDK, and PWA ports
together and add parity tests. See `CONTRIBUTING.md`.

---

## License

[MIT](LICENSE) © Esoptron contributors.

<div align="center">

**ἔσοπτρον — the surface that reflects without revealing.**

</div>
