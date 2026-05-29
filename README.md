<div align="center">

# Esoptron

**Visual Vault Identity | Post-Quantum Cryptography | Holographic Recovery**

[![Tests](https://img.shields.io/badge/tests-373%20passing-brightgreen?style=flat-square)](.)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](.)
[![TypeScript](https://img.shields.io/badge/typescript-5.0%2B-blue?style=flat-square)](.)
[![PQ Crypto](https://img.shields.io/badge/PQ-ML--DSA--87%20%2B%20ML--KEM--1024-teal?style=flat-square)](.)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

*From the Greek **ἔσοπτρον** — the mirror in which identity is reflected.*

[Whitepaper](docs/whitepaper_esoptron.md) · [Demo](#quick-demo) · [Documentation](#documentation)

</div>

---

## What is Esoptron?

Esoptron transforms cryptographic vault identities into **visual artifacts** that are both human-verifiable and machine-authenticated. It produces `.eopx` files — PNG images that serve as visual fingerprints with embedded post-quantum signatures.

**Think of it as a passport for your vault**: visually distinct, cryptographically signed, and verifiable offline.

```
┌─────────────────────────────────────────────────────────────┐
│  Eidolon Vault  ────►  Esoptron  ────►  .eopx Visual ID    │
│  (keys, secrets)       (encode)         (shareable PNG)     │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Features

### 🎨 Visual Identity
- **Metatron's Cube** geometry encodes 91 symbols (F₁₃)
- **Public cards**: Shareable identity, anyone can verify
- **Private sheets**: Full vault access, physical security required

### 🔐 Six Vault Protocols

| Protocol | Purpose |
|----------|---------|
| **A. Unlock** | Photo of private sheet → full vault access |
| **B. Verify** | Photo of public card → identity attestation |
| **C. SAS** | Card + device = two-factor authentication |
| **D. Enroll** | Public card + phone = unique per-device identity |
| **E. Genesis** | One ceremony sheet → N independent vaults |
| **F. Migrate** | Move to new device without exposing secrets |

### 🛡️ Post-Quantum Security
- **ML-DSA-87** (Dilithium5) for signatures
- **ML-KEM-1024** (Kyber) for key encapsulation
- **SHA3-512/256** for hashing
- **Argon2id** for password derivation

### 🔄 Holographic Recovery
No more 24-word seed phrases. Your vault is split into **k-of-n shares**:

```
┌─────────────────────────────────────────────────────┐
│  2-of-3 Recovery (default)                          │
│                                                     │
│  Share 1: Card PIN (Argon2id)      ─┐              │
│  Share 2: Contact Kyber key        ─┼─► Any 2 = OK │
│  Share 3: Cloud passphrase         ─┘              │
│                                                     │
│  ✓ Lose 1 share = still recoverable                │
│  ✓ Steal 1 share = learn nothing                   │
└─────────────────────────────────────────────────────┘
```

---

## Quick Demo

```bash
# Clone the repository
git clone https://github.com/oykdo/esoptron
cd esoptron

# Install dependencies
pip install -e ".[dev]"

# Run the ecosystem demo (no hardware needed)
python scripts/demo_ecosystem.py

# Run all tests
python -m pytest tests/ -v
```

<details>
<summary>📺 Demo output</summary>

```
============================================================
  ESOPTRON ECOSYSTEM DEMO
============================================================

PROTOCOL A: Private Sheet Unlock
1. Seed secrète (32 bytes): e562d2b02456c189...
2. Encodé en 91 symboles Metatron
3. Seed récupérée: e562d2b02456c189...
4. Master key dérivée: b7897f874ff43976...
✓ Protocol A OK

PROTOCOL F: Cross-Machine Migration
1. Vault sur machine source
2. Nouvelle machine affiche son lock (QR)
3. Source génère preuve NIZK
4. Target vérifie et migre: ✓ OK
5. Avec mauvaise machine: ✗ REJETÉ
✓ Protocol F OK

RECOVERY: Holographic 2-of-3
1. Package créé: 2-of-3
2. Récupération PIN + passphrase: ✓
3. Récupération Kyber + passphrase: ✓
✓ Recovery OK
```

</details>

---

## Installation

### Python (Core + CLI)

```bash
pip install -e ".[dev]"
```

Requirements:
- Python 3.11+
- `pqcrypto` (post-quantum primitives)
- `Pillow` (image processing)
- `opencv-contrib-python` (ArUco detection)

### PWA (Web Interface)

```bash
cd pwa
npm install
npm run dev

# In another terminal, start the API server:
python scripts/serve_pwa_api.py --cors http://localhost:5173
```

### TypeScript SDK (Verifier)

```bash
npm install @esoptron/verify
```

```typescript
import { verifyChunksOnly, readManifest } from '@esoptron/verify';

const result = verifyChunksOnly(eopxBuffer);
if (result.ok) {
  console.log('Valid .eopx from vault:', result.manifest.vaultId);
}
```

---

## CLI Tools

### Key Generation

```bash
# Generate ML-DSA + ML-KEM keypair
python scripts/eopx_keygen.py --out keys/default.json
```

### Pack & Verify .eopx

```bash
# Create signed .eopx from image
python scripts/eopx_pack.py \
  --image metatron.png \
  --key keys/default.json \
  --out vault.eopx

# Verify .eopx integrity
python scripts/eopx_verify.py vault.eopx
```

### Migration

```bash
# On NEW device: display machine lock as QR
python scripts/vault_migrate.py show-lock --machine-lock <hex> --qr

# On OLD device: generate proof
python scripts/vault_migrate.py prove \
  --master-key <hex> --vault-id <hex> \
  --source-lock <hex> --target-lock <hex> \
  --out proof.json

# On NEW device: verify and bind
python scripts/vault_migrate.py verify \
  --proof proof.json --master-key <hex> --machine-lock <hex>
```

### Visual Sharding

```bash
# Split vault into 3-of-5 encrypted shards
python scripts/eopx_shard.py \
  --input vault.eopx \
  --recipients r1.pub.json r2.pub.json r3.pub.json r4.pub.json r5.pub.json \
  --threshold 3 \
  --out-dir shards/

# Reconstruct from any 3 shards
python scripts/eopx_reconstruct.py \
  --shards shards/vault_1.eopx shards/vault_3.eopx shards/vault_5.eopx \
  --keys r1.json r3.json r5.json \
  --out recovered.secret
```

---

## Architecture

```
esoptron/
├── src/eopx/
│   ├── format/           # .eopx container, keys, Shamir, sharding
│   ├── metatron/         # Visual encoding (F₁₃, Reed-Solomon, ArUco)
│   ├── vault/            # Protocols A-F
│   │   ├── unlock.py     # Protocol A
│   │   ├── verify_card.py# Protocol B
│   │   ├── sas.py        # Protocol C
│   │   ├── enroll.py     # Protocol D
│   │   ├── genesis.py    # Protocol E
│   │   └── migrate.py    # Protocol F
│   ├── server/           # Flask API, phone-as-scanner
│   └── recovery.py       # Holographic recovery (2-of-3, k-of-n)
│
├── pwa/                  # TypeScript PWA
│   └── src/lib/          # Crypto, enrollment, recovery (Python parity)
│
├── sdk/
│   ├── python/esoptron/  # Standalone verifier
│   └── typescript/       # @esoptron/verify npm package
│
├── scripts/              # CLI tools
│   ├── demo_ecosystem.py # Full demo
│   ├── eopx_*.py         # .eopx operations
│   └── vault_migrate.py  # Protocol F CLI
│
├── tests/                # 359 tests
└── docs/
    ├── whitepaper_esoptron.md      # Full technical paper
    ├── whitepaper_vault_protocols.md
    └── migration_protocol.md
```

---

## The .eopx Format

A `.eopx` file is a PNG with signed metadata:

| Chunk | Content |
|-------|---------|
| `eopx:vault_id` | UUID of the vault |
| `eopx:dilithium_pk_b64` | ML-DSA-87 public key |
| `eopx:dilithium_pk_fp` | SHA3-256 fingerprint |
| `eopx:kyber_pk_fp` | ML-KEM-1024 fingerprint |
| `eopx:timestamp_utc` | Creation time |
| `eopx:image_sha3_512` | Pixel hash (tamper evidence) |
| `eopx:payload_hash` | SHA3-512 of manifest |
| `eopx:sig_dilithium5_b64` | ML-DSA signature |

**What .eopx reveals**: vault UUID, public keys, timestamp (all public).
**What .eopx protects**: pixel integrity, metadata authenticity, signer identity.

---

## Security Model

### Cryptographic Stack

| Primitive | Algorithm | NIST Level |
|-----------|-----------|------------|
| Signature | ML-DSA-87 (Dilithium5) | Level 5 |
| KEM | ML-KEM-1024 (Kyber) | Level 5 |
| Hash | SHA3-512/256 | — |
| KDF | HKDF-SHA3-512 | — |
| AEAD | ChaCha20-Poly1305 | — |
| Password | Argon2id (64-128 MB) | — |

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Quantum computer | ML-DSA + ML-KEM (post-quantum) |
| Pixel tampering | SHA3-512 image hash in signed payload |
| Single share theft | Shamir: k shares required |
| Migration MITM | NIZK proof bound to specific devices |
| Seed phrase theft | No seed phrase (holographic recovery) |

---

## Documentation

- **[Whitepaper](docs/whitepaper_esoptron.md)**: Complete technical specification
- **[Vault Protocols](docs/whitepaper_vault_protocols.md)**: Protocols A-F in detail
- **[Migration Protocol](docs/migration_protocol.md)**: Protocol F deep dive
- **[Testing Guide](docs/testing_guide.md)**: How to run and write tests

---

## Integration with Eidolon

Esoptron is designed to work with [Eidolon](https://github.com/oykdo/eidolon) vaults:

```
Eidolon                          Esoptron
───────                          ────────
Phase 6: spinor_hash (64B) ────► Public Metatron card
Phase 9: merkle_root (32B) ────► .eopx commitment
machine_lock binding       ────► Protocol F migration
```

The SDK verifier works standalone — no Eidolon installation required.

---

## Contributing

```bash
# Run tests
python -m pytest tests/ -v

# Type check
python -m mypy src/

# Format
python -m black src/ tests/
```

---

## License

Proprietary — see [LICENSE](LICENSE).

The `sdk/` modules may be distributed under separate terms for third-party integrators.

---

## Environment variables

Operational knobs (see `SECURITY.md` for the production hardening checklist):

| Variable | Default | Purpose |
|---|---|---|
| `ESOPTRON_LOCK_SERVER_URL` | `https://lock.eidolon-connect.xyz` | Eidolon Lock Server endpoint (required when `ESOPTRON_ANCHOR_BACKEND=http`). |
| `ESOPTRON_ANCHOR_BACKEND` | `sqlite` | `sqlite` for standalone mode, `http` to delegate sequence assignment to the lock server. |
| `ESOPTRON_LOCK_API_SECRET` | _(unset)_ | HMAC shared secret for the lock server signed endpoints. |
| `ESOPTRON_LOCK_TIMEOUT` | `5.0` | Lock-server HTTP timeout, in seconds. |
| `ESOPTRON_BTC_BLOCK_HASH` | _(required)_ | Anchor bootstrap: BTC block hash hex. |
| `ESOPTRON_BTC_BLOCK_HEIGHT` | _(required)_ | Anchor bootstrap: BTC block height. |
| `ESOPTRON_ALLOW_DEV_DEFAULTS` | _(unset)_ | Allow zero-block fallback when BTC env vars are missing. **NEVER set in production.** |
| `ESOPTRON_ENABLE_LEGACY_MOBILE_HTML` | _(unset)_ | Re-enable the deprecated `/scan` HTML flow on the live-scan demo. **Dev only.** |
| `ESOPTRON_DEBUG_DUMP_FRAMES` | _(unset)_ | Persist uploaded frames to disk. **Never in production.** |
| `ESOPTRON_RATE_LIMIT_DISABLE` | _(unset)_ | Disable the in-process token-bucket rate limiter (used by the test suite). |
| `ESOPTRON_RATE_LIMIT_DEFAULT` | `60/min` | Default rate-limit budget per client. |
| `ESOPTRON_RATE_LIMIT_HEAVY` | `10/min` | Budget for heavy endpoints (`/api/frame`). |
| `ESOPTRON_RATE_LIMIT_ANCHOR` | `30/min` | Budget for anchor endpoints. |
| `ESOPTRON_ARGON2_PROFILE` | `workstation` | `workstation` or `mobile`; recovery package embeds and replays the profile. |
| `ESOPTRON_CORS_ALLOWED_ORIGINS` | _(unset)_ | Explicit CORS allow-list (rejected if it contains `*`). |

> **Note on the default lock server**: `lock.eidolon-connect.xyz` is the
> reference deployment operated by the Eidolon team. Self-hosters MUST
> override `ESOPTRON_LOCK_SERVER_URL` and run their own coordinator if
> they want full sovereignty over the global `vault_number` ordering.

---

<div align="center">

*Esoptron is part of the Eidolon ecosystem.*

**ἔσοπτρον — the surface that reflects without revealing.**

</div>
