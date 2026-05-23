<div align="center">

```

```

**Visual Vault Identity · Authenticated Transport · Post-Quantum Sharding**

[![Status](https://img.shields.io/badge/status-pre--release-blueviolet?style=flat-square)](.)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](.)
[![Rust](https://img.shields.io/badge/rust-nightly-orange?style=flat-square)](.)
[![Crypto](https://img.shields.io/badge/PQ-Kyber1024%20%2B%20Dilithium5-teal?style=flat-square)](.)
[![License](https://img.shields.io/badge/license-proprietary-red?style=flat-square)](LICENSE)
[![Linked](https://img.shields.io/badge/linked-Eidolon-9b59b6?style=flat-square)](.)

*From the Greek **ἔσοπτρον** — the mirror in which identity is reflected.*

</div>

---

## What is Esoptron?

Esoptron is the visual identity and authenticated transport layer for [Eidolon](https://github.com/oykdo/eidolon) vaults.

It produces **`.eopx` files** — PNG artefacts that are simultaneously a human-readable visual fingerprint of a vault and a machine-verifiable cryptographic commitment. An `.eopx` can be shared publicly, printed as a QR code, embedded on a NFC tag, stored on IPFS — all without exposing a single secret from the underlying vault.

Think of it as a passport for your vault: visually distinct, cryptographically signed, and verifiable offline by anyone who holds the corresponding public key.

```
vault.psnx  +  vault.blend_data  ──▶  eopx_format  ──▶  vault.eopx
  (public)       (private)               │
                                         ├── 512×512 deterministic visual
                                         ├── HMAC-authenticated metadata chunks
                                         └── ML-DSA (Dilithium5) signature
```

---

## Core Concepts

### The `.eopx` artefact

A standard PNG file carrying cryptographically authenticated metadata in its `tEXt` chunks:

| Chunk | Content |
|---|---|
| `eopx:vault_id` | UUID of the originating vault |
| `eopx:merkle_root` | Merkle root of vault genesis data (Phase 9) |
| `eopx:kyber_pk_fp` | SHA3-256 fingerprint of the Kyber1024 public key |
| `eopx:timestamp_utc` | ISO-8601 generation timestamp |
| `eopx:payload_hash` | SHA3-512 of the full payload (tamper evidence) |
| `eopx:sig_dilithium5` | ML-DSA signature over `payload_hash` |

The visual layer is **deterministic**: the same vault always produces the same image. Two distinct vaults are visually distinguishable at a glance. The image is derived from the `spinor_hash` output of Eidolon's Phase 6 holographic key derivation — no random seeding, no external entropy.

### Shamir Visual Sharding *(Phase 2)*

An `.eopx` vault export can be split into `k/n` image shards, each carrying one Shamir share encrypted with the recipient's Kyber1024 public key:

```
vault_export()
    └─▶ shamir_split(k=3, n=5)
            ├─▶ kyber_enc(share_1, pk_1)  ──▶  vault.eopx_1
            ├─▶ kyber_enc(share_2, pk_2)  ──▶  vault.eopx_2
            ├─▶ kyber_enc(share_3, pk_3)  ──▶  vault.eopx_3
            ├─▶ kyber_enc(share_4, pk_4)  ──▶  vault.eopx_4
            └─▶ kyber_enc(share_5, pk_5)  ──▶  vault.eopx_5
```

Any 3 shards reconstruct the vault key. Each shard is independently verifiable with its own Dilithium5 signature. Shards can be distributed across heterogeneous media: local disk, IPFS/Arweave, printed QR, NFC tag, encrypted cloud storage.

### Cross-machine Migration *(Phase 3)*

Eidolon vaults are bound to a specific machine via `machine_lock`. Esoptron provides a `vault_migrate` flow that re-binds a vault to a new machine through a NIZK Schnorr proof (leveraging Eidolon Connect) without ever transmitting the vault key.

---

## Architecture

```
esoptron/
├── src/
│   └── eopx/
│       ├── __init__.py          # Public API surface
│       ├── eopx_format.py       # Build .eopx from spinor_hash + vault metadata
│       ├── eopx_verify.py       # Offline signature + integrity verification
│       ├── visual_sharding.py   # Shamir k/n image sharding (Phase 2)
│       └── vault_migrate.py     # Cross-machine re-bind flow (Phase 3)
├── sdk/
│   └── python/
│       └── esoptron/
│           └── eopx_verify.py   # Lightweight verifier — no Eidolon required
├── tests/
│   ├── test_eopx_format.py
│   ├── test_eopx_verify.py
│   └── vectors/
│       └── eopx/                # Reference PNG + expected hashes
└── CLAUDE.md
```

Esoptron delegates all cryptographic primitives to `eidolon_crypto`, the Rust native crate that also powers Eidolon core. There are no Python re-implementations of crypto — every hash, signature, and key operation calls into the same signed wheel.

---

## Cryptographic Stack

| Primitive | Algorithm | Purpose |
|---|---|---|
| Asymmetric signature | ML-DSA / Dilithium5 | `.eopx` payload signing |
| KEM | Kyber1024 | Shard encryption per recipient |
| Hash | SHA3-512 | Payload integrity (`payload_hash`) |
| Hash | SHA3-256 | Public key fingerprinting |
| Secret sharing | Shamir GF(2^8) | k/n vault key sharding |
| ZKP | NIZK Schnorr | Machine-lock migration proof |

All algorithms are **post-quantum**. Esoptron does not use RSA, ECDSA, or any pre-quantum asymmetric primitive.

---

## Dependency on Eidolon

Esoptron is a **linked monorepo** — it does not vendor or re-implement Eidolon internals.

| Dependency | What Esoptron uses |
|---|---|
| `eidolon_crypto` wheel | All cryptographic primitives (Rust, signed binary) |
| Phase 6 output | `spinor_hash: bytes` — input to visual renderer |
| Phase 9 output | `merkle_root: bytes` — embedded in `.eopx` payload |
| `secret_sharing.py` | `shamir_split` / `shamir_reconstruct` |
| `zkp_auth.py` | Schnorr proof generation for migration |
| `config/paths.py` | `get_vault_dir()` — no hardcoded paths |

The `sdk/python/esoptron/eopx_verify.py` module is the **only part of Esoptron that can run without a full Eidolon installation**, provided `eidolon_crypto` is installed separately.

---

## Relationship to Cipher

Esoptron follows the same monorepo architecture as **Cipher**, the Eidolon messaging layer:

```
eidolon/          ← vault core, key derivation, machine identity
  └── cipher/     ← encrypted messaging, linked monorepo
  └── esoptron/   ← visual vault identity, linked monorepo
```

Like Cipher, Esoptron ships its public SDK surface independently while keeping all privileged operations behind the `eidolon_crypto` boundary. SDK consumers verify `.eopx` artefacts; they never touch vault keys.

---

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| **P1** | `.eopx` format — `eopx_format.py` + `eopx_verify.py` | 🔵 In spec |
| **P2** | Shamir Visual Sharding — `visual_sharding.py` | ⬜ Planned |
| **P3** | Cross-machine migration — `vault_migrate.py` | ⬜ Planned |
| **P4** | SDK PyPI release — `pip install esoptron` | ⬜ Planned |

---

## Requirements

- Python 3.11+
- `eidolon_crypto` wheel (Rust native, distributed with Eidolon releases)
- Pillow ≥ 10.0
- Eidolon ≥ v1.2.0

---

## Development

```bash
# Clone alongside Eidolon
git clone https://github.com/oykdo/Esoptron
cd esoptron

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Verify against reference vectors
python -m pytest tests/test_eopx_verify.py::test_reference_vectors -v
```

The Rust native extension must be installed before running any test that touches crypto:

```bash
# From the Eidolon repo
make build-rust-wheel
pip install dist/eidolon_crypto-*.whl
```

---

## Security Model

**What `.eopx` reveals:** vault UUID, Merkle root, Kyber public key fingerprint, creation timestamp. All public material — equivalent to what is already in `.psnx`.

**What `.eopx` does not reveal:** vault key, private key material, `machine_lock` identity, temporal context, any data from `.blend_data`.

**Threat model:** an attacker in possession of a valid `.eopx` learns nothing beyond the vault's public identity. An attacker who modifies any chunk breaks the `payload_hash` check before the signature check is even reached. A forged `.eopx` without the Dilithium5 private key fails `eopx_verify` unconditionally.

**Shard threat model:** individual shards are ciphertext under Kyber1024. An attacker with fewer than `k` shards learns nothing about the vault key. An attacker with exactly `k` shards but without the corresponding Kyber private keys learns nothing.

---

## License

Proprietary — see [LICENSE](LICENSE). The `sdk/python/esoptron/eopx_verify.py` module may be distributed under separate terms for third-party integrators; see [SDK_LICENSE](SDK_LICENSE).

---

<div align="center">

*Esoptron is part of the Eidolon ecosystem.*
*ἔσοπτρον — the surface that reflects without revealing.*

</div>
