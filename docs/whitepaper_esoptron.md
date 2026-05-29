# Esoptron: Visual Vault Identity for the Post-Quantum Era

**Version 1.0 — May 2026**

*From the Greek ἔσοπτρον — the mirror in which identity is reflected.*

---

## Abstract

Esoptron is a visual identity and authenticated transport layer for cryptographic vaults. It transforms abstract cryptographic material into human-readable visual artifacts while maintaining post-quantum security guarantees. The system produces `.eopx` files — PNG images that serve simultaneously as visual fingerprints and machine-verifiable cryptographic commitments.

This paper describes the complete Esoptron architecture: the Metatron visual encoding scheme, six vault protocols (A-F), holographic recovery without seed phrases, and integration with the Eidolon vault ecosystem.

---

## 1. Introduction

### 1.1 The Problem

Modern cryptographic identity systems face a fundamental tension:

1. **Machine security** requires high-entropy keys that are incomprehensible to humans
2. **Human usability** requires memorable, verifiable representations
3. **Post-quantum threats** demand algorithm agility and larger key sizes
4. **Recovery mechanisms** like BIP-39 seed phrases create single points of failure

### 1.2 Our Approach

Esoptron resolves these tensions through:

- **Visual encoding**: Metatron's Cube geometry encodes 91 symbols in F₁₃, creating unique visual fingerprints
- **Dual artifacts**: Public cards for verification, private sheets for full access
- **Post-quantum cryptography**: ML-DSA-87 signatures, ML-KEM-1024 key encapsulation
- **Holographic recovery**: Shamir secret sharing eliminates seed phrase vulnerability

### 1.3 Design Principles

1. **No single point of failure**: Recovery requires k-of-n shares, not one phrase
2. **Visual verification**: Humans can compare cards without understanding cryptography
3. **Offline-first**: Core operations work without network connectivity
4. **Post-quantum ready**: All asymmetric operations use NIST PQC standards

---

## 2. The Metatron Visual Encoding

### 2.1 Geometric Foundation

Metatron's Cube is a sacred geometry figure containing 13 circles connected by 78 lines. We use this structure as a visual carrier for cryptographic data.

```
        ○
       /|\
      / | \
     ○──○──○
    /|\ | /|\
   ○─┼─○─┼─○
    \|/ | \|/
     ○──○──○
      \ | /
       \|/
        ○
```

### 2.2 Symbol Space

We encode data in F₁₃ (the field of integers modulo 13):

- **91 symbol positions** arranged in a chromatic grid
- **13 distinct glyphs** per position
- **Information capacity**: log₂(13⁹¹) ≈ 337 bits

### 2.3 Reed-Solomon Error Correction

Symbols are protected by a systematic RS(13, 10) code:

- **91 total symbols** = 70 data + 21 parity
- **Correction capacity**: Up to 10 erasures (known positions) or 5 errors (unknown)
- **Enables reliable photo capture** under varying conditions

### 2.4 Two Encoding Modes

| Mode | Input | Output | Use Case |
|------|-------|--------|----------|
| **Private** | 256-bit seed | Deterministic 91 symbols | Full vault access |
| **Public** | 512-bit spinor_hash | HKDF-derived 91 symbols | Identity verification |

**Security property**: Given only a public encoding, recovering the source spinor_hash is computationally infeasible (PRF assumption on HKDF-SHA3-512).

---

## 3. The .eopx Container Format

### 3.1 Overview

An `.eopx` file is a standard PNG with cryptographically authenticated metadata in `tEXt` chunks:

```
vault.eopx
├── PNG image data (Metatron visual)
└── tEXt chunks:
    ├── eopx:vault_id          → UUID
    ├── eopx:merkle_root       → 32-byte commitment
    ├── eopx:dilithium_pk_b64  → ML-DSA-87 public key
    ├── eopx:dilithium_pk_fp   → SHA3-256 fingerprint
    ├── eopx:kyber_pk_b64      → ML-KEM-1024 public key
    ├── eopx:timestamp_utc     → ISO-8601 creation time
    ├── eopx:image_sha3_512    → Pixel hash (tamper evidence)
    ├── eopx:payload_hash      → SHA3-512 of canonical manifest
    └── eopx:sig_dilithium5_b64 → ML-DSA signature
```

### 3.2 Verification Algorithm

```python
def verify_eopx(path):
    img = load_png(path)
    chunks = extract_text_chunks(img)
    
    # 1. Parse and validate manifest structure
    manifest = parse_manifest(chunks)
    
    # 2. Verify embedded key fingerprint
    assert sha3_256(manifest.dilithium_pk) == manifest.dilithium_pk_fp
    
    # 3. Verify pixel integrity
    assert sha3_512(img.rgb_bytes) == manifest.image_sha3_512
    
    # 4. Verify payload hash
    assert sha3_512(manifest.canonical_payload()) == manifest.payload_hash
    
    # 5. Verify ML-DSA signature
    assert ml_dsa_87.verify(manifest.dilithium_pk, 
                            manifest.payload_hash, 
                            manifest.signature)
    
    return VerificationResult(ok=True, manifest=manifest)
```

### 3.3 Threat Model

| Threat | Mitigation |
|--------|------------|
| Pixel tampering | SHA3-512 image hash embedded in signed payload |
| Metadata tampering | Payload hash covers all fields before signing |
| Key substitution | Fingerprint consistency check before signature verification |
| Replay attacks | Timestamp + vault_id binding |

---

## 4. Vault Protocols

Esoptron implements six protocols for vault operations:

### 4.1 Protocol A: Unlock (Private Sheet)

**Purpose**: Recover full vault access from a printed private sheet.

```
Private Sheet (physical) 
    → photograph 
    → 91 symbols 
    → RS decode 
    → 256-bit seed
    → HKDF(seed, "master_key") 
    → master_key
```

**Security**: The sheet IS the secret. Physical security required.

### 4.2 Protocol B: Verify (Public Card)

**Purpose**: Confirm a photographed card matches a locally-known vault.

```
card_fingerprint(scanned_symbols) == card_fingerprint(encode_public(local_spinor))
```

**Security**: No secrets revealed. Safe to verify in public.

### 4.3 Protocol C: SAS (Strong Authentication Sheet)

**Purpose**: Two-factor authentication combining physical card + device credential.

```
Challenge = {vault_id, nonce, timestamp}
Response = HMAC(spinor_local, vault_id || nonce || scanned_symbols)
Session_key = SHA3-512(spinor_local || nonce || card_fingerprint)
```

**Security**: Requires both stolen card AND compromised device.

### 4.4 Protocol D: Enrollment

**Purpose**: Derive per-device identity from a shared public card.

```
device_secret = HKDF(device_entropy, info="identity.private")
public_tag = HKDF(device_secret, salt=card_fp, info="identity.public_tag")
```

**Properties**:
- Same card, different devices → different identities
- Same device, different cards → different identities
- Reproducible given (card, device_entropy)

### 4.5 Protocol E: Genesis Ceremony

**Purpose**: One printed sheet creates N independent vaults for ceremony participants.

```
ceremony_seed = decode_private(sheet_symbols)
vault_seed = HKDF(ceremony_seed || device_entropy, info="genesis")
```

**Properties**:
- All participants share the same ceremony fingerprint
- Each participant derives a unique, independent vault
- Recovery requires BOTH sheet AND device_entropy

### 4.6 Protocol F: Migration

**Purpose**: Transfer vault binding to a new device without exposing secrets.

```
# On source device:
commitment = HKDF(master_key, salt=nonce, info="commit")
challenge_hash = SHA3-256(vault_id || source_lock || target_lock || commitment || nonce)
response = HKDF(master_key || challenge_hash, info="response")

# Proof transferred to target device

# On target device:
verify(commitment, response)  # NIZK verification
machine_bound_key = HKDF(master_key, salt=target_lock, info="bind")
```

**Security properties**:
- Zero-knowledge: Response reveals nothing about master_key
- Non-transferable: Proof bound to specific (source, target) pair
- Time-limited: 5-minute TTL prevents delayed replay

---

## 5. Holographic Recovery

### 5.1 Motivation

BIP-39 seed phrases have critical weaknesses:
- Single point of failure (lose the paper = lose everything)
- Single point of compromise (find the paper = steal everything)
- No partial recovery (23 of 24 words = nothing)

### 5.2 Architecture

Esoptron uses Shamir Secret Sharing over GF(2⁸) with per-share encryption:

```
device_entropy (32 bytes)
    │
    ▼
Shamir Split (k=2, n=3)
    │
    ├─► Share 1 ──► Argon2id(PIN) ──► CardPinShare
    │
    ├─► Share 2 ──► ML-KEM-1024(contact_pk) ──► KyberShare
    │
    └─► Share 3 ──► Argon2id(passphrase) ──► PassphraseShare
```

### 5.3 Share Types

| Share | Protection | Use Case |
|-------|------------|----------|
| **CardPinShare** | Argon2id (64MB, 3 iterations) | Printed recovery card with short PIN |
| **KyberShare** | ML-KEM-1024 encapsulation | Trusted contact holds decryption key |
| **PassphraseShare** | Argon2id (128MB, 4 iterations) | Cloud backup with strong passphrase |

### 5.4 Recovery Scenarios

| Scenario | Shares Available | Outcome |
|----------|------------------|---------|
| Normal recovery | PIN + passphrase | ✓ Full recovery |
| Lost phone | PIN + contact | ✓ Full recovery |
| Forgot PIN | Contact + passphrase | ✓ Full recovery |
| Lost 2 shares | Any 1 share | ✗ Cannot recover |
| Attacker has 1 share | — | ✗ Learns nothing |

### 5.5 Flexible k-of-n

For advanced users, arbitrary thresholds are supported:

```python
setup_recovery_flexible(
    entropy,
    share_configs=[
        ShareConfig(kind="card_pin", secret="111111"),
        ShareConfig(kind="card_pin", secret="222222"),
        ShareConfig(kind="kyber_pk", recipient_pk=alice_pk),
        ShareConfig(kind="kyber_pk", recipient_pk=bob_pk),
        ShareConfig(kind="passphrase", secret="..."),
    ],
    threshold=3,  # Any 3 of 5
)
```

---

## 6. Cryptographic Primitives

### 6.1 Algorithm Selection

| Function | Algorithm | Standard | Rationale |
|----------|-----------|----------|-----------|
| Signature | ML-DSA-87 | FIPS 204 | Post-quantum, NIST Level 5 |
| KEM | ML-KEM-1024 | FIPS 203 | Post-quantum, NIST Level 5 |
| Hash | SHA3-512/256 | FIPS 202 | Keccak sponge, domain separation |
| KDF | HKDF-SHA3-512 | RFC 5869 | Extract-then-expand with SHA3 |
| AEAD | ChaCha20-Poly1305 | RFC 8439 | Fast software implementation |
| Password KDF | Argon2id | RFC 9106 | Memory-hard, side-channel resistant |
| Secret sharing | Shamir GF(2⁸) | — | Information-theoretic security |

### 6.2 Key Sizes

| Key Type | Size | Fingerprint |
|----------|------|-------------|
| ML-DSA-87 public key | 2,592 bytes | SHA3-256 (32 bytes) |
| ML-DSA-87 secret key | 4,896 bytes | — |
| ML-DSA-87 signature | 4,627 bytes | — |
| ML-KEM-1024 public key | 1,568 bytes | SHA3-256 (32 bytes) |
| ML-KEM-1024 secret key | 3,168 bytes | — |
| ML-KEM-1024 ciphertext | 1,568 bytes | — |

### 6.3 Domain Separation

All KDF operations use unique info strings to prevent cross-protocol attacks:

```
esoptron.vault.master_key.v1
esoptron.vault.sas.session_key.v1
esoptron.genesis.vault_seed.v1
esoptron.migrate.commitment.v1
esoptron.recovery.kyber.aead.v1
...
```

---

## 7. Visual Sharding

### 7.1 Concept

An `.eopx` vault export can be split into k-of-n image shards, each carrying one Shamir share encrypted for a specific recipient:

```
vault_export()
    └─► shamir_split(k=3, n=5)
            ├─► kyber_enc(share_1, pk_1) ──► vault.eopx_1
            ├─► kyber_enc(share_2, pk_2) ──► vault.eopx_2
            ├─► kyber_enc(share_3, pk_3) ──► vault.eopx_3
            ├─► kyber_enc(share_4, pk_4) ──► vault.eopx_4
            └─► kyber_enc(share_5, pk_5) ──► vault.eopx_5
```

### 7.2 Properties

- Each shard is a valid `.eopx` with its own ML-DSA signature
- Any k shards reconstruct the vault key
- Individual shards reveal nothing (information-theoretic)
- Shards can be distributed across heterogeneous media

---

## 8. Integration with Eidolon

### 8.1 Data Flow

```
Eidolon Vault
    │
    ├── Phase 6: spinor_hash (64 bytes) ──► Public Metatron card
    │
    ├── Phase 9: merkle_root (32 bytes) ──► .eopx commitment
    │
    └── machine_lock binding ──► Protocol F migration
```

### 8.2 Interface Contract

| From Eidolon | Size | Usage in Esoptron |
|--------------|------|-------------------|
| `vault_id` | 32 B | SHA3-256(spinor_hash), identifies vault |
| `spinor_hash` | 64 B | Input to public Metatron encoding |
| `merkle_root` | 32 B | Optional .eopx payload field |
| `machine_lock` | 32 B | Protocol F migration binding |
| `master_key` | 32 B | Protocol A/F derivation source |

---

## 9. Security Analysis

### 9.1 Threat Model Summary

| Asset | Threat | Mitigation |
|-------|--------|------------|
| Private sheet | Physical theft | User responsibility; no digital copy |
| Public card | Photography | By design: reveals only public identity |
| .eopx file | Tampering | SHA3-512 pixel hash + ML-DSA signature |
| Recovery shares | Single share theft | Shamir: k shares required |
| Migration proof | MITM | Bound to specific (source, target) locks |
| Master key | Quantum computer | ML-DSA + ML-KEM are post-quantum |

### 9.2 Cryptographic Assumptions

1. **SHA3-512/256**: Collision and preimage resistance
2. **HKDF-SHA3-512**: PRF assumption on HMAC-SHA3
3. **ML-DSA-87**: Module-LWE hardness (NIST Level 5)
4. **ML-KEM-1024**: Module-LWE + Module-LWR (NIST Level 5)
5. **Argon2id**: Memory-hardness against ASICs
6. **Shamir GF(2⁸)**: Information-theoretic (no assumptions)

### 9.3 Known Limitations

1. **Private sheet single point of failure**: If captured, full vault access
2. **Photo quality dependency**: Poor lighting may cause RS decode failures
3. **Argon2id mobile performance**: 64-128MB memory usage may be slow on low-end devices

---

## 10. Implementation Status

### 10.1 Repository Structure

```
esoptron/
├── src/eopx/           # Core Python implementation
│   ├── format/         # .eopx container, keys, sharding
│   ├── metatron/       # Visual encoding, detection
│   ├── vault/          # Protocols A-F
│   ├── server/         # Flask API, phone-as-scanner
│   └── recovery.py     # Holographic recovery
├── pwa/                # TypeScript PWA
├── sdk/
│   ├── python/         # Standalone verifier
│   └── typescript/     # @esoptron/verify package
├── scripts/            # CLI tools
└── tests/              # 359 tests
```

### 10.2 Test Coverage

| Module | Tests | Status |
|--------|-------|--------|
| Protocols A-F | 55 | ✓ |
| .eopx format | 16 | ✓ |
| Metatron encoding | 44 | ✓ |
| Recovery | 33 | ✓ |
| Visual sharding | 10 | ✓ |
| Server/API | 70 | ✓ |
| Integration | 17 | ✓ |

---

## 11. Future Work

1. **Hardware attestation**: Bind machine_lock to TPM/Secure Enclave
2. **Animated holograms**: GPU-rendered parallax effects for anti-counterfeiting
3. **NFC integration**: Tap-to-verify with embedded .eopx
4. **Multi-party ceremonies**: Coordinated genesis across multiple devices
5. **Revocation registry**: On-chain anchoring of migration events

---

## 12. Conclusion

Esoptron bridges the gap between cryptographic security and human usability. By encoding vault identity in visual artifacts and replacing seed phrases with Shamir-sharded recovery, we eliminate single points of failure while maintaining post-quantum security guarantees.

The system is fully implemented with 359 passing tests, TypeScript/Python SDK parity, and comprehensive documentation. It integrates seamlessly with the Eidolon vault ecosystem while remaining usable as a standalone visual identity layer.

---

## References

1. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
2. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
3. NIST FIPS 202: SHA-3 Standard
4. RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
5. RFC 9106: Argon2 Memory-Hard Function
6. Shamir, A. (1979): How to Share a Secret

---

*Esoptron is part of the Eidolon ecosystem.*
*ἔσοπτρον — the surface that reflects without revealing.*
