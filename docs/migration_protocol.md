# Protocol F: Cross-Machine Vault Migration

**Status**: Implemented in `src/eopx/vault/migrate.py`
**CLI**: `scripts/vault_migrate.py`
**Tests**: `tests/test_vault_migrate.py`

## Overview

When an Eidolon vault is bound to a specific machine via `machine_lock`, migrating to a new device requires proving possession of the vault secret **without transmitting it**. Protocol F uses a Fiat-Shamir transformed commitment scheme to achieve this.

## Security Properties

| Property | Description |
|----------|-------------|
| **Zero-knowledge** | The proof reveals nothing about `master_key` beyond the fact that the prover knows it |
| **Non-transferability** | Proof is bound to specific `(source, target)` machine locks; replay fails |
| **Time-limited** | TTL of 5 minutes prevents delayed replay attacks |
| **Constant-time** | All comparisons use `hmac.compare_digest` to prevent timing attacks |

## Protocol Flow

```
┌─────────────────┐                              ┌─────────────────┐
│  SOURCE DEVICE  │                              │  TARGET DEVICE  │
│  (has master_key)│                             │  (new device)   │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  1. Target displays machine_lock as QR         │
         │ <───────────────────────────────────────────── │
         │                                                │
         │  2. Source scans QR, gets target_lock          │
         │                                                │
         │  3. Source computes:                           │
         │     challenge = (vault_id, source_lock,        │
         │                  target_lock, nonce, timestamp)│
         │     commitment = HKDF(master_key, salt=nonce,  │
         │                       info="commit")           │
         │     ch = SHA3-256(vault_id || source ||        │
         │                   target || commitment || nonce)│
         │     response = HKDF(master_key || ch,          │
         │                     salt=nonce, info="response")│
         │                                                │
         │  4. Source sends MigrationProof                │
         │ ──────────────────────────────────────────────>│
         │                                                │
         │                      5. Target verifies:       │
         │                         - target_lock matches  │
         │                         - TTL not expired      │
         │                         - recompute commitment │
         │                         - recompute response   │
         │                                                │
         │                      6. Target derives:        │
         │                         machine_bound_key =    │
         │                           HKDF(master_key,     │
         │                                salt=target_lock,│
         │                                info="bind")    │
         │                                                │
         └────────────────────────────────────────────────┘
```

## Data Structures

### MigrationChallenge

Created on source device to initiate migration.

```python
@dataclass
class MigrationChallenge:
    vault_id: bytes      # 32 B - identifies the vault
    source_lock: bytes   # 32 B - current machine fingerprint
    target_lock: bytes   # 32 B - new device fingerprint
    nonce: bytes         # 32 B - fresh randomness
    timestamp: float     # Unix timestamp
```

### MigrationProof

Serializable proof transferred from source to target.

```python
@dataclass
class MigrationProof:
    vault_id: bytes      # 32 B
    source_lock: bytes   # 32 B
    target_lock: bytes   # 32 B
    nonce: bytes         # 32 B
    commitment: bytes    # 32 B - HKDF commitment
    response: bytes      # 32 B - Fiat-Shamir response
    timestamp: float     # for TTL check
```

### MigrationResult

Returned on successful verification.

```python
@dataclass
class MigrationResult:
    vault_id: bytes          # 32 B
    machine_bound_key: bytes # 32 B - new device-specific key
    session_key: bytes       # 32 B - ephemeral for data transfer
```

## CLI Usage

### Step 1: Target Device Displays Lock

```bash
# On the NEW device
py scripts/vault_migrate.py show-lock \
    --machine-lock $(cat /path/to/machine_lock.hex) \
    --qr
```

This displays the machine lock as a QR code for the source to scan.

### Step 2: Source Device Generates Proof

```bash
# On the CURRENT device (has master_key)
py scripts/vault_migrate.py prove \
    --master-key <64-char-hex> \
    --vault-id <64-char-hex> \
    --source-lock <64-char-hex> \
    --target-lock <64-char-hex-from-qr> \
    --out proof.json \
    --verify-tag
```

### Step 3: Transfer Proof

Transfer `proof.json` to the target device via:
- QR code (encode JSON as QR)
- NFC tap
- Encrypted channel
- Direct file transfer

### Step 4: Target Device Verifies and Binds

```bash
# On the NEW device
py scripts/vault_migrate.py verify \
    --proof proof.json \
    --master-key <64-char-hex> \
    --machine-lock <64-char-hex> \
    --out keys.json
```

On success, `keys.json` contains:
```json
{
  "vault_id_hex": "...",
  "machine_bound_key_hex": "...",
  "session_key_hex": "..."
}
```

## Cryptographic Details

### Domain Separation

All HKDF derivations use unique info strings:

| Derivation | Info String |
|------------|-------------|
| Commitment | `esoptron.migrate.commitment.v1` |
| Response | `esoptron.migrate.response.v1` |
| Challenge hash | `esoptron.migrate.challenge.v1` |
| Machine binding | `esoptron.migrate.machine_bind.v1` |
| Session key | `esoptron.migrate.session_key.v1` |
| Verify tag | `esoptron.migrate.verify_tag.v1` |

### Challenge Hash

```
ch = SHA3-256(
    INFO_CHALLENGE ||
    vault_id ||
    source_lock ||
    target_lock ||
    commitment ||
    nonce
)
```

### Verify Tag (Optional)

A public verification tag can be embedded in `.eopx` for third-party witnesses:

```python
verify_tag = HKDF(master_key, salt=vault_id, info="verify_tag", length=32)
```

This allows a migration server to attest that a valid proof was presented without learning `master_key`.

## Integration with Eidolon

### Required from Eidolon

1. **vault_id**: `SHA3-256(spinor_hash)`, 32 bytes
2. **machine_lock**: Hardware-derived fingerprint, 32 bytes
3. **master_key**: Vault master key from Phase 9 or genesis, 32 bytes

### Post-Migration

After successful migration:

1. Target device stores `machine_bound_key` in secure storage
2. Source device should be added to revocation list (Eidolon-side)
3. `session_key` can be used for one-time secure data transfer

## Threat Model

| Threat | Mitigation |
|--------|------------|
| MITM intercepts proof | Cannot derive keys without `master_key`; proof bound to specific targets |
| Replay old proof | TTL check rejects proofs > 5 minutes old |
| Wrong device claims to be target | `target_lock` comparison fails |
| Brute force commitment | HKDF-SHA3-512 with 32-byte nonce is computationally infeasible |
| Timing attack on comparison | All comparisons use `hmac.compare_digest` |

## Testing

```bash
# Run all migration tests
py -m pytest tests/test_vault_migrate.py -v

# Test specific scenarios
py -m pytest tests/test_vault_migrate.py -k "roundtrip" -v
py -m pytest tests/test_vault_migrate.py -k "wrong_target" -v
py -m pytest tests/test_vault_migrate.py -k "ttl" -v
```

## Future Work

1. **Revocation list integration**: Eidolon-side invalidation of source device
2. **Multi-device migration**: Batch migration to multiple targets
3. **Hardware attestation**: Bind to TPM/Secure Enclave measurements
4. **Witness protocol**: Full verify_tag-based attestation without master_key
