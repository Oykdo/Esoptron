# EPX-G — Esoptron Protocol G: Identity Reclaim

| Field           | Value                                            |
| --------------- | ------------------------------------------------ |
| Identifier      | EPX-G                                            |
| Status          | Draft                                            |
| Version         | 1                                                |
| Date            | 2026-05-30                                       |
| Author          | Jérémy ZGONEC                                    |
| Layer           | `eopx.vault` (no Eidolon-side change required)   |
| Wire compat     | Additive — does not modify any A-F protocol      |

## Abstract

Protocol G defines a procedure by which a new device (Device B) can
re-derive the *exact* Esoptron `EnrollmentRecord` that was originally
issued to a now-lost or migrating device (Device A), given:

1. Possession of the **PUBLIC Metatron card** that anchored the
   original enrollment.
2. A **second factor** that proves prior ownership of the original
   `device_entropy`:
   - **Path P**: BIP-39 recovery phrase (24 words), or
   - **Path S**: a quorum of Esoptron recovery shards (k-of-n).

The protocol produces a self-contained `ReclaimClaim` artefact —
verifiable by any third party who holds `enrollment_fp` — which proves
that the holder of the reclaim possesses `device_secret` and is
operating with consent of the legitimate owner.

Protocol G is strictly an **Esoptron-side** addition. It does **not**
modify the Eidolon Phases 1..6, does not change `machine_lock`'s role
in `spinor_hash` derivation, and is fully optional. An Eidolon
deployment that wishes to recognise reclaimed enrollments simply
trusts a `ReclaimClaim` whose signature verifies under the
`enrollment_fp` it has on file.

## 1. Motivation

The current enrollment model (Protocol D) couples each enrolled
identity to the `device_entropy` of the device that ran the
ceremony. If the device is lost, the only paths back to the same
`enrollment_fp` are:

- **Cross-machine migration (Protocol F)** — requires the *old* device
  to be alive enough to produce a NIZK proof. Useless if the device is
  destroyed.
- **Re-enrolling on a new device (Protocol D)** — produces a
  *different* `enrollment_fp`, breaking continuity of identity across
  the ecosystem (audit logs, social graph, attestations).

Protocol G fills this gap. It exploits a property already present in
the architecture: the Metatron PUBLIC card is a stable, public,
out-of-band anchor that any device can re-photograph at any time, and
the *only* secret-bearing component of an enrollment is the 32-byte
`device_entropy` — which the user is already encouraged to back up via
either BIP-39 (Genesis recovery phrase) or holographic shards
(`eopx.recovery`).

If the user has either backup, the new device has all the inputs it
needs to *reproduce* the original `EnrollmentRecord` byte-for-byte.

## 2. Roles and notation

| Symbol           | Definition                                            |
| ---------------- | ----------------------------------------------------- |
| Device A         | The device that ran the original Protocol D enrollment |
| Device B         | The new device performing the reclaim                  |
| `card`           | The PUBLIC Metatron card carrying the 91 F_13 symbols  |
| `card_fp`        | 32-byte fingerprint = SHA3-256 over canonical encoding |
| `device_entropy` | 32 B, the per-device random component of enrollment    |
| `device_secret`  | 32 B, HKDF(device_entropy, info="identity.private.v1") |
| `enrollment_fp`  | 32 B, the stable public ID of the enrollment           |
| `nonce`          | 32 B, fresh randomness from Device B                   |
| `t`              | Unix timestamp (seconds), UTC, integer                 |
| `target_context` | 32 B opaque, optional (e.g. hash of Device B's machine_lock) |

All HKDF calls are HKDF-SHA3-512 as in `metatron.field.hkdf_sha3_512`.
All HMAC calls are HMAC-SHA3-256.

## 3. Reclaim flow

### 3.1 Inputs

Device B obtains the following:

1. A photo of the PUBLIC card → extract 91 F_13 symbols → compute
   `card_fp` (existing primitive `card_fingerprint`).
2. A second factor that yields the original 32-byte `device_entropy`:
   - **Path P**: the user types in the 24-word BIP-39 phrase →
     `device_entropy = recovery_phrase_to_entropy(words)`.
   - **Path S**: the user provides a quorum of Esoptron recovery shards
     (k-of-n, see `eopx.recovery`) → `device_entropy =
     recover_entropy(package, creds)`.
3. Optional `target_context` (32 B). If absent, the value
   `SHA3-256("epx-g.no-target-context.v1")` is used (binds the claim
   to "no specific target", which is fine when Device B has no
   stable machine identity yet).

### 3.2 Derivation

Device B reproduces the original Protocol D enrollment with the same
`device_entropy`:

```text
enrollment = enroll_from_card(card_symbols, device_entropy=device_entropy)
```

Because `enroll_from_card` is deterministic in `(card_symbols,
device_entropy)`, the resulting `EnrollmentRecord` is bit-for-bit
identical to the one Device A originally produced — same `vault_fp`,
`device_secret`, `enrollment_fp`, `public_tag`, `shadow_hologram`.

### 3.3 Claim generation

Device B then generates a `ReclaimClaim` that **proves possession of
`device_secret`** in the current reclaim context:

```text
nonce          = csprng(32)
t              = now()                                  # seconds, integer
claim_id       = SHA3-256(
                   "epx-g.reclaim_id.v1"
                 ‖ enrollment_fp
                 ‖ target_context
                 ‖ nonce
                 ‖ uint64_be(t)
                 )

claim_tag      = HMAC-SHA3-256(
                   key  = device_secret,
                   msg  = "epx-g.claim_tag.v1\n"
                        ‖ claim_id
                 )
```

The `ReclaimClaim` artefact is then:

```text
ReclaimClaim {
  version          = 1            # 1 byte
  enrollment_fp    : 32 B
  vault_fp         : 32 B           # = card_fp at time of original enrollment
  target_context   : 32 B
  nonce            : 32 B
  timestamp        : uint64_be      # 8 B
  claim_id         : 32 B            # derived; included for ease of verification
  claim_tag        : 32 B            # HMAC under device_secret
  path             = "phrase" | "shards"   # documentary, not signed
}
```

Wire size: **201 bytes** (binary) or ≈ 550 bytes (JSON-hex).

### 3.4 Verification

Any party V that holds either `device_secret` (i.e. an old backup of
the same enrollment) **or** `enrollment_fp` plus a *previously
recorded* `claim_tag_known` value can verify the claim.

Two verification modes are defined:

**Mode V1 — full verification (recommended)**

```text
require:
  - V has device_secret on record (e.g. a paired device that has
    not been wiped, or a server that escrowed it under HSM)

procedure:
  1. recompute claim_id locally (V knows all fields)
  2. expected_tag = HMAC-SHA3-256(device_secret, "epx-g.claim_tag.v1\n" ‖ claim_id)
  3. accept if hmac.compare_digest(expected_tag, claim.claim_tag)
                                        AND
                |t - now()| <= RECLAIM_TTL_SECONDS
  4. log (enrollment_fp, vault_fp, target_context, t) for audit
```

**Mode V2 — fingerprint-only verification**

When V only knows `enrollment_fp` (e.g. a public registry), V cannot
verify the HMAC. V can however require Mode V1 verification by a
*trusted relay* who does hold `device_secret` and have that relay
co-sign the claim. This is the recommended composition for Eidolon-
side acceptance.

### 3.5 TTL and replay defence

`RECLAIM_TTL_SECONDS = 600` (10 minutes by default; environment
override `ESOPTRON_RECLAIM_TTL_SECONDS`).

The `(enrollment_fp, nonce)` pair MUST be remembered by V for at least
`RECLAIM_TTL_SECONDS` to reject replays of the same claim within its
validity window. After expiry the nonce can be garbage-collected.

## 4. Threat model

### Threats considered

| Threat                                          | Mitigation                                                                        |
| ----------------------------------------------- | --------------------------------------------------------------------------------- |
| Photo of the card leaked publicly               | Card alone is *insufficient*: attacker also needs the second factor (P or S).     |
| BIP-39 phrase leaked                            | Phrase alone is *insufficient*: attacker also needs the matching card.            |
| Single shard captured                           | Single shard reveals nothing (Shamir property). Attacker still needs k-1 more.    |
| Replay of a captured `ReclaimClaim`             | Bound to fresh `nonce` + `t`; verifier MUST de-duplicate within TTL.              |
| Replay across deployments                       | `target_context` differs; if absent, deployments SHOULD use distinct domain salts. |
| Long-term collection of valid claims for later  | TTL = 10 min; expired claims must be rejected.                                    |
| Side-channel timing on HMAC                     | `hmac.compare_digest` (constant time) in reference implementation.                |
| Phishing of card_fp (wrong card scanned)        | `vault_fp` recorded in claim; verifier checks against known enrollment record.    |

### Threats explicitly NOT in scope

| Threat                                                        | Comment                                                                    |
| ------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Simultaneous compromise of card + BIP-39 + shards quorum      | By design indistinguishable from legitimate user; defence ends here.       |
| Eidolon-side `machine_lock` revocation                        | Out of scope. Eidolon must layer its own revocation policy on top.         |
| Loss of all backups                                           | Out of scope. User MUST keep at least one second-factor backup alive.      |
| Attacker controls verifier V                                  | Out of scope. Verifier integrity is a deployment concern.                  |

### Comparison with Protocol F (NIZK migration)

Protocol F requires the **source device** to be alive and active. Its
threat model accordingly assumes the source private key (`master_key`)
is reachable.

Protocol G replaces "source device alive" with "user has backed up
second factor". The threat models are complementary:

- Use F when migrating a working device to a new working device.
- Use G when the source device is lost / destroyed / decommissioned
  and the user has only the card + a backup.

The two protocols MUST NOT be confused: a successful G claim is *not*
equivalent to migrating an active vault; it merely re-derives the same
public enrollment identity on a new device. Vault unlock (master_key,
session keys) still requires the appropriate A/C/F protocol.

## 5. Wire format

### 5.1 Binary encoding (201 bytes)

| Offset | Length | Field            | Notes                                          |
| -----: | -----: | ---------------- | ---------------------------------------------- |
|      0 |      1 | version          | `0x01`                                         |
|      1 |     32 | enrollment_fp    |                                                |
|     33 |     32 | vault_fp         |                                                |
|     65 |     32 | target_context   | all-zeros = none                               |
|     97 |     32 | nonce            |                                                |
|    129 |      8 | timestamp        | uint64 big-endian, seconds since Unix epoch    |
|    137 |     32 | claim_id         | redundant w/ derivation; included for sanity   |
|    169 |     32 | claim_tag        |                                                |

Bytes 0..168 (versioned header + identifiers + nonce + ts + claim_id)
are the canonical bytes hashed/verified; `claim_tag` is the HMAC over
the message body defined in §3.3.

### 5.2 JSON encoding (recommended for transport)

```json
{
  "version": 1,
  "type": "epx-g.reclaim_claim.v1",
  "enrollment_fp_hex": "...",
  "vault_fp_hex": "...",
  "target_context_hex": "...",
  "nonce_hex": "...",
  "timestamp": 1748620800,
  "claim_id_hex": "...",
  "claim_tag_hex": "...",
  "path": "phrase"
}
```

The `path` field is documentary (`"phrase"` for Path P, `"shards"`
for Path S, `"other"` reserved). Verifiers MUST ignore it for the
purposes of authentication; it is only used for audit logging.

### 5.3 Constants table

| Constant                            | Value                                  |
| ----------------------------------- | -------------------------------------- |
| `RECLAIM_CLAIM_VERSION`             | `1`                                    |
| `RECLAIM_TTL_SECONDS`               | `600`                                  |
| `RECLAIM_DOMAIN_ID`                 | `b"epx-g.reclaim_id.v1"`               |
| `RECLAIM_DOMAIN_TAG`                | `b"epx-g.claim_tag.v1\n"`              |
| `RECLAIM_DOMAIN_NO_TARGET`          | `b"epx-g.no-target-context.v1"`        |

## 6. Test vectors

### 6.1 Vector G.1 — Path P (BIP-39 phrase)

Inputs (deterministic):

```text
device_entropy = 0x00 ** 32
card_symbols   = [i % 13 for i in range(91)]
nonce          = 0xAB ** 32
timestamp      = 1748620800
target_context = 0x00 ** 32
```

Derived:

```text
card_fp        = SHA3-256("esoptron.metatron.card_fingerprint.v1\n" ‖ S_bytes)
                = (32 bytes — see test_reclaim::test_vector_G1 in CI)
device_secret  = HKDF(device_entropy, info="esoptron.enroll.identity.private.v1", 32)
enrollment_fp  = HKDF(device_secret, salt=card_fp,
                      info="esoptron.enroll.fingerprint.v1", 32)
```

The reference implementation MUST emit a `ReclaimClaim` whose
`claim_id` and `claim_tag` match the values asserted in
`tests/test_reclaim.py::test_vector_G1` (bit-exact).

### 6.2 Vector G.2 — Path S (Shamir reconstruction)

Same as G.1 but `device_entropy` is recovered from a 2-of-3 shard
package (parameters frozen in test fixture).

The resulting `ReclaimClaim` MUST be bit-identical to G.1, except
for the `path` field which is `"shards"`. Equality of the claim
demonstrates that the reclaim is **path-agnostic** at the security
boundary.

### 6.3 Vector G.3 — Tamper detection

Mutating any of the 168 message bytes of a valid claim MUST cause
verification to fail. The test suite enumerates all 168 positions.

## 7. Reference implementation

Module: `src/eopx/vault/reclaim.py`

Public API:

```python
@dataclass(frozen=True)
class ReclaimClaim:
    version: int
    enrollment_fp: bytes
    vault_fp: bytes
    target_context: bytes
    nonce: bytes
    timestamp: int
    claim_id: bytes
    claim_tag: bytes
    path: str

    def to_bytes(self) -> bytes: ...
    def to_dict(self) -> dict: ...
    @classmethod
    def from_bytes(cls, b: bytes) -> "ReclaimClaim": ...
    @classmethod
    def from_dict(cls, d: dict) -> "ReclaimClaim": ...


def reclaim_from_phrase(
    card_symbols: Sequence[int],
    recovery_phrase: Sequence[str],
    *,
    target_context: Optional[bytes] = None,
    timestamp: Optional[int] = None,
    nonce: Optional[bytes] = None,
    language: str = "english",
) -> tuple[EnrollmentRecord, ReclaimClaim]: ...


def reclaim_from_shards(
    card_symbols: Sequence[int],
    package: RecoveryPackage,
    creds: RecoveryCredentials | FlexibleCredentials,
    *,
    target_context: Optional[bytes] = None,
    timestamp: Optional[int] = None,
    nonce: Optional[bytes] = None,
) -> tuple[EnrollmentRecord, ReclaimClaim]: ...


def verify_reclaim(
    claim: ReclaimClaim,
    device_secret: bytes,
    *,
    now: Optional[int] = None,
    ttl: int = RECLAIM_TTL_SECONDS,
) -> bool: ...
```

`reclaim_*` functions return BOTH the re-derived `EnrollmentRecord`
(so the caller can install it on the new device) AND the
`ReclaimClaim` (so the caller can transmit it to verifiers). Callers
MUST treat `EnrollmentRecord.device_secret` as sensitive and store /
zero it according to the host platform's secure-memory conventions.

## 8. Open items and future extensions

- **Co-signed reclaim (G + Cosigner)**. A future extension may add a
  third path where a pre-registered peer device co-signs the claim
  with a Dilithium-5 signature. This is strictly an addition; the
  current Path P / Path S protocol stays canonical.
- **Eidolon-side acceptance policy**. Out of scope here. A future
  Eidolon spec ("EID-2") may define how a Reclaim flow is presented
  to the Phases pipeline and what additional attestations Eidolon
  requires before binding a new `machine_lock`.
- **Cross-deployment claims**. The `target_context` field is designed
  to carry a deployment identifier; a registry of well-known
  deployment IDs may be standardised separately.

## 9. References

- BIP-0039: Mnemonic code for generating deterministic keys.
- RFC 5869: HMAC-based Extract-and-Expand KDF (HKDF).
- FIPS PUB 202: SHA-3 Standard.
- Esoptron Whitepaper IV — Vault Protocols A-F.
- Esoptron `recovery.py` module — 2-of-3 holographic Shamir sharding.

---

*This document is normative for `version = 1`. Future versions MUST
bump `RECLAIM_CLAIM_VERSION` and ship a migration note in
`docs/migration_protocol.md`.*
