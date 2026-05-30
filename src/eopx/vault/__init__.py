"""Vault-level protocols that consume Metatron symbol vectors.

Protocols A-F exposed:

A. unlock_from_private_symbols(symbols)        -> bytes (master_key)
   Reconstructs the seed from a PRIVATE inscription and derives the vault's
   master key via HKDF-SHA3-512. The sheet alone is sufficient.

B. verify_card(symbols, spinor_hash_local)     -> bool
   Checks whether a PUBLIC card matches a vault known locally.

C. SAS  (Strong Authentication Sheet)         -- challenge / response 2FA
   Combines a publicly printed card with a device-resident credential.

D. enroll_from_card(card_symbols, ...)         -- holographic on-boarding
   Per-device identity derived from a shared card + device entropy.

E. genesis_enroll(sheet_symbols, ...)          -- ceremony onboarding
   ONE sheet → MANY unique vaults. Each participant scanning the same
   sheet gets an independent vault via HKDF(sheet_seed || device_entropy).

F. vault_migrate(master_key, challenge)        -- cross-machine migration
   NIZK proof of vault ownership for migrating to a new device without
   exposing the master_key. Uses Fiat-Shamir transformed commitment.

G. reclaim_from_phrase / reclaim_from_shards  -- identity reclaim
   Re-derive the exact original EnrollmentRecord on a new device from
   the PUBLIC card + a second factor (BIP-39 phrase or k-of-n shard
   quorum). See ``docs/specs/EPX-G_reclaim.md``.
"""

from .unlock import (
    derive_master_key,
    unlock_from_private_symbols,
    unlock_from_seed,
)
from .verify_card import verify_card, card_fingerprint
from .sas import (
    SASChallenge,
    SASResponse,
    new_challenge,
    respond,
    verify_response,
)
from .enroll import (
    EnrollmentRecord,
    enroll_from_card,
    derive_shadow_hologram,
)
from .genesis import (
    GenesisVault,
    CeremonyAttestation,
    genesis_enroll,
    genesis_recover,
    sign_ceremony_attestation,
    verify_ceremony_attestation,
)
from .migrate import (
    MigrationChallenge,
    MigrationProof,
    MigrationResult,
    new_migration_challenge,
    prove_migration,
    verify_migration,
    compute_verify_tag,
)
from .reclaim import (
    RECLAIM_CLAIM_VERSION,
    DEFAULT_RECLAIM_TTL_SECONDS,
    NO_TARGET_CONTEXT,
    PATH_PHRASE,
    PATH_SHARDS,
    PATH_OTHER,
    ReclaimClaim,
    reclaim_from_phrase,
    reclaim_from_shards,
    reclaim_from_entropy,
    verify_reclaim,
)

__all__ = [
    "derive_master_key",
    "unlock_from_private_symbols",
    "unlock_from_seed",
    "verify_card",
    "card_fingerprint",
    "SASChallenge",
    "SASResponse",
    "new_challenge",
    "respond",
    "verify_response",
    "EnrollmentRecord",
    "enroll_from_card",
    "derive_shadow_hologram",
    "GenesisVault",
    "CeremonyAttestation",
    "genesis_enroll",
    "genesis_recover",
    "sign_ceremony_attestation",
    "verify_ceremony_attestation",
    "MigrationChallenge",
    "MigrationProof",
    "MigrationResult",
    "new_migration_challenge",
    "prove_migration",
    "verify_migration",
    "compute_verify_tag",
    "RECLAIM_CLAIM_VERSION",
    "DEFAULT_RECLAIM_TTL_SECONDS",
    "NO_TARGET_CONTEXT",
    "PATH_PHRASE",
    "PATH_SHARDS",
    "PATH_OTHER",
    "ReclaimClaim",
    "reclaim_from_phrase",
    "reclaim_from_shards",
    "reclaim_from_entropy",
    "verify_reclaim",
]
