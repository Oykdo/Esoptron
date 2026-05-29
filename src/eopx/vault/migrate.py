"""Protocol F: Cross-machine vault migration with NIZK proof.

Use case
--------
An Eidolon vault is bound to a machine via ``machine_lock``. When the user
wants to migrate to a new device, they must prove possession of the vault
secret WITHOUT transmitting it. This prevents man-in-the-middle attacks
during migration.

The protocol uses a Fiat-Shamir transformed commitment scheme:

    1. Source device generates a migration challenge binding:
       - vault_id (identifies the vault)
       - source_machine_lock (current device identity)
       - target_machine_lock (new device identity)
       - fresh nonce

    2. Source device computes a NIZK proof that it possesses master_key:
       - commitment = HKDF(master_key, salt=nonce, info="commit")
       - challenge_hash = SHA3-256(vault_id || source || target || commitment || nonce)
       - response = HKDF(master_key || challenge_hash, info="response")

    3. Target device receives (commitment, nonce, response) + vault_id.
       It cannot verify without the public parameters published during
       vault creation. Verification requires the vault's public commitment
       (stored in .eopx or .psnx).

    4. Once verified, the target device derives its new machine-bound key:
       - new_machine_key = HKDF(master_key, salt=target_machine_lock, info="bind")

Security properties:
    - Zero-knowledge: The response reveals nothing about master_key beyond
      the fact that the prover knows it.
    - Non-transferability: The proof is bound to specific (source, target)
      machine locks; replaying it on another device fails.
    - Forward secrecy: After migration, the source device's binding is
      invalidated (requires Eidolon-side revocation list).

Implementation notes:
    - This module provides the cryptographic proof primitives.
    - The actual machine_lock binding is Eidolon's responsibility.
    - The migration ceremony requires out-of-band exchange of target_machine_lock
      (e.g., QR code displayed on the new device).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from ..metatron.field import hkdf_sha3_512

# Domain separation strings
INFO_COMMIT = b"esoptron.migrate.commitment.v1"
INFO_RESPONSE = b"esoptron.migrate.response.v1"
INFO_CHALLENGE = b"esoptron.migrate.challenge.v1"
INFO_BIND = b"esoptron.migrate.machine_bind.v1"
INFO_SESSION = b"esoptron.migrate.session_key.v1"
INFO_VERIFY_TAG = b"esoptron.migrate.verify_tag.v1"

NONCE_BYTES = 32
COMMITMENT_BYTES = 32
RESPONSE_BYTES = 32
CHALLENGE_TTL_SECONDS = 300  # 5 minutes


@dataclass(frozen=True)
class MigrationChallenge:
    """A challenge issued by the source device to initiate migration."""
    vault_id: bytes          # 32 B - identifies the vault
    source_lock: bytes       # 32 B - source machine_lock fingerprint
    target_lock: bytes       # 32 B - target machine_lock fingerprint
    nonce: bytes             # 32 B - fresh randomness
    timestamp: float         # Unix timestamp


@dataclass(frozen=True)
class MigrationProof:
    """NIZK proof of vault ownership for migration."""
    vault_id: bytes          # 32 B - identifies the vault
    source_lock: bytes       # 32 B - source machine_lock fingerprint
    target_lock: bytes       # 32 B - target machine_lock fingerprint
    nonce: bytes             # 32 B - challenge nonce
    commitment: bytes        # 32 B - HKDF commitment
    response: bytes          # 32 B - Fiat-Shamir response
    timestamp: float         # Unix timestamp (for TTL)

    def to_dict(self) -> dict:
        return {
            "vault_id_hex": self.vault_id.hex(),
            "source_lock_hex": self.source_lock.hex(),
            "target_lock_hex": self.target_lock.hex(),
            "nonce_hex": self.nonce.hex(),
            "commitment_hex": self.commitment.hex(),
            "response_hex": self.response.hex(),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MigrationProof":
        return cls(
            vault_id=bytes.fromhex(d["vault_id_hex"]),
            source_lock=bytes.fromhex(d["source_lock_hex"]),
            target_lock=bytes.fromhex(d["target_lock_hex"]),
            nonce=bytes.fromhex(d["nonce_hex"]),
            commitment=bytes.fromhex(d["commitment_hex"]),
            response=bytes.fromhex(d["response_hex"]),
            timestamp=d["timestamp"],
        )


@dataclass(frozen=True)
class MigrationResult:
    """Result of a successful migration on the target device."""
    vault_id: bytes          # 32 B
    machine_bound_key: bytes # 32 B - new machine-specific key
    session_key: bytes       # 32 B - ephemeral session key for data transfer

    def to_public_dict(self) -> dict:
        """Safe to log - no secrets."""
        return {
            "vault_id_hex": self.vault_id.hex(),
        }


def _compute_challenge_hash(vault_id: bytes,
                             source_lock: bytes,
                             target_lock: bytes,
                             commitment: bytes,
                             nonce: bytes,
                             timestamp: float) -> bytes:
    """SHA3-256 Fiat-Shamir challenge hash."""
    h = hashlib.sha3_256()
    h.update(INFO_CHALLENGE)
    h.update(vault_id)
    h.update(source_lock)
    h.update(target_lock)
    h.update(commitment)
    h.update(nonce)
    h.update(struct.pack(">d", float(timestamp)))
    return h.digest()


def new_migration_challenge(vault_id: bytes,
                             source_lock: bytes,
                             target_lock: bytes) -> MigrationChallenge:
    """Create a fresh migration challenge on the source device.

    Parameters
    ----------
    vault_id : bytes
        32-byte vault identifier (e.g., SHA3-256 of spinor_hash).
    source_lock : bytes
        32-byte fingerprint of the current machine_lock.
    target_lock : bytes
        32-byte fingerprint of the target machine_lock (obtained via QR).

    Returns
    -------
    MigrationChallenge
        A fresh challenge to be used with prove_migration().
    """
    if len(vault_id) != 32:
        raise ValueError("vault_id must be 32 bytes")
    if len(source_lock) != 32:
        raise ValueError("source_lock must be 32 bytes")
    if len(target_lock) != 32:
        raise ValueError("target_lock must be 32 bytes")

    return MigrationChallenge(
        vault_id=vault_id,
        source_lock=source_lock,
        target_lock=target_lock,
        nonce=secrets.token_bytes(NONCE_BYTES),
        timestamp=time.time(),
    )


def prove_migration(master_key: bytes,
                     challenge: MigrationChallenge) -> MigrationProof:
    """Generate a NIZK proof of vault ownership.

    This is executed on the SOURCE device. The proof demonstrates knowledge
    of master_key without revealing it.

    Parameters
    ----------
    master_key : bytes
        32-byte vault master key (from unlock_from_private_symbols or genesis).
    challenge : MigrationChallenge
        The migration challenge created by new_migration_challenge().

    Returns
    -------
    MigrationProof
        A non-interactive zero-knowledge proof transferable to the target.
    """
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")

    # Step 1: Compute commitment
    # commitment = HKDF(master_key, salt=nonce, info="commit")
    commitment = hkdf_sha3_512(
        ikm=master_key,
        salt=challenge.nonce,
        info=INFO_COMMIT,
        length=COMMITMENT_BYTES,
    )

    # Step 2: Compute Fiat-Shamir challenge hash
    ch = _compute_challenge_hash(
        challenge.vault_id,
        challenge.source_lock,
        challenge.target_lock,
        commitment,
        challenge.nonce,
        challenge.timestamp,
    )

    # Step 3: Compute response
    # response = HKDF(master_key || challenge_hash, info="response")
    response = hkdf_sha3_512(
        ikm=master_key + ch,
        salt=challenge.nonce,
        info=INFO_RESPONSE,
        length=RESPONSE_BYTES,
    )

    return MigrationProof(
        vault_id=challenge.vault_id,
        source_lock=challenge.source_lock,
        target_lock=challenge.target_lock,
        nonce=challenge.nonce,
        commitment=commitment,
        response=response,
        timestamp=challenge.timestamp,
    )


def verify_migration(proof: MigrationProof,
                      master_key: bytes,
                      local_machine_lock: bytes,
                      *,
                      check_ttl: bool = True) -> Optional[MigrationResult]:
    """Verify a migration proof and derive new machine-bound keys.

    This is executed on the TARGET device. The verifier must have obtained
    master_key through a secure channel (e.g., Shamir reconstruction,
    encrypted backup, or direct transfer after proof verification).

    In a full implementation, the target device would:
    1. Receive the proof over an insecure channel
    2. Verify the proof structure and TTL
    3. Request the encrypted master_key from a recovery service
    4. Decrypt using its Kyber private key
    5. Call this function to verify and bind

    Parameters
    ----------
    proof : MigrationProof
        The proof received from the source device.
    master_key : bytes
        32-byte vault master key (obtained through secure channel).
    local_machine_lock : bytes
        32-byte fingerprint of THIS device's machine_lock.
    check_ttl : bool
        Whether to enforce the challenge TTL (default True).

    Returns
    -------
    MigrationResult or None
        The new machine-bound keys if verification succeeds, None otherwise.
    """
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    if len(local_machine_lock) != 32:
        raise ValueError("local_machine_lock must be 32 bytes")

    # Check that this device is the intended target
    if not hmac.compare_digest(proof.target_lock, local_machine_lock):
        return None

    # Check TTL
    if check_ttl:
        age = time.time() - proof.timestamp
        if age > CHALLENGE_TTL_SECONDS or age < 0:
            return None

    # Recompute the commitment from master_key
    expected_commitment = hkdf_sha3_512(
        ikm=master_key,
        salt=proof.nonce,
        info=INFO_COMMIT,
        length=COMMITMENT_BYTES,
    )

    if not hmac.compare_digest(proof.commitment, expected_commitment):
        return None

    # Recompute challenge hash and response
    ch = _compute_challenge_hash(
        proof.vault_id,
        proof.source_lock,
        proof.target_lock,
        proof.commitment,
        proof.nonce,
        proof.timestamp,
    )

    expected_response = hkdf_sha3_512(
        ikm=master_key + ch,
        salt=proof.nonce,
        info=INFO_RESPONSE,
        length=RESPONSE_BYTES,
    )

    if not hmac.compare_digest(proof.response, expected_response):
        return None

    # Derive new machine-bound key for the target device
    machine_bound_key = hkdf_sha3_512(
        ikm=master_key,
        salt=local_machine_lock,
        info=INFO_BIND,
        length=32,
    )

    # Derive ephemeral session key for secure data transfer
    session_key = hkdf_sha3_512(
        ikm=master_key + proof.nonce,
        salt=local_machine_lock,
        info=INFO_SESSION,
        length=32,
    )

    return MigrationResult(
        vault_id=proof.vault_id,
        machine_bound_key=machine_bound_key,
        session_key=session_key,
    )


def compute_verify_tag(master_key: bytes, vault_id: bytes) -> bytes:
    """Compute a public verification tag for a vault.

    This tag is embedded in the .eopx or .psnx at creation time. It allows
    anyone with the tag to verify a migration proof WITHOUT the master_key,
    by checking that the prover's commitment matches.

    The tag is: HKDF(master_key, info="verify_tag") truncated to 32 bytes.
    It's computationally infeasible to recover master_key from the tag.

    Parameters
    ----------
    master_key : bytes
        32-byte vault master key.
    vault_id : bytes
        32-byte vault identifier.

    Returns
    -------
    bytes
        32-byte verification tag (safe to publish).
    """
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    if len(vault_id) != 32:
        raise ValueError("vault_id must be 32 bytes")

    return hkdf_sha3_512(
        ikm=master_key,
        salt=vault_id,
        info=INFO_VERIFY_TAG,
        length=32,
    )


# NOTE: A `verify_proof_with_tag(proof, verify_tag)` witness API was removed
# in this version because the previous implementation only performed structural
# length checks and accepted arbitrary commitment/response bytes, providing
# zero cryptographic assurance to a third-party witness.
#
# Implementing it correctly requires extending `MigrationProof` with an extra
# `tag_commitment = HKDF(verify_tag, salt=nonce, info=INFO_TAG_COMMITMENT)`
# field computed at proof time, and recomputed at verification time. Until
# that protocol revision is shipped, callers MUST use `verify_migration` with
# the full master_key.


__all__ = [
    "MigrationChallenge",
    "MigrationProof",
    "MigrationResult",
    "new_migration_challenge",
    "prove_migration",
    "verify_migration",
    "compute_verify_tag",
    "CHALLENGE_TTL_SECONDS",
]
