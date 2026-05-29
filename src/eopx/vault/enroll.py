"""Protocol D: phone-only onboarding via Metatron card scan.

Use case
--------
A new user receives a PUBLIC Metatron card (invitation / welcome poster /
NFC-printed page). They open the Esoptron mobile app, point the phone
camera at the card, and the app:

  1. Extracts 91 F_13 symbols from the photo.
  2. Computes a stable vault_fingerprint (32 bytes) from the card.
  3. Mixes the fingerprint with locally-generated device entropy to
     produce a unique enrollment_fingerprint and shadow_hologram_seed.
  4. Generates the user's first device-bound Eidolon-compatible
     identity:
            id_priv       = device entropy alone (never leaves device)
            id_public_tag = HKDF(device_secret || vault_fp)
            enrollment_fp = HKDF(device_secret || vault_fp) — unique per phone
  5. Renders a holographic preview locally from the card_fingerprint
     so the user sees an animated, interactive confirmation that they
     have "entered" the ecosystem - all without contacting a server
     or desktop.

No secret of the issuing vault is ever transmitted: the card carries an
HKDF expansion of `spinor_hash`, which is one-way under the PRF
assumption (Whitepaper III, Theorem 2). The phone derives an INDEPENDENT
identity bound to the card's fingerprint, not to its preimage.

Threat model
------------
- An attacker photographing the same poster derives the SAME vault_fp,
  but a DIFFERENT enrollment_fp (because device_entropy is unique).
  The ecosystem can track enrollments by enrollment_fp to detect
  duplicate scans, while vault_fp identifies the issuing vault.
- The user's device private key is generated locally; the card scan
  only contributes to the identity TAG, not to the private material.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Optional, Sequence

from ..metatron.field import hkdf_sha3_512
from .verify_card import card_fingerprint

SHADOW_BYTES = 64
DEVICE_ENTROPY_BYTES = 32
PUBLIC_TAG_BYTES = 16

INFO_SHADOW   = b"esoptron.enroll.shadow_hologram.v1"
INFO_IDPRIV   = b"esoptron.enroll.identity.private.v1"
INFO_IDPUBTAG = b"esoptron.enroll.identity.public_tag.v1"
INFO_ENROLLFP = b"esoptron.enroll.fingerprint.v1"


@dataclass(frozen=True)
class EnrollmentRecord:
    """Output of an enrollment ceremony. Only `device_secret` is sensitive."""
    vault_fp: bytes             # 32 B — shared fingerprint of the issuing vault (card_fp)
    device_secret: bytes        # 32 B — SENSITIVE, never leaves device
    enrollment_fp: bytes        # 32 B — UNIQUE per enrollment (vault_fp + device_secret)
    public_tag: bytes           # 16 B — public ID, unique per enrollment
    shadow_hologram: bytes      # 64 B — used to render local hologram preview

    def to_public_dict(self) -> dict:
        """Strip the secret for safe display / logging."""
        return {
            "vault_fp_hex": self.vault_fp.hex(),
            "enrollment_fp_hex": self.enrollment_fp.hex(),
            "public_tag_hex": self.public_tag.hex(),
            "shadow_hologram_hex": self.shadow_hologram.hex(),
        }


def derive_shadow_hologram(card_fp: bytes,
                           device_entropy: bytes,
                           length: int = SHADOW_BYTES) -> bytes:
    """Derive a per-device shadow hologram seed for a given card.

    The shadow hologram is meant to FEED a local renderer (e.g. a
    GLSL shader on the phone) so the user sees a personal, animated
    artefact bound to BOTH the card and their device. Two users
    scanning the same poster see DIFFERENT holograms.
    """
    if len(card_fp) != 32:
        raise ValueError("card_fp must be 32 bytes")
    if len(device_entropy) != DEVICE_ENTROPY_BYTES:
        raise ValueError(f"device_entropy must be {DEVICE_ENTROPY_BYTES} bytes")
    ikm = card_fp + device_entropy
    return hkdf_sha3_512(ikm=ikm, salt=b"", info=INFO_SHADOW, length=length)


def enroll_from_card(card_symbols: Sequence[int],
                     device_entropy: Optional[bytes] = None,
                     rng=None) -> EnrollmentRecord:
    """Run the enrollment ceremony from a freshly scanned PUBLIC card.

    Parameters
    ----------
    card_symbols : Sequence[int]
        91 F_13 symbols extracted from the photographed card.
    device_entropy : bytes, optional
        32 bytes of locally-generated entropy. If None, drawn from
        secrets.token_bytes (CSPRNG) or `rng` if provided. Pass a fixed
        value for reproducible tests.
    rng : optional
        Callable rng(n)->bytes, for deterministic tests.

    Returns
    -------
    EnrollmentRecord
        Holds the card fingerprint, the SENSITIVE device secret, a
        public identity tag, and the shadow hologram seed.
    """
    if len(card_symbols) != 91:
        raise ValueError("card_symbols must have length 91")
    fp = card_fingerprint(card_symbols)

    if device_entropy is None:
        device_entropy = (rng(DEVICE_ENTROPY_BYTES) if rng is not None
                          else secrets.token_bytes(DEVICE_ENTROPY_BYTES))
    if len(device_entropy) != DEVICE_ENTROPY_BYTES:
        raise ValueError(f"device_entropy must be {DEVICE_ENTROPY_BYTES} bytes")

    # Private device material. Never leaves the device.
    device_secret = hkdf_sha3_512(
        ikm=device_entropy, salt=b"", info=INFO_IDPRIV, length=32,
    )
    # Enrollment fingerprint: UNIQUE per enrollment.
    # Combines the vault identity (card_fp) with the device identity
    # so each phone gets a different fingerprint from the same sheet.
    enrollment_fp = hkdf_sha3_512(
        ikm=device_secret, salt=fp, info=INFO_ENROLLFP, length=32,
    )
    # Public tag = short, enrollment-bound identifier. Safe to publish.
    public_tag = hkdf_sha3_512(
        ikm=device_secret, salt=fp, info=INFO_IDPUBTAG,
        length=PUBLIC_TAG_BYTES,
    )
    shadow = derive_shadow_hologram(fp, device_entropy)

    return EnrollmentRecord(
        vault_fp=fp,
        device_secret=device_secret,
        enrollment_fp=enrollment_fp,
        public_tag=public_tag,
        shadow_hologram=shadow,
    )
