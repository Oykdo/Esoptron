"""Protocol E: Genesis ceremony — one sheet, many unique vaults.

Use case
--------
An organizer prints a single "genesis sheet" (A4 with Metatron cube +
chromatic grid). Each new participant scans it with their phone. The
scan creates a FRESH, INDEPENDENT vault unique to that participant.

The sheet serves as a shared ceremony identifier. Each device combines
it with locally-generated entropy to derive a per-device vault seed:

    genesis_seed = HKDF(sheet_fingerprint || device_entropy, info="genesis")

This means:
  - No two devices derive the same vault seed (different device_entropy)
  - The sheet alone CANNOT open any individual vault (need device_entropy)
  - Recovering a lost vault requires BOTH the sheet AND the device_entropy
    (stored as a recovery phrase on the device)

Workflow:
  1. Organizer prints genesis sheet: make_test_vault.py --genesis
  2. Participant 1 scans → phone generates device_entropy → derives vault_1
  3. Participant 2 scans → phone generates device_entropy → derives vault_2
  4. ... N participants → N unique vaults, all traced to the same ceremony

The sheet encodes a "ceremony key" that is NOT a vault seed itself.
Instead, it's a public commitment that gets mixed with per-device secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..format.keys import EopxKey
import time
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from ..metatron.field import hkdf_sha3_512
from ..metatron import decode_private, encode_private
from .verify_card import card_fingerprint
from .unlock import derive_master_key

CEREMONY_INFO = b"esoptron.genesis.ceremony.v1"
CEREMONY_ATTESTATION_INFO = b"esoptron.genesis.ceremony.attestation.v1"
GENESIS_SEED_INFO = b"esoptron.genesis.vault_seed.v1"
GENESIS_MASTER_INFO = b"esoptron.genesis.master_key.v1"
DEVICE_ENTROPY_BYTES = 32
RECOVERY_PHRASE_WORDS = 24  # 32 bytes → 24 BIP-39 words (256-bit entropy)


@dataclass(frozen=True)
class GenesisVault:
    """A vault derived from a genesis ceremony sheet + device entropy.

    Each participant scanning the same sheet gets a different GenesisVault
    because device_entropy is unique per enrollment.
    """
    ceremony_fp: bytes          # 32 B — shared, identifies the ceremony (sheet)
    device_entropy: bytes       # 32 B — per-device randomness
    vault_seed: bytes           # 32 B — the actual vault seed (unique per device)
    master_key: bytes           # 32 B — derived from vault_seed
    vault_fp: bytes             # 32 B — fingerprint of THIS vault (unique)

    def to_dict(self) -> dict:
        """Return a dict with all fields (careful: contains secrets!)."""
        return {
            "ceremony_fp_hex": self.ceremony_fp.hex(),
            "vault_seed_hex": self.vault_seed.hex(),
            "master_key_hex": self.master_key.hex(),
            "vault_fp_hex": self.vault_fp.hex(),
            # device_entropy is intentionally excluded from dict output
        }

    def to_public_dict(self) -> dict:
        """Return only public fields (safe to display/log)."""
        return {
            "ceremony_fp_hex": self.ceremony_fp.hex(),
            "vault_fp_hex": self.vault_fp.hex(),
        }


@dataclass(frozen=True)
class CeremonyAttestation:
    """Organizer-signed proof that a Genesis ceremony is legitimate.

    Signed payload: ``CEREMONY_ATTESTATION_INFO || ceremony_fp ||
    organizer_pk || issued_at || nonce || metadata``.

    Verifying this attestation before deriving a vault prevents a
    photographed-and-reprinted ceremony sheet from being passed off as a
    different ceremony (the attacker controls the symbols but cannot forge a
    signature by the organizer's Dilithium key).

    Fields
    ------
    ceremony_fp : bytes
        32-byte fingerprint of the ceremony sheet (must match the scanned
        sheet's ``card_fingerprint``).
    organizer_pk : bytes
        Organizer's ML-DSA-87 public key.
    issued_at : float
        Unix timestamp (seconds) at attestation creation time.
    nonce : bytes
        16+ bytes of random padding to bind the signature to a single
        attestation issuance.
    metadata : dict
        Application-specific JSON-serialisable metadata (event name, expected
        participant count, …). Included in the signed payload.
    signature : bytes
        ML-DSA-87 signature over the canonical payload.
    """

    ceremony_fp: bytes
    organizer_pk: bytes
    issued_at: float
    nonce: bytes
    metadata: dict
    signature: bytes

    def canonical_payload(self) -> bytes:
        """Return the bytes that ``signature`` is computed over."""
        meta_json = json.dumps(self.metadata, sort_keys=True,
                                separators=(",", ":"))
        return b"\n".join([
            CEREMONY_ATTESTATION_INFO,
            self.ceremony_fp.hex().encode("ascii"),
            self.organizer_pk,
            f"{float(self.issued_at):.6f}".encode("ascii"),
            self.nonce,
            meta_json.encode("utf-8"),
        ])

    def to_dict(self) -> dict:
        return {
            "ceremony_fp_hex": self.ceremony_fp.hex(),
            "organizer_pk_b64": _b64(self.organizer_pk),
            "issued_at": self.issued_at,
            "nonce_hex": self.nonce.hex(),
            "metadata": self.metadata,
            "signature_b64": _b64(self.signature),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CeremonyAttestation":
        return cls(
            ceremony_fp=bytes.fromhex(d["ceremony_fp_hex"]),
            organizer_pk=_b64d(d["organizer_pk_b64"]),
            issued_at=float(d["issued_at"]),
            nonce=bytes.fromhex(d["nonce_hex"]),
            metadata=d.get("metadata") or {},
            signature=_b64d(d["signature_b64"]),
        )


def _b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    import base64
    return base64.b64decode(s.encode("ascii"))


def sign_ceremony_attestation(ceremony_fp: bytes,
                               organizer_key: "EopxKey",
                               *,
                               metadata: Optional[dict] = None,
                               nonce: Optional[bytes] = None,
                               issued_at: Optional[float] = None,
                               ) -> CeremonyAttestation:
    """Create a fresh organizer-signed ceremony attestation.

    ``organizer_key`` must be an :class:`EopxKey` with a Dilithium secret
    key (``has_secrets`` True).
    """
    from ..format.keys import EopxKey  # local import to avoid cycle at module load
    from pqcrypto.sign import ml_dsa_87 as _dsa

    if not isinstance(organizer_key, EopxKey):
        raise TypeError("organizer_key must be an EopxKey instance")
    if organizer_key.dilithium_sk is None:
        raise ValueError("organizer_key has no Dilithium secret key")
    if len(ceremony_fp) != 32:
        raise ValueError("ceremony_fp must be 32 bytes")

    att = CeremonyAttestation(
        ceremony_fp=ceremony_fp,
        organizer_pk=organizer_key.dilithium_pk,
        issued_at=issued_at if issued_at is not None else time.time(),
        nonce=nonce if nonce is not None else secrets.token_bytes(16),
        metadata=dict(metadata or {}),
        signature=b"",
    )
    sig = _dsa.sign(organizer_key.dilithium_sk, att.canonical_payload())
    return CeremonyAttestation(
        ceremony_fp=att.ceremony_fp,
        organizer_pk=att.organizer_pk,
        issued_at=att.issued_at,
        nonce=att.nonce,
        metadata=att.metadata,
        signature=sig,
    )


def verify_ceremony_attestation(attestation: CeremonyAttestation,
                                 *,
                                 expected_ceremony_fp: bytes,
                                 expected_organizer_pk: Optional[bytes] = None,
                                 max_age_seconds: Optional[float] = None,
                                 ) -> bool:
    """Verify a ceremony attestation.

    Parameters
    ----------
    attestation : CeremonyAttestation
        The signed attestation received with the sheet (out-of-band).
    expected_ceremony_fp : bytes
        Fingerprint of the locally scanned sheet. MUST match.
    expected_organizer_pk : bytes, optional
        When supplied, the embedded ``organizer_pk`` must equal this value.
        Use this to pin the ceremony to a known organizer.
    max_age_seconds : float, optional
        When supplied, reject attestations older than this many seconds.
    """
    from pqcrypto.sign import ml_dsa_87 as _dsa

    if len(attestation.ceremony_fp) != 32 or len(attestation.signature) == 0:
        return False
    if not hmac.compare_digest(attestation.ceremony_fp, expected_ceremony_fp):
        return False
    if expected_organizer_pk is not None and not hmac.compare_digest(
        attestation.organizer_pk, expected_organizer_pk
    ):
        return False
    if max_age_seconds is not None:
        age = time.time() - attestation.issued_at
        if age < 0 or age > max_age_seconds:
            return False
    try:
        ok = _dsa.verify(
            attestation.organizer_pk,
            attestation.canonical_payload(),
            attestation.signature,
        )
    except Exception:
        return False
    return bool(ok)


def genesis_enroll(sheet_symbols: Sequence[int],
                   device_entropy: Optional[bytes] = None,
                   *,
                   attestation: Optional[CeremonyAttestation] = None,
                   expected_organizer_pk: Optional[bytes] = None,
                   max_attestation_age_seconds: Optional[float] = None,
                   ) -> GenesisVault:
    """Create a unique vault from a genesis ceremony sheet.

    Parameters
    ----------
    sheet_symbols : Sequence[int]
        91 F_13 symbols extracted from the photographed sheet.
    device_entropy : bytes, optional
        32 bytes of locally-generated entropy. If None, drawn from
        secrets.token_bytes (CSPRNG). This MUST be backed up by the
        participant (e.g. as a recovery phrase) to recover the vault
        if the device is lost.

    Returns
    -------
    GenesisVault
        A unique vault derived from the ceremony sheet + device entropy.
    """
    if len(sheet_symbols) != 91:
        raise ValueError("sheet_symbols must have length 91")

    # Decode the sheet to get the ceremony key
    # The sheet's 91 symbols encode a ceremony seed via RS(13,10)
    ceremony_seed, _verified = decode_private(sheet_symbols)
    ceremony_fp = card_fingerprint(sheet_symbols)

    # If an organizer attestation is supplied, verify it before we let the
    # caller derive a vault from a sheet they cannot prove was issued by the
    # legitimate organizer. The attestation is opt-in for backwards compat.
    if attestation is not None:
        ok = verify_ceremony_attestation(
            attestation,
            expected_ceremony_fp=ceremony_fp,
            expected_organizer_pk=expected_organizer_pk,
            max_age_seconds=max_attestation_age_seconds,
        )
        if not ok:
            raise ValueError(
                "ceremony attestation failed verification (signature, "
                "fingerprint, organizer pubkey or TTL mismatch)"
            )

    if device_entropy is None:
        device_entropy = secrets.token_bytes(DEVICE_ENTROPY_BYTES)
    if len(device_entropy) != DEVICE_ENTROPY_BYTES:
        raise ValueError(f"device_entropy must be {DEVICE_ENTROPY_BYTES} bytes")

    # Derive the per-device vault seed:
    # vault_seed = HKDF(ceremony_seed || device_entropy)
    ikm = ceremony_seed + device_entropy
    vault_seed = hkdf_sha3_512(
        ikm=ikm, salt=b"", info=GENESIS_SEED_INFO, length=32,
    )

    # Derive master key from vault seed
    master_key = derive_master_key(vault_seed)

    # Compute this vault's unique fingerprint
    vault_cw = encode_private(vault_seed)
    vault_fp = card_fingerprint(vault_cw)

    return GenesisVault(
        ceremony_fp=ceremony_fp,
        device_entropy=device_entropy,
        vault_seed=vault_seed,
        master_key=master_key,
        vault_fp=vault_fp,
    )


def genesis_recover(sheet_symbols: Sequence[int],
                     device_entropy: bytes,
                     ) -> GenesisVault:
    """Recover a vault from a re-scanned sheet + backed-up device entropy.

    Same as genesis_enroll but requires device_entropy (no random generation).
    This is the recovery flow: participant loses phone, re-scans the
    genesis sheet, enters their recovery phrase → vault recovered.
    """
    return genesis_enroll(sheet_symbols, device_entropy=device_entropy)


_BIP39_LANG_DEFAULT = "english"


def entropy_to_recovery_phrase(entropy: bytes,
                                language: str = _BIP39_LANG_DEFAULT,
                                ) -> List[str]:
    """Convert device entropy to a BIP-39 mnemonic.

    BIP-39 supports entropies of 128 / 160 / 192 / 224 / 256 bits, producing
    12 / 15 / 18 / 21 / 24 words respectively. ``DEVICE_ENTROPY_BYTES`` (32)
    is the 256-bit / 24-word case, but this function accepts any
    BIP-39-compatible length so callers can use shorter mnemonics in tests.

    Parameters
    ----------
    entropy:
        Raw entropy bytes (16, 20, 24, 28 or 32 bytes).
    language:
        BIP-39 wordlist language; defaults to ``"english"``.

    Returns
    -------
    list of str
        The mnemonic words, in order. Suitable for display to the user.
    """
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError(
            "entropy length must be one of 16, 20, 24, 28, 32 bytes "
            f"(got {len(entropy)})"
        )
    # Lazy import so the rest of the module loads even if the package is
    # not yet installed (e.g. in a SDK-only environment).
    from mnemonic import Mnemonic
    mnemo = Mnemonic(language)
    phrase = mnemo.to_mnemonic(entropy)
    return phrase.split()


def recovery_phrase_to_entropy(words: List[str],
                                language: str = _BIP39_LANG_DEFAULT,
                                ) -> bytes:
    """Convert a BIP-39 mnemonic back to its source entropy.

    Validates the BIP-39 checksum: a corrupt or mistyped phrase raises
    ``ValueError`` rather than silently returning garbage.
    """
    from mnemonic import Mnemonic
    mnemo = Mnemonic(language)
    phrase = " ".join(w.strip().lower() for w in words)
    if not mnemo.check(phrase):
        raise ValueError("invalid BIP-39 mnemonic (bad checksum or word)")
    return bytes(mnemo.to_entropy(phrase))
