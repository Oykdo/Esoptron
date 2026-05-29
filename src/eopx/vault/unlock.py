"""Protocol A: unlock the vault directly from a PRIVATE Metatron sheet.

The printed sheet IS the secret. Scanning recovers the 256-bit seed via
RS decoding, then HKDF-SHA3-512 expands it into a per-vault master key.

Pipeline:
    photo  ->  rectify  ->  91 symbols  ->  decode_private  ->  seed_256
                                                                |
                                       HKDF-SHA3-512(info=...,  seed)
                                                                |
                                                                v
                                                        master_key (32 B)
"""

from __future__ import annotations

from typing import Iterable, Optional, Sequence, Tuple

from ..metatron import decode_private
from ..metatron.field import hkdf_sha3_512

# Domain separation strings. NEVER change without bumping the version byte
# of the mnemonic payload, otherwise old sheets will derive different keys.
INFO_MASTER = b"esoptron.vault.master_key.v1"
INFO_AUTH   = b"esoptron.vault.auth_subkey.v1"
INFO_ENC    = b"esoptron.vault.enc_subkey.v1"

MASTER_KEY_BYTES = 32


def derive_master_key(seed: bytes,
                      info: bytes = INFO_MASTER,
                      length: int = MASTER_KEY_BYTES) -> bytes:
    """Derive a vault master key from a 256-bit seed via HKDF-SHA3-512.

    The seed is the one reconstructed from a PRIVATE Metatron inscription.
    Splitting into subkeys (auth, enc) is left to the caller using the
    additional INFO_* constants exposed above.
    """
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return hkdf_sha3_512(ikm=seed, salt=b"", info=info, length=length)


def unlock_from_seed(seed: bytes) -> bytes:
    """Convenience wrapper: seed -> master_key."""
    return derive_master_key(seed)


def unlock_from_private_symbols(symbols: Sequence[int],
                                erasures: Optional[Iterable[int]] = None
                                ) -> Tuple[bytes, bytes]:
    """End-to-end: 91 F_13 symbols (private) -> (seed, master_key).

    Returns both so callers can rotate / re-encode without re-scanning.
    """
    if len(symbols) != 91:
        raise ValueError("symbols must have length 91")
    seed, _version = decode_private(symbols, erasures=erasures)
    master_key = derive_master_key(seed)
    return seed, master_key
