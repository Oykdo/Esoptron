"""Generate cross-language test vectors for the Esoptron enrollment crypto.

This is the **single source of truth** that the TypeScript port in
``pwa/src/lib/enrollment.ts`` must reproduce byte-for-byte. Whenever the
Python implementation changes, regenerate the vectors and the TS unit
tests will detect any drift.

Usage
-----
    py scripts/gen_test_vectors.py [--out pwa/src/lib/__tests__/vectors.json]

The output JSON has the shape::

    {
      "card_fingerprint": [{"symbols": [...], "expected_hex": "..."}, ...],
      "enroll_from_card":  [
          {
              "symbols": [...],
              "device_entropy_hex": "...",
              "expected": {
                  "vault_fp_hex": "...",
                  "device_secret_hex": "...",
                  "enrollment_fp_hex": "...",
                  "public_tag_hex": "...",
                  "shadow_hologram_hex": "..."
              }
          },
          ...
      ],
      "hkdf_sha3_512":    [{"ikm_hex": "...", "salt_hex": "...",
                            "info_hex": "...", "length": N,
                            "expected_hex": "..."}, ...]
    }

The vectors are deterministic: a fixed PRNG seed produces the same JSON
every run, so this file can be committed and reviewed.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure the in-repo src/ is importable when the package is not installed.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from eopx.format.keys import EopxKey  # noqa: E402
from eopx.format.shamir import _eval_poly  # noqa: E402
from eopx.genesis_token import (  # noqa: E402
    archetypes_commitment_hex,
    BTC_BLOCK_TARGET,
    derive_positions,
    mint_genesis_seal,
)
from eopx.metatron.field import hkdf_sha3_512  # noqa: E402
from eopx.recovery import (  # noqa: E402
    setup_recovery,
    recover_entropy,
    RecoveryCredentials,
)
from eopx.vault.enroll import enroll_from_card  # noqa: E402
from eopx.vault.genesis import entropy_to_recovery_phrase  # noqa: E402
from eopx.vault.verify_card import card_fingerprint  # noqa: E402


def _rand_symbols(rng: random.Random) -> List[int]:
    return [rng.randrange(0, 13) for _ in range(91)]


def _rand_bytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(0, 256) for _ in range(n))


def gen_card_fingerprint_vectors(rng: random.Random,
                                  n: int = 8) -> List[Dict[str, Any]]:
    out = []
    for _ in range(n):
        symbols = _rand_symbols(rng)
        fp = card_fingerprint(symbols)
        out.append({"symbols": symbols, "expected_hex": fp.hex()})
    return out


def gen_enroll_vectors(rng: random.Random,
                        n: int = 6) -> List[Dict[str, Any]]:
    out = []
    for _ in range(n):
        symbols = _rand_symbols(rng)
        entropy = _rand_bytes(rng, 32)
        rec = enroll_from_card(symbols, device_entropy=entropy)
        out.append({
            "symbols": symbols,
            "device_entropy_hex": entropy.hex(),
            "expected": {
                "vault_fp_hex": rec.vault_fp.hex(),
                "device_secret_hex": rec.device_secret.hex(),
                "enrollment_fp_hex": rec.enrollment_fp.hex(),
                "public_tag_hex": rec.public_tag.hex(),
                "shadow_hologram_hex": rec.shadow_hologram.hex(),
            },
        })
    return out


def gen_bip39_vectors(rng: random.Random,
                       n: int = 5) -> List[Dict[str, Any]]:
    """BIP-39 round-trip vectors at all supported entropy lengths."""
    out = []
    # All 5 valid BIP-39 entropy lengths.
    lengths = [16, 20, 24, 28, 32]
    for _ in range(n):
        size = rng.choice(lengths)
        entropy = _rand_bytes(rng, size)
        words = entropy_to_recovery_phrase(entropy)
        out.append({
            "entropy_hex": entropy.hex(),
            "words": words,
        })
    return out


def _shamir_split_with_coeffs(secret: bytes, k: int, n: int,
                                coeffs: List[List[int]]) -> List[List[int]]:
    """Shamir split using caller-supplied non-constant coefficients.

    ``coeffs[pos][j]`` is the j-th coefficient (j in 1..k-1) for byte
    position ``pos``. The constant coefficient is the secret byte. This
    is the deterministic kernel that both the Python and TypeScript
    implementations must reproduce bit-for-bit.

    Returns a list of n share-byte-lists (each of length len(secret)).
    """
    L = len(secret)
    shares: List[List[int]] = [[0] * L for _ in range(n)]
    for pos in range(L):
        poly = [secret[pos]] + list(coeffs[pos])
        assert len(poly) == k
        for i in range(1, n + 1):
            shares[i - 1][pos] = _eval_poly(poly, i)
    return shares


def gen_shamir_vectors(rng: random.Random,
                        n_vectors: int = 6) -> List[Dict[str, Any]]:
    """Deterministic Shamir vectors with explicit non-constant coefficients."""
    out = []
    for _ in range(n_vectors):
        L = rng.choice([1, 16, 32, 48])
        k = rng.choice([2, 3])
        n = rng.choice([k, k + 1, max(k + 1, k + 2)])
        if n > 8:
            n = 8
        secret = _rand_bytes(rng, L)
        # k-1 random coefficients per byte position
        coeffs = [
            [rng.randrange(0, 256) for _ in range(k - 1)]
            for _ in range(L)
        ]
        shares = _shamir_split_with_coeffs(secret, k, n, coeffs)
        out.append({
            "secret_hex": secret.hex(),
            "k": k, "n": n,
            "coeffs": coeffs,  # [[c1, c2, ...], ...] per position
            "shares": [
                {"index": i + 1, "bytes_hex": bytes(s).hex()}
                for i, s in enumerate(shares)
            ],
        })
    return out


def gen_recovery_vectors(rng: random.Random,
                          n_vectors: int = 3) -> List[Dict[str, Any]]:
    """Cross-language ``RecoveryPackage`` vectors.

    Each vector contains:
    * ``entropy_hex`` — the original device entropy (the secret)
    * ``card_pin`` — PIN string (>=4 chars)
    * ``cloud_passphrase`` — passphrase string
    * ``contact_pk_hex`` / ``contact_sk_hex`` — Kyber keypair so TS
      tests can both encapsulate-side check and decapsulate-side check
    * ``package`` — full JSON RecoveryPackage produced by ``setup_recovery``

    The TS test loads each vector, decrypts the package with the
    supplied credentials, and verifies the combined entropy matches
    ``entropy_hex``.  Since Argon2id, ChaCha20-Poly1305 and ML-KEM are
    all deterministic given inputs, this is a strict equality test.
    """
    out: List[Dict[str, Any]] = []
    for _ in range(n_vectors):
        entropy = _rand_bytes(rng, 32)
        pin = "".join(str(rng.randrange(0, 10)) for _ in range(6))
        # Use a long passphrase made of english letters
        passphrase = " ".join(
            "".join(chr(rng.randrange(ord("a"), ord("z") + 1))
                     for _ in range(rng.randrange(4, 9)))
            for _ in range(4)
        )
        contact = EopxKey.generate()
        pkg = setup_recovery(
            entropy,
            card_pin=pin,
            contact_kyber_pk=contact.kyber_pk,
            cloud_passphrase=passphrase,
            vault_fp_hex="ee" * 32,
        )
        # Sanity: confirm we can ourselves recover via PIN+passphrase
        assert recover_entropy(pkg, RecoveryCredentials(
            card_pin=pin, cloud_passphrase=passphrase,
        )) == entropy
        # And via Kyber+passphrase
        assert recover_entropy(pkg, RecoveryCredentials(
            contact_kyber_sk=contact.kyber_sk,
            cloud_passphrase=passphrase,
        )) == entropy

        out.append({
            "entropy_hex": entropy.hex(),
            "card_pin": pin,
            "cloud_passphrase": passphrase,
            "contact_pk_hex": contact.kyber_pk.hex(),
            "contact_sk_hex": contact.kyber_sk.hex(),
            "package": pkg.to_dict(),
        })
    return out


def gen_genesis_vectors(rng: random.Random,
                         n_vectors: int = 3) -> Dict[str, Any]:
    """Genesis Token cross-language vectors.

    Each derivation vector fixes a Bitcoin block hash and height, and
    records the expected 88 positions. The TS port re-derives and must
    match exactly.

    A single seal vector ships a Dilithium-signed Genesis seal so the
    TS verifier proves interop with ``pqcrypto.sign.ml_dsa_87``.
    """
    derivations: List[Dict[str, Any]] = []
    for _ in range(n_vectors):
        block_hash = _rand_bytes(rng, 32)
        height = rng.randrange(700_000, 1_100_000)
        positions = derive_positions(block_hash, btc_block_height=height)
        derivations.append({
            "btc_block_hash_hex": block_hash.hex(),
            "btc_block_height": height,
            "positions": positions,
        })

    # Seal vector — use a fixed block hash + deterministic-ish height
    deployment_key = EopxKey.generate()
    block_hash = _rand_bytes(rng, 32)
    height = BTC_BLOCK_TARGET
    positions = derive_positions(block_hash, btc_block_height=height)
    vault_fp = _rand_bytes(rng, 32)
    # Pick the 12th genesis vault → archetype id 11 ("Crown of Earth")
    seq = positions[11]
    seal = mint_genesis_seal(
        vault_fp=vault_fp, sequence=seq,
        btc_block_hash=block_hash, btc_block_height=height,
        positions=positions, deployment_key=deployment_key,
    )
    return {
        "archetypes_commitment_hex": archetypes_commitment_hex(),
        "derivations": derivations,
        "seal": {
            "deployment_pk_hex": deployment_key.dilithium_pk.hex(),
            "btc_block_hash_hex": block_hash.hex(),
            "btc_block_height": height,
            "positions": positions,
            "seal": seal.to_dict(),
        },
    }


def gen_hkdf_vectors(rng: random.Random,
                      n: int = 6) -> List[Dict[str, Any]]:
    """Direct HKDF-SHA3-512 vectors for low-level parity."""
    out = []
    for _ in range(n):
        ikm = _rand_bytes(rng, rng.randrange(16, 64))
        salt = _rand_bytes(rng, rng.randrange(0, 32))
        info = _rand_bytes(rng, rng.randrange(0, 32))
        length = rng.choice([16, 32, 48, 64, 96, 128])
        okm = hkdf_sha3_512(ikm=ikm, salt=salt, info=info, length=length)
        out.append({
            "ikm_hex": ikm.hex(),
            "salt_hex": salt.hex(),
            "info_hex": info.hex(),
            "length": length,
            "expected_hex": okm.hex(),
        })
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path,
        default=Path(__file__).resolve().parents[1]
        / "pwa" / "src" / "lib" / "__tests__" / "vectors.json",
        help="output path for the JSON test vectors",
    )
    parser.add_argument("--seed", type=int, default=0xE0EBE0,
                         help="PRNG seed (deterministic output)")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    vectors: Dict[str, Any] = {
        "schema_version": 4,
        "seed": args.seed,
        "card_fingerprint": gen_card_fingerprint_vectors(rng),
        "enroll_from_card": gen_enroll_vectors(rng),
        "hkdf_sha3_512": gen_hkdf_vectors(rng),
        "bip39": gen_bip39_vectors(rng),
        "shamir": gen_shamir_vectors(rng),
        "genesis": gen_genesis_vectors(rng),
        # Recovery vectors last — they consume the most entropy from rng.
        "recovery": gen_recovery_vectors(rng),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(vectors, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.out} ({sum(len(v) for v in vectors.values() if isinstance(v, list))} vectors total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
