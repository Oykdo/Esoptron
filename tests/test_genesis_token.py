"""Genesis Token — derivation, sealing, verification, tamper-resistance."""

from __future__ import annotations

import hashlib
import json

import pytest

from eopx.format.keys import EopxKey
from eopx.genesis_token import (
    BTC_BLOCK_TARGET,
    GENESIS_SEAL_SIGNED_FIELDS,
    GENESIS_SEAL_UNSIGNED_FIELDS,
    GENESIS_WINDOW,
    GenesisSeal,
    LATTICE_ELEMENTS,
    LATTICE_PATTERNS,
    SCHEMA_VERSION,
    TOTAL_GENESIS,
    all_archetypes,
    archetype_for_sequence,
    archetype_of,
    archetypes_commitment_hex,
    derive_positions,
    genesis_commitment,
    INSCRIPTION_MAX_MOTTO_BYTES,
    INSCRIPTION_MAX_NAME_BYTES,
    Inscription,
    is_genesis,
    mint_genesis_seal,
    verify_genesis_seal,
)


@pytest.fixture
def btc_hash() -> bytes:
    return bytes.fromhex(
        "00000000000000000001b9fd1a83c1c5d3e87f9b8a7c5e4f3d2a1b0987654321"
    )


@pytest.fixture
def positions(btc_hash) -> list:
    return derive_positions(btc_hash)


@pytest.fixture
def deployment_key() -> EopxKey:
    return EopxKey.generate()


# ---------------------------------------------------------------------------
# Archetype catalog
# ---------------------------------------------------------------------------

def test_lattice_dimensions():
    assert len(LATTICE_PATTERNS) == 22
    assert len(LATTICE_ELEMENTS) == 4
    assert TOTAL_GENESIS == 88
    assert len(all_archetypes()) == 88


def test_archetype_ids_are_unique_and_dense():
    archs = all_archetypes()
    ids = [a.id for a in archs]
    assert sorted(ids) == list(range(88))


def test_archetype_names_are_unique():
    archs = all_archetypes()
    names = [a.name for a in archs]
    assert len(set(names)) == 88


def test_archetype_of_round_trip():
    for i in range(TOTAL_GENESIS):
        assert archetype_of(i).id == i


def test_archetype_of_rejects_out_of_range():
    with pytest.raises(ValueError):
        archetype_of(-1)
    with pytest.raises(ValueError):
        archetype_of(TOTAL_GENESIS)


def test_archetypes_commitment_is_stable():
    # The catalog is frozen; the commitment hash should not change.
    a = archetypes_commitment_hex()
    b = archetypes_commitment_hex()
    assert a == b
    assert len(a) == 64  # 32-byte SHA3-256


# ---------------------------------------------------------------------------
# Position derivation
# ---------------------------------------------------------------------------

def test_positions_count_and_range(positions):
    assert len(positions) == TOTAL_GENESIS
    assert len(set(positions)) == TOTAL_GENESIS  # all distinct
    assert all(1 <= p <= GENESIS_WINDOW for p in positions)
    assert positions == sorted(positions)


def test_positions_deterministic(btc_hash):
    assert derive_positions(btc_hash) == derive_positions(btc_hash)


def test_positions_change_when_block_changes(btc_hash):
    other = bytes(b ^ 1 for b in btc_hash)
    assert derive_positions(other) != derive_positions(btc_hash)


def test_positions_change_when_height_changes(btc_hash):
    p1 = derive_positions(btc_hash, btc_block_height=900_000)
    p2 = derive_positions(btc_hash, btc_block_height=900_001)
    assert p1 != p2


def test_positions_rejects_wrong_hash_length():
    with pytest.raises(ValueError):
        derive_positions(b"\x00" * 31)


def test_positions_total_must_be_reasonable():
    with pytest.raises(ValueError):
        derive_positions(b"\x00" * 32, total=0)
    with pytest.raises(ValueError):
        derive_positions(b"\x00" * 32, total=10, window=5)


def test_positions_distributed_across_window(positions):
    # 88 picks in a window of 333,333 should spread roughly evenly.
    # Check at least one position in each quintile.
    q = GENESIS_WINDOW // 5
    bins = [0, 0, 0, 0, 0]
    for p in positions:
        bins[min(4, p // q)] += 1
    assert all(b > 0 for b in bins), f"distribution gap: {bins}"


# ---------------------------------------------------------------------------
# Sequence detection
# ---------------------------------------------------------------------------

def test_is_genesis_hits_each_position(positions):
    for p in positions:
        assert is_genesis(p, positions)


def test_is_genesis_misses_non_positions(positions):
    # Pick 50 random non-positions
    bag = set(positions)
    cnt = 0
    for cand in range(1, GENESIS_WINDOW + 1):
        if cand in bag:
            continue
        assert not is_genesis(cand, positions)
        cnt += 1
        if cnt >= 50:
            break


def test_archetype_assignment_matches_sorted_order(positions):
    sorted_pos = sorted(positions)
    for rank, p in enumerate(sorted_pos):
        arch = archetype_for_sequence(p, positions)
        assert arch is not None
        assert arch.id == rank


def test_archetype_assignment_none_for_non_genesis(positions):
    bag = set(positions)
    cand = next(c for c in range(1, GENESIS_WINDOW) if c not in bag)
    assert archetype_for_sequence(cand, positions) is None


# ---------------------------------------------------------------------------
# Seal mint / verify round-trip
# ---------------------------------------------------------------------------

def test_seal_round_trip(deployment_key, positions, btc_hash):
    vault_fp = bytes(32)
    N = positions[42]
    seal = mint_genesis_seal(
        vault_fp=vault_fp, sequence=N,
        btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
        positions=positions, deployment_key=deployment_key,
    )
    assert seal.schema_version == SCHEMA_VERSION
    assert seal.vault_fp_hex == vault_fp.hex()
    assert seal.sequence == N
    assert verify_genesis_seal(
        seal, deployment_pk=deployment_key.dilithium_pk,
        positions=positions,
    )


def test_mint_rejects_non_genesis_sequence(deployment_key, positions, btc_hash):
    bag = set(positions)
    non_genesis = next(c for c in range(1, GENESIS_WINDOW) if c not in bag)
    with pytest.raises(ValueError, match="not a Genesis position"):
        mint_genesis_seal(
            vault_fp=bytes(32), sequence=non_genesis,
            btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
            positions=positions, deployment_key=deployment_key,
        )


def test_verify_rejects_wrong_pk(deployment_key, positions, btc_hash):
    other = EopxKey.generate()
    seal = mint_genesis_seal(
        vault_fp=bytes(32), sequence=positions[0],
        btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
        positions=positions, deployment_key=deployment_key,
    )
    # signer_pk_fp won't match other.dilithium_pk
    assert not verify_genesis_seal(
        seal, deployment_pk=other.dilithium_pk, positions=positions,
    )


def test_verify_rejects_tampered_archetype(deployment_key, positions, btc_hash):
    seal = mint_genesis_seal(
        vault_fp=bytes(32), sequence=positions[5],
        btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
        positions=positions, deployment_key=deployment_key,
    )
    seal.archetype_id = (seal.archetype_id + 1) % 88
    assert not verify_genesis_seal(
        seal, deployment_pk=deployment_key.dilithium_pk, positions=positions,
    )


def test_verify_rejects_tampered_vault_fp(deployment_key, positions, btc_hash):
    seal = mint_genesis_seal(
        vault_fp=bytes(32), sequence=positions[5],
        btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
        positions=positions, deployment_key=deployment_key,
    )
    seal.vault_fp_hex = "ff" * 32
    assert not verify_genesis_seal(
        seal, deployment_pk=deployment_key.dilithium_pk, positions=positions,
    )


def test_verify_rejects_tampered_signature(deployment_key, positions,
                                              btc_hash):
    seal = mint_genesis_seal(
        vault_fp=bytes(32), sequence=positions[5],
        btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
        positions=positions, deployment_key=deployment_key,
    )
    bad = bytearray(bytes.fromhex(seal.signature_hex))
    bad[10] ^= 0xff
    seal.signature_hex = bytes(bad).hex()
    assert not verify_genesis_seal(
        seal, deployment_pk=deployment_key.dilithium_pk, positions=positions,
    )


def test_verify_rejects_wrong_btc_block(deployment_key, positions, btc_hash):
    seal = mint_genesis_seal(
        vault_fp=bytes(32), sequence=positions[5],
        btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
        positions=positions, deployment_key=deployment_key,
    )
    seal.btc_block_hash_hex = bytes(32).hex()
    assert not verify_genesis_seal(
        seal, deployment_pk=deployment_key.dilithium_pk, positions=positions,
    )


def test_seal_json_round_trip(deployment_key, positions, btc_hash):
    seal = mint_genesis_seal(
        vault_fp=bytes(32), sequence=positions[1],
        btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
        positions=positions, deployment_key=deployment_key,
    )
    s = seal.to_json()
    restored = GenesisSeal.from_dict(json.loads(s))
    assert restored == seal
    assert verify_genesis_seal(
        restored, deployment_pk=deployment_key.dilithium_pk,
        positions=positions,
    )


def test_from_dict_rejects_wrong_schema_version(deployment_key, positions,
                                                  btc_hash):
    seal = mint_genesis_seal(
        vault_fp=bytes(32), sequence=positions[0],
        btc_block_hash=btc_hash, btc_block_height=BTC_BLOCK_TARGET,
        positions=positions, deployment_key=deployment_key,
    )
    d = seal.to_dict()
    d["schema_version"] = 999
    with pytest.raises(ValueError, match="schema_version"):
        GenesisSeal.from_dict(d)


# ---------------------------------------------------------------------------
# Commitment
# ---------------------------------------------------------------------------

def test_commitment_includes_required_fields(deployment_key):
    c = genesis_commitment(deployment_key.dilithium_pk)
    for f in [
        "schema_version", "domain", "info_positions", "info_seal",
        "btc_block_height", "total_genesis", "genesis_window",
        "total_vaults", "deployment_pk_fp_hex", "archetypes_root",
    ]:
        assert f in c
    assert c["total_genesis"] == TOTAL_GENESIS
    assert c["genesis_window"] == GENESIS_WINDOW
    assert c["deployment_pk_fp_hex"] == hashlib.sha3_256(
        deployment_key.dilithium_pk).hexdigest()


def test_genesis_seal_canonical_fields_enumeration():
    """Contract test: every dataclass field is either signed or explicitly unsigned.

    If this fails, a new field was added to ``GenesisSeal`` without updating
    the canonical ``GENESIS_SEAL_SIGNED_FIELDS`` / ``GENESIS_SEAL_UNSIGNED_FIELDS``
    tuples — a silent signing-compatibility break waiting to happen.
    """
    import dataclasses
    dataclass_fields = {f.name for f in dataclasses.fields(GenesisSeal)}
    enumerated = set(GENESIS_SEAL_SIGNED_FIELDS) | set(GENESIS_SEAL_UNSIGNED_FIELDS)
    assert dataclass_fields == enumerated, (
        f"GenesisSeal fields {sorted(dataclass_fields)} drift from "
        f"signed+unsigned tuples {sorted(enumerated)}"
    )
    assert set(GENESIS_SEAL_SIGNED_FIELDS).isdisjoint(
        set(GENESIS_SEAL_UNSIGNED_FIELDS)
    )


# ---------------------------------------------------------------------------
# Inscription — engrave a human-readable name + date into the signed seal.
# ---------------------------------------------------------------------------


@pytest.fixture
def inscription_alice() -> Inscription:
    return Inscription(
        name="Alice's Vault",
        issued_at="2026-05-29T22:14:36Z",
        motto="Custodes mei",
    )


class TestInscription:
    def test_validates_name_required(self):
        with pytest.raises(ValueError, match="name"):
            Inscription(name="", issued_at="2026-05-29T22:14:36Z")

    def test_validates_issued_at_format(self):
        with pytest.raises(ValueError, match="issued_at"):
            Inscription(name="x", issued_at="May 29 2026")
        with pytest.raises(ValueError, match="issued_at"):
            Inscription(name="x", issued_at="2026-05-29T22:14:36+02:00")

    def test_validates_name_length(self):
        too_long = "a" * (INSCRIPTION_MAX_NAME_BYTES + 1)
        with pytest.raises(ValueError, match="name too long"):
            Inscription(name=too_long, issued_at="2026-05-29T22:14:36Z")

    def test_validates_motto_length(self):
        too_long = "m" * (INSCRIPTION_MAX_MOTTO_BYTES + 1)
        with pytest.raises(ValueError, match="motto too long"):
            Inscription(
                name="ok",
                issued_at="2026-05-29T22:14:36Z",
                motto=too_long,
            )

    def test_fingerprint_deterministic(self, inscription_alice):
        fp1 = inscription_alice.fingerprint()
        fp2 = Inscription(
            name="Alice's Vault",
            issued_at="2026-05-29T22:14:36Z",
            motto="Custodes mei",
        ).fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 32

    def test_fingerprint_changes_with_any_field(self, inscription_alice):
        base = inscription_alice.fingerprint()
        # Changing each field individually must change the hash.
        assert Inscription(
            name="Bob's Vault",
            issued_at=inscription_alice.issued_at,
            motto=inscription_alice.motto,
        ).fingerprint() != base
        assert Inscription(
            name=inscription_alice.name,
            issued_at="2027-01-01T00:00:00Z",
            motto=inscription_alice.motto,
        ).fingerprint() != base
        assert Inscription(
            name=inscription_alice.name,
            issued_at=inscription_alice.issued_at,
            motto="Different motto",
        ).fingerprint() != base

    def test_canonical_bytes_uses_length_prefix(self):
        # "ab" + "cd" must hash differently from "a" + "bcd" — length prefixes
        # are what prevent the ambiguity.
        a = Inscription(name="ab", issued_at="2026-05-29T22:14:36Z", motto="cd")
        b = Inscription(name="a", issued_at="2026-05-29T22:14:36Z", motto="bcd")
        assert a.fingerprint() != b.fingerprint()

    def test_roundtrip_dict(self, inscription_alice):
        d = inscription_alice.to_dict()
        restored = Inscription.from_dict(d)
        assert restored == inscription_alice


class TestSealWithInscription:
    def test_mint_with_inscription_verifies(
        self, btc_hash, positions, deployment_key, inscription_alice
    ):
        seal = mint_genesis_seal(
            vault_fp=b"\xee" * 32,
            sequence=positions[0],
            btc_block_hash=btc_hash,
            btc_block_height=BTC_BLOCK_TARGET,
            positions=positions,
            deployment_key=deployment_key,
            inscription=inscription_alice,
        )
        assert seal.inscription == inscription_alice
        assert seal.inscription_fp_hex == inscription_alice.fingerprint().hex()
        assert verify_genesis_seal(
            seal,
            deployment_pk=deployment_key.dilithium_pk,
            positions=positions,
        )

    def test_tampered_name_breaks_signature(
        self, btc_hash, positions, deployment_key, inscription_alice
    ):
        seal = mint_genesis_seal(
            vault_fp=b"\xee" * 32,
            sequence=positions[0],
            btc_block_hash=btc_hash,
            btc_block_height=BTC_BLOCK_TARGET,
            positions=positions,
            deployment_key=deployment_key,
            inscription=inscription_alice,
        )
        # Replace inscription with a forged name; signature must reject.
        seal.inscription = Inscription(
            name="Eve's Vault",
            issued_at=inscription_alice.issued_at,
            motto=inscription_alice.motto,
        )
        assert not verify_genesis_seal(
            seal,
            deployment_pk=deployment_key.dilithium_pk,
            positions=positions,
        )

    def test_tampered_date_breaks_signature(
        self, btc_hash, positions, deployment_key, inscription_alice
    ):
        seal = mint_genesis_seal(
            vault_fp=b"\xee" * 32,
            sequence=positions[0],
            btc_block_hash=btc_hash,
            btc_block_height=BTC_BLOCK_TARGET,
            positions=positions,
            deployment_key=deployment_key,
            inscription=inscription_alice,
        )
        seal.inscription = Inscription(
            name=inscription_alice.name,
            issued_at="2027-01-01T00:00:00Z",
            motto=inscription_alice.motto,
        )
        assert not verify_genesis_seal(
            seal,
            deployment_pk=deployment_key.dilithium_pk,
            positions=positions,
        )

    def test_removing_inscription_breaks_signature(
        self, btc_hash, positions, deployment_key, inscription_alice
    ):
        seal = mint_genesis_seal(
            vault_fp=b"\xee" * 32,
            sequence=positions[0],
            btc_block_hash=btc_hash,
            btc_block_height=BTC_BLOCK_TARGET,
            positions=positions,
            deployment_key=deployment_key,
            inscription=inscription_alice,
        )
        seal.inscription = None
        assert not verify_genesis_seal(
            seal,
            deployment_pk=deployment_key.dilithium_pk,
            positions=positions,
        )

    def test_adding_inscription_after_mint_breaks_signature(
        self, btc_hash, positions, deployment_key, inscription_alice
    ):
        # Mint WITHOUT inscription, then try to graft one in post-hoc.
        seal = mint_genesis_seal(
            vault_fp=b"\xee" * 32,
            sequence=positions[0],
            btc_block_hash=btc_hash,
            btc_block_height=BTC_BLOCK_TARGET,
            positions=positions,
            deployment_key=deployment_key,
        )
        assert verify_genesis_seal(
            seal,
            deployment_pk=deployment_key.dilithium_pk,
            positions=positions,
        )
        seal.inscription = inscription_alice
        assert not verify_genesis_seal(
            seal,
            deployment_pk=deployment_key.dilithium_pk,
            positions=positions,
        )

    def test_legacy_seal_without_inscription_still_verifies(
        self, btc_hash, positions, deployment_key
    ):
        """Backward compat: minting WITHOUT inscription must produce the
        exact same signed bytes as before the feature landed.
        """
        seal = mint_genesis_seal(
            vault_fp=b"\xee" * 32,
            sequence=positions[0],
            btc_block_hash=btc_hash,
            btc_block_height=BTC_BLOCK_TARGET,
            positions=positions,
            deployment_key=deployment_key,
        )
        assert seal.inscription is None
        assert seal.inscription_fp_hex is None
        assert "inscription" not in seal.to_dict()
        assert "inscription_fp_hex" not in seal.to_dict()
        assert verify_genesis_seal(
            seal,
            deployment_pk=deployment_key.dilithium_pk,
            positions=positions,
        )

    def test_json_roundtrip_preserves_inscription(
        self, btc_hash, positions, deployment_key, inscription_alice
    ):
        from eopx.genesis_token import GenesisSeal
        seal = mint_genesis_seal(
            vault_fp=b"\xee" * 32,
            sequence=positions[0],
            btc_block_hash=btc_hash,
            btc_block_height=BTC_BLOCK_TARGET,
            positions=positions,
            deployment_key=deployment_key,
            inscription=inscription_alice,
        )
        blob = seal.to_json()
        restored = GenesisSeal.from_dict(json.loads(blob))
        assert restored.inscription == inscription_alice
        assert verify_genesis_seal(
            restored,
            deployment_pk=deployment_key.dilithium_pk,
            positions=positions,
        )

    def test_from_dict_rejects_corrupt_fp(
        self, btc_hash, positions, deployment_key, inscription_alice
    ):
        from eopx.genesis_token import GenesisSeal
        seal = mint_genesis_seal(
            vault_fp=b"\xee" * 32,
            sequence=positions[0],
            btc_block_hash=btc_hash,
            btc_block_height=BTC_BLOCK_TARGET,
            positions=positions,
            deployment_key=deployment_key,
            inscription=inscription_alice,
        )
        d = seal.to_dict()
        d["inscription_fp_hex"] = "00" * 32  # wrong hash
        with pytest.raises(ValueError, match="inscription_fp_hex"):
            GenesisSeal.from_dict(d)
