"""Genesis card PNG renderer (Pillow) — payload + render smoke tests."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from PIL import Image

from eopx.format.keys import EopxKey
from eopx.genesis_card import (
    CARD_H,
    CARD_W,
    GenesisCardInputs,
    build_qr_payload,
    build_seal_envelope,
    render_genesis_card_png,
    write_genesis_card_png,
    write_genesis_seal_envelope,
)
from eopx.genesis_token import (
    TOTAL_GENESIS,
    archetype_for_sequence,
    archetype_of,
    archetypes_commitment_hex,
    derive_positions,
    mint_genesis_seal,
)


@pytest.fixture(scope="module")
def real_seal_inputs() -> GenesisCardInputs:
    """Build a real Dilithium5-signed seal so the renderer paths see
    the full byte sizes of signature + pubkey."""
    btc_hash = bytes.fromhex("ab" * 32)
    btc_height = 925_000
    positions = derive_positions(btc_hash, btc_block_height=btc_height)
    sequence = positions[0]
    archetype = archetype_for_sequence(sequence, positions)
    assert archetype is not None
    vault_fp = bytes.fromhex("fd83".ljust(64, "0"))
    deployment_key = EopxKey.generate()
    seal = mint_genesis_seal(
        vault_fp=vault_fp,
        sequence=sequence,
        btc_block_hash=btc_hash,
        btc_block_height=btc_height,
        positions=positions,
        deployment_key=deployment_key,
    )
    return GenesisCardInputs(
        vault_fp_hex=vault_fp.hex(),
        sequence=sequence,
        btc_block_hash_hex=btc_hash.hex(),
        btc_block_height=btc_height,
        deployment_pk_hex=deployment_key.dilithium_pk.hex(),
        genesis_seal=seal,
    )


class TestQrPayload:
    def test_payload_shape_matches_ts_contract(self, real_seal_inputs):
        payload = build_qr_payload(real_seal_inputs)
        assert payload["type"] == "esoptron-genesis-card"
        assert payload["schema_version"] == 1
        assert payload["sequence"] == real_seal_inputs.sequence
        assert payload["archetype_id"] == real_seal_inputs.genesis_seal.archetype_id
        assert payload["vault_fp_hex"] == real_seal_inputs.vault_fp_hex
        assert payload["archetypes_commitment_hex"] == archetypes_commitment_hex()

    def test_payload_excludes_signature_and_pk(self, real_seal_inputs):
        payload = build_qr_payload(real_seal_inputs)
        assert "signature_hex" not in payload
        assert "deployment_pk_hex" not in payload

    def test_payload_fits_under_500_bytes(self, real_seal_inputs):
        # Mirrors the TS-side ceiling so QR-Q remains achievable.
        json_str = json.dumps(build_qr_payload(real_seal_inputs))
        assert len(json_str) <= 500

    def test_payload_includes_anchor_url_when_provided(self, real_seal_inputs):
        inputs = GenesisCardInputs(
            **{**real_seal_inputs.__dict__,
               "anchor_url": "https://esoptron.app/api/v1"}
        )
        payload = build_qr_payload(inputs)
        assert payload["anchor_url"] == "https://esoptron.app/api/v1"


class TestSealEnvelope:
    def test_envelope_carries_signature_and_pk(self, real_seal_inputs):
        env = build_seal_envelope(real_seal_inputs)
        assert env["type"] == "esoptron-genesis-seal"
        assert env["signature_hex"] == real_seal_inputs.genesis_seal.signature_hex
        assert env["deployment_pk_hex"] == real_seal_inputs.deployment_pk_hex
        assert env["pointer"]["sequence"] == real_seal_inputs.sequence

    def test_envelope_size_matches_dilithium_payload(self, real_seal_inputs):
        env = build_seal_envelope(real_seal_inputs)
        json_str = json.dumps(env)
        # Dilithium5 sig 4627B + pk 2592B = 7219B → 14438 hex chars
        # plus framing → expect 14-19 KB.
        assert 14_000 < len(json_str) < 20_000


class TestArchetypeMismatch:
    def test_render_rejects_mismatched_archetype(self, real_seal_inputs):
        wrong_id = (
            real_seal_inputs.genesis_seal.archetype_id + 1
        ) % TOTAL_GENESIS
        wrong_arch = archetype_of(wrong_id)
        bad_inputs = GenesisCardInputs(
            **{**real_seal_inputs.__dict__, "archetype": wrong_arch}
        )
        with pytest.raises(ValueError, match="archetype.id does not match"):
            render_genesis_card_png(bad_inputs)


class TestRendering:
    def test_render_produces_valid_png(self, real_seal_inputs):
        data = render_genesis_card_png(real_seal_inputs)
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
        # Image dimensions
        img = Image.open(io.BytesIO(data))
        assert img.size == (CARD_W, CARD_H)
        assert img.mode == "RGB"

    def test_render_is_deterministic_for_same_inputs(self, real_seal_inputs):
        a = render_genesis_card_png(real_seal_inputs)
        b = render_genesis_card_png(real_seal_inputs)
        # PNG outputs may differ in CRC ordering, but image content
        # should be identical; compare via re-decoded pixels.
        ia = Image.open(io.BytesIO(a)).tobytes()
        ib = Image.open(io.BytesIO(b)).tobytes()
        assert ia == ib

    def test_write_genesis_card_png_creates_file(self, real_seal_inputs,
                                                    tmp_path: Path):
        target = tmp_path / "card.png"
        n = write_genesis_card_png(real_seal_inputs, str(target))
        assert target.exists()
        assert n > 5_000  # decent-size PNG
        img = Image.open(target)
        assert img.size == (CARD_W, CARD_H)

    def test_write_seal_envelope_creates_json(self, real_seal_inputs,
                                                tmp_path: Path):
        target = tmp_path / "seal.json"
        n = write_genesis_seal_envelope(real_seal_inputs, str(target))
        assert target.exists()
        assert n > 14_000
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["type"] == "esoptron-genesis-seal"
        assert data["pointer"]["sequence"] == real_seal_inputs.sequence


class TestPythonTsParity:
    def test_payload_keys_match_ts_contract(self, real_seal_inputs):
        # Frozen contract: the field names below MUST match the TS
        # genesisCard.ts buildGenesisQrPayload output.
        payload = build_qr_payload(real_seal_inputs)
        expected_keys = {
            "type", "schema_version", "vault_fp_hex", "sequence",
            "archetype_id", "btc_block_hash_hex", "btc_block_height",
            "signer_pk_fp_hex", "archetypes_commitment_hex",
        }
        assert set(payload.keys()) == expected_keys

    def test_envelope_keys_match_ts_contract(self, real_seal_inputs):
        env = build_seal_envelope(real_seal_inputs)
        assert set(env.keys()) == {
            "type", "schema_version", "pointer",
            "deployment_pk_hex", "signature_hex",
        }
