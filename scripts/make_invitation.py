"""Generate an Esoptron invitation card.

Produces a deterministic invitation passphrase, derives the vault seed from
it, mints a Genesis seal with an engraved inscription (name + date + motto),
and emits a print-ready A4 PNG.

Usage::

    py scripts/make_invitation.py
    py scripts/make_invitation.py --name "Logos #001" --motto "In silentio mirror"
    py scripts/make_invitation.py --code GENESIS-ALPHA-001 --name "Founders"
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import secrets
import sys
from pathlib import Path

# Make sibling scripts importable for the layout primitives.
_SCRIPTS_DIR = Path(__file__).parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from eopx.format.keys import EopxKey
from eopx.genesis_token import (
    BTC_BLOCK_TARGET,
    GENESIS_WINDOW,
    Inscription,
    TOTAL_GENESIS,
    derive_positions,
    mint_genesis_seal,
)
from eopx.metatron import encode_private, encode_public
from print_sheet import make_sheet, DPI  # type: ignore  # noqa: E402


WORDS = [
    "ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON", "ZETA", "ETA", "THETA",
    "IOTA", "KAPPA", "LAMBDA", "SIGMA", "OMEGA", "PHI", "PSI", "CHI",
    "AURORA", "BOREALIS", "CELESTE", "DRAKE", "ECHO", "FOXTROT", "GENESIS",
    "HELIO", "INDIGO", "JULIET", "KILO", "LUMEN", "MIRROR", "NOVA",
    "ORACLE", "PRISM", "QUARTZ", "ROGUE", "SOLAR", "TANGO", "ULTRA",
    "VAULT", "WRAITH", "XENON", "YANKEE", "ZULU",
]


def generate_code() -> str:
    """Generate a memorable invitation code like ``ESPX-AURORA-MIRROR-7423``."""
    a = secrets.choice(WORDS)
    b = secrets.choice(WORDS)
    while b == a:
        b = secrets.choice(WORDS)
    digits = "".join(str(secrets.randbelow(10)) for _ in range(4))
    return f"ESPX-{a}-{b}-{digits}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--code", help="Invitation code (auto-generated if omitted).")
    ap.add_argument("--name", default="Esoptron Invitation",
                    help="Engraved on the seal (\u2264 128 bytes UTF-8).")
    ap.add_argument("--motto", default="In silentio, mirror",
                    help="Optional motto engraved on the seal.")
    ap.add_argument("--out-dir", default="out",
                    help="Where to write the A4 + seal JSON.")
    ap.add_argument("--btc-block-hash",
                    default="00000000000000000001b9fd1a83c1c5d3e87f9b8a7c5e4f3d2a1b0987654321",
                    help="BTC block hash hex (default: stable demo value).")
    ap.add_argument("--btc-block-height", type=int, default=BTC_BLOCK_TARGET,
                    help="BTC block height (default: configured target).")
    args = ap.parse_args()

    code = args.code or generate_code()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Deterministic seed + spinor from the invitation code so the same code
    # always re-produces the same vault if the user wants to regenerate.
    seed = hashlib.sha3_256(b"esoptron.invitation.v1|" + code.encode("utf-8")).digest()
    spinor = hashlib.sha3_512(b"esoptron.invitation.v1|" + code.encode("utf-8") + b"|spinor").digest()
    vault_fp = hashlib.sha3_256(b"esoptron.vault_fp.v1|" + seed).digest()

    # Pick a Genesis position deterministically from the code so the seal lands
    # on a real Genesis slot. We need a deployment key to sign the seal; for
    # the invitation it is generated on the fly and the public key is exposed
    # alongside the seal so the recipient can verify.
    btc_hash = bytes.fromhex(args.btc_block_hash)
    positions = derive_positions(
        btc_hash, total=TOTAL_GENESIS, window=GENESIS_WINDOW,
        btc_block_height=args.btc_block_height,
    )
    # Use the seed to pick which position this invitation occupies.
    sequence = positions[int.from_bytes(seed[:8], "big") % len(positions)]

    deployment_key = EopxKey.generate()

    issued_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    inscription = Inscription(
        name=args.name,
        issued_at=issued_at,
        motto=args.motto,
    )

    seal = mint_genesis_seal(
        vault_fp=vault_fp,
        sequence=sequence,
        btc_block_hash=btc_hash,
        btc_block_height=args.btc_block_height,
        positions=positions,
        deployment_key=deployment_key,
        inscription=inscription,
    )

    # ---- Render the A4 ----
    # Layout-sensitive: keep `extra_lines` to <= 2 entries so the chromatic
    # scan grid still fits above the WARNING strip (see make_sheet logic).
    cw_priv = encode_private(seed)
    label = f"{code}  |  {inscription.name}  |  {issued_at}"
    extra_lines = [
        f"motto: {inscription.motto}  |  seq: {sequence}  |  arch: {seal.archetype_id}",
        f"insc_fp: {seal.inscription_fp_hex}",
    ]
    sheet = make_sheet(
        cw_priv, role="private",
        label=label,
        hash_hex=seed.hex(),
        extra_lines=extra_lines,
    )

    safe_code = code.replace("-", "_")
    out_a4 = out / f"invitation_{safe_code}_A4.png"
    sheet.save(out_a4, format="PNG", dpi=(DPI, DPI), optimize=False)

    # ---- Also emit the matching PUBLIC card and the seal JSON ----
    cw_pub = encode_public(spinor)
    sheet_pub = make_sheet(
        cw_pub, role="public",
        label=label,
        hash_hex=spinor.hex(),
        extra_lines=extra_lines,
    )
    out_a4_pub = out / f"invitation_{safe_code}_PUBLIC_A4.png"
    sheet_pub.save(out_a4_pub, format="PNG", dpi=(DPI, DPI), optimize=False)

    bundle = {
        "code": code,
        "issued_at": issued_at,
        "vault_fp_hex": vault_fp.hex(),
        "seed_hex": seed.hex(),
        "spinor_hex": spinor.hex(),
        "deployment_pk_hex": deployment_key.dilithium_pk.hex(),
        "deployment_kyber_pk_hex": deployment_key.kyber_pk.hex(),
        "seal": seal.to_dict(),
    }
    out_json = out / f"invitation_{safe_code}.json"
    out_json.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    # ---- Summary ----
    bar = "=" * 72
    print(bar)
    print(f"  ESOPTRON INVITATION  -  {code}")
    print(bar)
    print(f"  name           : {inscription.name}")
    print(f"  motto          : {inscription.motto}")
    print(f"  issued_at      : {issued_at}")
    print(f"  vault_fp       : {vault_fp.hex()}")
    print(f"  sequence       : {sequence}  (Genesis)")
    print(f"  archetype_id   : {seal.archetype_id}")
    print(f"  inscription_fp : {seal.inscription_fp_hex}")
    print()
    print(f"  PRIVATE A4     : {out_a4}")
    print(f"  PUBLIC  A4     : {out_a4_pub}")
    print(f"  seal bundle    : {out_json}")
    print()
    print("Next steps:")
    print(f"  1. Open: explorer.exe {out_a4}")
    print("  2. Print at 100 % scale, A4 white paper, no margins fit-to-page.")
    print("  3. Verify the 10 mm scale bar with a ruler after printing.")
    print("  4. Photograph or scan; or run live_scan.py to capture via webcam.")
    print()
    print("Share the PRIVATE card only with the intended recipient -- it")
    print("reconstructs a 256-bit seed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
