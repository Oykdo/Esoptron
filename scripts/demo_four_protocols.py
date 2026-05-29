"""End-to-end demonstration of the four vault protocols A, B, C, D.

Runs without a camera: simulates the photo pipeline by rendering a cube
and feeding it through extract_canonical (which is the exact same code
path the post-rectification photo would take).
"""

from __future__ import annotations

import hashlib
import os

from eopx.metatron import (
    encode_private, encode_public, render, extract_canonical,
)
from eopx.vault import (
    unlock_from_private_symbols,
    verify_card, card_fingerprint,
    new_challenge, respond, verify_response,
    enroll_from_card,
)


def line(c: str = "=", n: int = 72) -> None:
    print(c * n)


def main() -> int:
    line()
    print("  Esoptron / Metatron -- 4-protocol vault demo")
    line()
    print()

    # -------------------- A --------------------
    line("-")
    print("  PROTOCOL A : unlock from a PRIVATE sheet")
    line("-")
    seed = hashlib.sha3_256(b"demo.vault.alpha").digest()
    print(f"  seed       : {seed.hex()}")
    cw = encode_private(seed)
    img = render(cw, size=1024)
    syms, _d = extract_canonical(img)
    seed_back, master_key = unlock_from_private_symbols(syms)
    assert seed_back == seed
    print(f"  recovered  : {seed_back.hex()}")
    print(f"  master_key : {master_key.hex()}")
    print()

    # -------------------- B --------------------
    line("-")
    print("  PROTOCOL B : verify a PUBLIC card against a local vault")
    line("-")
    spinor = hashlib.sha3_512(b"demo.vault.alpha.public").digest()
    print(f"  spinor[:32]: {spinor[:32].hex()}")
    cw_pub = encode_public(spinor)
    img_pub = render(cw_pub, size=1024)
    scanned, _ = extract_canonical(img_pub)
    print(f"  card fp    : {card_fingerprint(scanned).hex()}")
    print(f"  verify_card(scanned, correct spinor) = {verify_card(scanned, spinor)}")
    wrong = hashlib.sha3_512(b"demo.vault.beta").digest()
    print(f"  verify_card(scanned, wrong  spinor) = {verify_card(scanned, wrong)}")
    print()

    # -------------------- C --------------------
    line("-")
    print("  PROTOCOL C : SAS challenge / response")
    line("-")
    vault_id = hashlib.sha3_256(spinor).digest()
    challenge = new_challenge(vault_id)
    print(f"  vault_id   : {vault_id.hex()}")
    print(f"  nonce      : {challenge.nonce.hex()}")
    resp = respond(scanned, spinor, challenge)
    session = verify_response(resp, spinor, scanned)
    assert session is not None
    print(f"  session_key: {session.hex()}")
    print()
    # Try replay with wrong card -> must fail
    other_spinor = hashlib.sha3_512(b"demo.vault.gamma").digest()
    other_card, _ = extract_canonical(render(encode_public(other_spinor), 1024))
    try:
        respond(other_card, spinor, challenge)
        raise SystemExit("SAS should have rejected the other card")
    except ValueError:
        print("  cross-card attack correctly rejected at respond().")
    print()

    # -------------------- D --------------------
    line("-")
    print("  PROTOCOL D : enrollment via phone scan (no PC)")
    line("-")
    # Same card scanned by two different phones with different entropy:
    e1 = b"\x01" * 32  # phone Alice
    e2 = b"\x02" * 32  # phone Bob
    rec_a = enroll_from_card(scanned, device_entropy=e1)
    rec_b = enroll_from_card(scanned, device_entropy=e2)
    print(f"  card_fp (shared)  : {rec_a.card_fp.hex()}")
    print(f"  Alice public_tag  : {rec_a.public_tag.hex()}")
    print(f"  Bob   public_tag  : {rec_b.public_tag.hex()}")
    print(f"  Alice hologram[:8]: {rec_a.shadow_hologram[:8].hex()}")
    print(f"  Bob   hologram[:8]: {rec_b.shadow_hologram[:8].hex()}")
    assert rec_a.card_fp == rec_b.card_fp
    assert rec_a.public_tag != rec_b.public_tag
    assert rec_a.shadow_hologram != rec_b.shadow_hologram
    print("  same card -> same fp, different identities, different holograms.")
    print()

    line()
    print("  All four protocols completed end to end.")
    line()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
