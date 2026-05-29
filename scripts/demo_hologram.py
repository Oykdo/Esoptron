"""Render three sample shadow-holograms to illustrate Protocol D.

Same issuer card, three different "device entropies" -> three visually
distinguishable holograms. This is what a user would see on their phone
when joining the ecosystem.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from eopx.metatron import encode_public, render, extract_canonical
from eopx.vault import enroll_from_card

# Local renderer for the hologram (same code as in enroll_from_card.py).
import sys as _sys
_SCRIPTS_DIR = Path(__file__).parent
if str(_SCRIPTS_DIR) not in _sys.path:
    _sys.path.insert(0, str(_SCRIPTS_DIR))
from enroll_from_card import render_shadow_hologram  # type: ignore


def main() -> int:
    out = Path("out")
    out.mkdir(parents=True, exist_ok=True)

    # 1 fake public card (= "welcome poster" of the ecosystem).
    spinor = hashlib.sha3_512(b"ecosystem.welcome.poster.v1").digest()
    card_symbols = encode_public(spinor)

    # The card itself (so the user can see it side by side).
    card_img = render(card_symbols, size=720)
    card_img.save(out / "demo_card.png", format="PNG")
    print(f"  card image : {out / 'demo_card.png'}")

    # Three users enrolling from the SAME card.
    users = {
        "alice": b"\x10" * 32,
        "bob":   b"\x20" * 32,
        "carol": b"\x30" * 32,
    }
    for name, e in users.items():
        rec = enroll_from_card(card_symbols, device_entropy=e)
        holo = render_shadow_hologram(rec.shadow_hologram, size=720)
        holo.save(out / f"demo_hologram_{name}.png", format="PNG")
        print(f"  {name:5s}  public_tag={rec.public_tag.hex()}  "
              f"hologram={out / f'demo_hologram_{name}.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
