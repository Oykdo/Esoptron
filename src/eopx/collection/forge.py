"""Forge — assemble a Codex relic into a badge .eopx + titled artifact.

Given a :class:`~eopx.collection.Relic` and an issuer key, this produces the
three bound objects that *are* the relic:

1. a **Metatron badge** image (cube + EPX-H seal) rendered deterministically
   from the relic's spinor seed;
2. a **titled artifact** (EPX-T) whose ``content_commit`` binds the relic's
   lore, ready to be anchored at ``seq=0``;
3. an initial **controller** — either freshly generated (caller holds the
   secret) or, when a destination vault's ``device_secret`` is supplied,
   **sealed to that vault** (spec §8) so holding the vault wakes the relic.

The badge `.eopx` is bound to the artifact by carrying ``merkle_root =
SHA3-256(artifact_id || content_commit)`` in its signed manifest, so the
image, the lore, and the ledger identity are cryptographically linked.

This module performs no I/O and contacts no anchor; ``scripts/
forge_collection.py`` orchestrates disk output and the optional mint.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from PIL import Image

from ..format.keys import EopxKey
from ..metatron import encode_public, render_seal_revealed
from ..transfer import (
    SealedContent,
    TitledArtifact,
    bind_new_controller,
    generate_controller,
    mint_artifact,
)
from ..transfer.binding import SealedController
from . import Relic


def relic_vault_fp(relic: Relic) -> bytes:
    """32-byte fingerprint used to seed the badge's seal geometry."""
    return hashlib.sha3_256(relic.artifact_id()).digest()


def relic_merkle_root(relic: Relic) -> bytes:
    """32-byte link binding the badge image to the artifact + lore."""
    return hashlib.sha3_256(
        relic.artifact_id() + relic.content_commit()
    ).digest()


def render_relic_badge(relic: Relic, size: int = 1024) -> Image.Image:
    """Render the relic's Metatron cube + revealed seal, deterministically."""
    spinor = relic.spinor_seed()
    symbols = encode_public(spinor)
    return render_seal_revealed(
        symbols, relic_vault_fp(relic), spinor, size=size,
    )


@dataclass
class ForgedRelic:
    """In-memory result of forging one relic (no I/O performed)."""
    relic: Relic
    artifact: TitledArtifact
    sealed_content: SealedContent
    badge: Image.Image
    # Exactly one of these is set:
    controller: Optional[EopxKey] = None          # when no destination vault
    sealed_controller: Optional[SealedController] = None  # sealed to a vault

    @property
    def merkle_root(self) -> bytes:
        return relic_merkle_root(self.relic)


def forge_relic(
    relic: Relic,
    issuer: EopxKey,
    *,
    destination_device_secret: Optional[bytes] = None,
    badge_size: int = 1024,
) -> ForgedRelic:
    """Forge a relic into its bound badge + artifact + controller.

    Parameters
    ----------
    relic:
        The Codex relic to forge.
    issuer:
        The minting vault key (secret half required); signs the genesis
        record and (later, in the script) the badge ``.eopx``.
    destination_device_secret:
        The 32-byte ``device_secret`` of the vault that will own the relic.
        When given, the initial controller is **sealed to that vault** and
        ``sealed_controller`` is populated (``controller`` is ``None``).
        When omitted, a fresh controller is generated and returned in
        ``controller`` (useful for tests / issuer-held distribution).
    badge_size:
        Pixel side of the rendered badge.
    """
    aid = relic.artifact_id()

    controller: Optional[EopxKey]
    sealed_controller: Optional[SealedController]
    if destination_device_secret is not None:
        controller_full, sealed_controller = bind_new_controller(
            destination_device_secret, aid,
        )
        first_controller = controller_full.public_only()
        controller = None
    else:
        controller = generate_controller()
        sealed_controller = None
        first_controller = controller.public_only()

    artifact, sealed_content = mint_artifact(
        issuer, relic.artifact_type, first_controller,
        content=relic.lore_payload(), artifact_id=aid,
    )
    assert sealed_content is not None  # relics always carry lore content

    badge = render_relic_badge(relic, size=badge_size)

    return ForgedRelic(
        relic=relic,
        artifact=artifact,
        sealed_content=sealed_content,
        badge=badge,
        controller=controller,
        sealed_controller=sealed_controller,
    )


__all__ = [
    "relic_vault_fp",
    "relic_merkle_root",
    "render_relic_badge",
    "ForgedRelic",
    "forge_relic",
]
