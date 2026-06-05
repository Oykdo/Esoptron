"""The Esoptron Codex — a curated collection of titled relics (EPX-C).

EPX-T artifacts are unbounded by design; a *collection* is a curated,
frozen subset with names, lore, and fixed identities. The **Codex** is the
first such collection: **twelve relics**, each bound to a real mechanism of
the system and echoing a known myth without borrowing its IP (the mirror
reflects what you bring — POSITIONING).

Distribution is **deterministic and publicly verifiable**, derived from the
same Genesis Bitcoin block as the 88 archetype positions:

* relics of rank 1–3 (the *primordial trio*) go to vaults **#1, #2, #3** —
  the founder intent, stated plainly;
* relics of rank 4–12 land on nine positions in ``[4, 1000]`` derived from
  the block hash via :func:`eopx.genesis_token.derive_positions`, so no one
  can hand-pick who receives them.

This module is **pure**: it defines the catalog, the distribution, and a
tamper-evident commitment over the lore. It holds no keys and mints
nothing — the forge (``scripts/forge_collection.py``) orchestrates minting
against an anchor, sealing each relic's initial controller to the
destination vault (see :mod:`eopx.transfer.binding`).

The lore text is content, not law; the **commitment** (:func:`catalog_commitment_hex`)
freezes the immutable identity fields (rank, key, name, element, myth echo)
so a relic's identity cannot drift after publication.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..genesis_token import BTC_BLOCK_TARGET, derive_positions

CODEX_VERSION = 2
CODEX_DOMAIN = b"esoptron.codex.v1"  # frozen derivation domain (artifact_ids stable across versions)

# The founder slots: the primordial trio is placed here, by rank.
FOUNDER_SLOTS = (1, 2, 3)
# The window the remaining relics are distributed across.
DISTRIBUTION_WINDOW = 1000

# Per-element default seal hue (degrees on the colour wheel), echoing the
# fire/water/air/earth palette already used by the 88 archetypes.
ELEMENT_HUE = {"Fire": 8, "Water": 210, "Air": 48, "Earth": 132}


@dataclass(frozen=True)
class Relic:
    """One titled relic: immutable identity + curatable lore.

    The *identity* fields (``rank``, ``key``, ``name``, ``element``,
    ``myth_echo``) are frozen by :func:`catalog_commitment_hex`. The
    ``lore`` / ``lore_fr`` fields are presentation and may be translated or
    refined without breaking the commitment — they are intentionally
    excluded from the committed bytes.
    """
    rank: int                 # 1..7, stable ordering
    key: str                  # slug, stable identifier
    name: str                 # Latin / evocative title
    title: str                # short English subtitle
    element: str              # Fire | Water | Air | Earth
    myth_echo: str            # the legend it rhymes with (not copied)
    mechanism: str            # the real system mechanic it embodies
    lore: str                 # English lore (presentation)
    lore_fr: str = ""         # French lore (presentation)

    @property
    def artifact_type(self) -> str:
        return "relic"

    @property
    def is_founder(self) -> bool:
        return self.rank <= len(FOUNDER_SLOTS)

    @property
    def seal_hue(self) -> int:
        return ELEMENT_HUE.get(self.element, 0)

    def spinor_seed(self) -> bytes:
        """Deterministic 64-byte public seed for this relic's badge.

        Feeds :func:`eopx.metatron.encode_public` so every relic renders a
        distinct, reproducible Metatron cube + seal.
        """
        return hashlib.sha3_512(
            CODEX_DOMAIN + b"|spinor|" + self.key.encode("utf-8")
        ).digest()

    def artifact_id(self) -> bytes:
        """Stable 16-byte EPX-T ``artifact_id`` for this relic.

        Deterministic from the relic key so the Codex is reproducible: the
        same relic always mints to the same identifier (still globally
        unique within the 2^128 namespace).
        """
        return hashlib.sha3_256(
            CODEX_DOMAIN + b"|aid|" + self.key.encode("utf-8")
        ).digest()[:16]

    def content_commit(self) -> bytes:
        """SHA3-512 over :meth:`lore_payload` — the artifact content commit."""
        return hashlib.sha3_512(self.lore_payload()).digest()

    def card_fingerprint_hex(self) -> str:
        """Fingerprint of this relic's PUBLIC Metatron card.

        Lets a scanner map a scanned sheet back to a relic: the card extracts
        to ``encode_public(spinor_seed)`` and ``card_fingerprint`` of those 91
        symbols equals this value. Lazy imports keep the module light.
        """
        from ..metatron import encode_public
        from ..vault import card_fingerprint
        return card_fingerprint(encode_public(self.spinor_seed())).hex()

    def lore_payload(self) -> bytes:
        """Canonical content bytes bound into the artifact ``content_commit``.

        Includes the full record (identity *and* lore) so the titled
        artifact commits to the exact relic text it was minted with.
        """
        doc = {
            "codex_version": CODEX_VERSION,
            "rank": self.rank,
            "key": self.key,
            "name": self.name,
            "title": self.title,
            "element": self.element,
            "myth_echo": self.myth_echo,
            "mechanism": self.mechanism,
            "lore": self.lore,
            "lore_fr": self.lore_fr,
        }
        return json.dumps(doc, ensure_ascii=False, sort_keys=True).encode("utf-8")

    def identity_tuple(self) -> tuple:
        """Immutable fields covered by the catalog commitment."""
        return (self.rank, self.key, self.name, self.element, self.myth_echo)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rank": self.rank,
            "key": self.key,
            "name": self.name,
            "title": self.title,
            "element": self.element,
            "seal_hue": self.seal_hue,
            "myth_echo": self.myth_echo,
            "mechanism": self.mechanism,
            "lore": self.lore,
            "lore_fr": self.lore_fr,
            "is_founder": self.is_founder,
            "artifact_id_hex": self.artifact_id().hex(),
            "card_fingerprint_hex": self.card_fingerprint_hex(),
        }


# ---------------------------------------------------------------------------
# The seven relics — hybrid lore (original names, myth echoes, real mechanics)
# ---------------------------------------------------------------------------

CODEX: List[Relic] = [
    Relic(
        rank=1, key="speculum_primum",
        name="Speculum Primum", title="The First Mirror",
        element="Air", myth_echo="Narcissus / the mirror of truth",
        mechanism="esoptron — identity reflected, never revealed "
                  "(the 91 F_13 symbols)",
        lore="Before a vault has a name it has a reflection. The First "
             "Mirror shows the holder not an image but a proof: that the "
             "face in the glass and the key in the hand are one. It reveals "
             "nothing it is not asked, and keeps nothing it is not given.",
        lore_fr="Avant qu'un coffre ait un nom, il a un reflet. Le Premier "
                 "Miroir ne montre pas une image mais une preuve : que le "
                 "visage dans le verre et la clé dans la main ne font qu'un. "
                 "Il ne révèle rien qu'on ne lui demande, ne garde rien "
                 "qu'on ne lui confie.",
    ),
    Relic(
        rank=2, key="clavis",
        name="Clavis", title="The Keystone",
        element="Earth", myth_echo="the Seal of Solomon / the signet ring",
        mechanism="the EPX-H seal revealed from the cube geometry",
        lore="A vault is an arch; the Keystone is the seal that lets it "
             "stand. It is the last stone set and the first one seen — the "
             "star that emerges from the cube when the light is true. "
             "Beautiful, recognisable, and honest: a mark, not a secret.",
        lore_fr="Un coffre est une arche ; la Clé de Voûte est le sceau qui "
                 "la tient debout. Dernière pierre posée, première pierre "
                 "vue — l'étoile qui émerge du cube quand la lumière est "
                 "juste. Belle, reconnaissable, honnête : une marque, pas un "
                 "secret.",
    ),
    Relic(
        rank=3, key="scintilla",
        name="Scintilla", title="The Stolen Ember",
        element="Fire", myth_echo="Prometheus / the gift of fire",
        mechanism="sovereign self-custody — the key no one can grant or "
                  "revoke for you",
        lore="The Ember is the fire carried down from the mountain: the "
             "power to hold one's own keys, taken back from every keeper "
             "that asked to hold them for you. It warms only the hand that "
             "dares to carry it, and goes out for no one else.",
        lore_fr="La Braise est le feu rapporté de la montagne : le pouvoir "
                 "de tenir ses propres clés, repris à tout gardien qui "
                 "demandait à les tenir pour toi. Elle ne réchauffe que la "
                 "main qui ose la porter, et ne s'éteint pour personne "
                 "d'autre.",
    ),
    Relic(
        rank=4, key="unda",
        name="Unda", title="The Tide",
        element="Water", myth_echo="the waters of Mnemosyne / Lethe's mirror",
        mechanism="holographic recovery — Shamir k-of-n and the BIP-39 "
                  "memory",
        lore="What is lost to one shore returns on another. The Tide is the "
             "promise that a vault drowned is not a vault dead: split across "
             "many waters, it gathers itself again from any sufficient few. "
             "Memory that cannot be stolen whole.",
        lore_fr="Ce qu'une rive perd, une autre le rend. La Marée est la "
                 "promesse qu'un coffre noyé n'est pas un coffre mort : "
                 "réparti sur plusieurs eaux, il se rassemble à partir de "
                 "quelques-unes suffisantes. Une mémoire qu'on ne peut voler "
                 "entière.",
    ),
    Relic(
        rank=5, key="stamen",
        name="Stamen", title="The Loom",
        element="Earth", myth_echo="the Moirai / the Norns who weave fate",
        mechanism="k-of-n custody — the threads that must be gathered to "
                  "act",
        lore="No single thread decides. The Loom binds a fate from many "
             "hands: cut one strand and the weave holds; gather enough and "
             "the pattern speaks. Control here is a chord, never a single "
             "note.",
        lore_fr="Aucun fil ne décide seul. Le Métier à tisser tresse un "
                 "destin à plusieurs mains : coupe un brin et la trame "
                 "tient ; rassemble-en assez et le motif parle. Le contrôle "
                 "y est un accord, jamais une note seule.",
    ),
    Relic(
        rank=6, key="lucerna",
        name="Lucerna", title="The Lantern",
        element="Fire", myth_echo="the lamp of Diogenes / the honest seeker",
        mechanism="verification — proving a card matches a vault without "
                  "revealing it",
        lore="Diogenes carried a lamp by daylight, looking for one honest "
             "thing. The Lantern is that light turned on a vault: it does "
             "not open the door, it tells you the door is true. Carry it and "
             "you can trust without unveiling.",
        lore_fr="Diogène portait une lampe en plein jour, cherchant une "
                 "seule chose honnête. La Lanterne est cette lumière "
                 "braquée sur un coffre : elle n'ouvre pas la porte, elle te "
                 "dit que la porte est vraie. Porte-la et tu peux faire "
                 "confiance sans dévoiler.",
    ),
    Relic(
        rank=7, key="corona_cava",
        name="Corona Cava", title="The Hollow Crown",
        element="Air", myth_echo="the crown that is worn, never owned",
        mechanism="titled transfer (EPX-T) — ownership is the ledger's "
                  "line, not the object held",
        lore="A title is not the paper you hold; it is the line the ledger "
             "draws under your name. The Hollow Crown can be worn by anyone "
             "and owned by only one — and the one is whoever the record "
             "names now, not whoever clutches the gold. Pass it on and your "
             "claim goes dark.",
        lore_fr="Un titre n'est pas le papier que tu tiens ; c'est la ligne "
                 "que le registre trace sous ton nom. La Couronne Creuse "
                 "peut être portée par quiconque et possédée par un seul — "
                 "et ce seul est celui que le registre nomme maintenant, non "
                 "celui qui serre l'or. Transmets-la et ta prétention "
                 "s'éteint.",
    ),
    Relic(
        rank=8, key="persona",
        name="Persona", title="The Mask",
        element="Air", myth_echo="the many masks of one face / Dionysus",
        mechanism="per-device enrollment (Protocol D) — one card, a distinct "
                  "identity on each device",
        lore="One face, many masks. From a single public card each device "
             "draws an identity unmistakably its own — same origin, never the "
             "same mask twice. To be known by many doors without handing any "
             "of them your face.",
        lore_fr="Un seul visage, mille masques. D'une même carte publique, "
                 "chaque appareil tire une identité qui n'appartient qu'à lui "
                 "— même origine, jamais deux fois le même masque. Être "
                 "reconnu par mille portes sans livrer ton visage à aucune.",
    ),
    Relic(
        rank=9, key="focus",
        name="Focus", title="The Hearth",
        element="Fire", myth_echo="Hestia / the hearth-fire shared, never divided",
        mechanism="the Genesis ceremony (Protocol E) — one sheet, many "
                  "independent vaults",
        lore="A hearth gives its fire to every torch and loses none of its "
             "own. From one ceremony sheet a hundred vaults are born, each "
             "whole, each independent — lit from the same flame, owing it "
             "nothing.",
        lore_fr="Un âtre donne son feu à chaque torche sans rien perdre du "
                 "sien. D'une seule feuille de cérémonie naissent cent "
                 "coffres, chacun entier, chacun indépendant — allumés à la "
                 "même flamme, ne lui devant rien.",
    ),
    Relic(
        rank=10, key="limen",
        name="Limen", title="The Threshold",
        element="Earth", myth_echo="Janus, god of thresholds and passages",
        mechanism="cross-machine migration (Protocol F) — prove ownership to "
                  "a new device without exposing the secret",
        lore="Janus looks both ways at once: the door you leave and the door "
             "you enter. The Threshold lets a vault cross from one machine to "
             "another, proving it is itself the whole way — and arriving "
             "without ever having shown the road its key.",
        lore_fr="Janus regarde des deux côtés à la fois : la porte qu'on "
                 "quitte et celle qu'on franchit. Le Seuil laisse un coffre "
                 "passer d'une machine à l'autre, prouvant qu'il est bien "
                 "lui-même tout du long — et arrivant sans avoir jamais "
                 "montré sa clé au chemin.",
    ),
    Relic(
        rank=11, key="phoenix",
        name="Phoenix", title="The Phoenix",
        element="Fire", myth_echo="the phoenix rising from its ashes",
        mechanism="identity reclaim (Protocol G) — rebuild the exact "
                  "enrollment on new ground",
        lore="Burned to nothing, it returns the same. The Phoenix is the "
             "promise that a lost device is not a lost self: from the public "
             "card and a second token, the very same identity rises again on "
             "new ground — unbroken, recognisable, yours.",
        lore_fr="Réduit à rien, il revient identique. Le Phénix est la "
                 "promesse qu'un appareil perdu n'est pas un soi perdu : "
                 "depuis la carte publique et un second jeton, la même "
                 "identité renaît sur une terre neuve — intacte, "
                 "reconnaissable, tienne.",
    ),
    Relic(
        rank=12, key="tessera",
        name="Tessera", title="The Watchword",
        element="Water", myth_echo="Shibboleth — the word that told who belonged",
        mechanism="Strong-Authentication Sheet (Protocol C) — card plus "
                  "device, challenge and response",
        lore="At the ford they asked for one word, and the saying of it told "
             "friend from foe. The Watchword binds a printed card to a living "
             "device: neither alone will pass, but together they answer the "
             "challenge and the gate opens.",
        lore_fr="Au gué, on demandait un seul mot, et sa prononciation "
                 "distinguait l'ami de l'ennemi. Le Mot de Garde lie une "
                 "carte imprimée à un appareil vivant : ni l'un ni l'autre ne "
                 "passe seul, mais ensemble ils répondent au défi et la porte "
                 "s'ouvre.",
    ),
]

CODEX_BY_KEY: Dict[str, Relic] = {r.key: r for r in CODEX}


# ---------------------------------------------------------------------------
# Distribution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RelicAssignment:
    """A relic's deterministic destination in the founder window."""
    relic: Relic
    vault_sequence: int
    placement: str  # "founder" | "derived"


def derive_relic_positions(
    btc_block_hash: bytes,
    btc_block_height: int = BTC_BLOCK_TARGET,
    *,
    count: int,
    window: int = DISTRIBUTION_WINDOW,
    reserved: tuple = FOUNDER_SLOTS,
) -> List[int]:
    """Derive ``count`` distinct positions in ``[1, window] \\ reserved``.

    Reuses :func:`eopx.genesis_token.derive_positions` over the reduced
    window ``window - len(reserved)`` and lifts each draw past the reserved
    founder slots, so the result is deterministic, collision-free with the
    founder trio, and sorted ascending.
    """
    reserved_sorted = sorted(set(reserved))
    usable = window - len(reserved_sorted)
    raw = derive_positions(
        btc_block_hash, btc_block_height, total=count, window=usable,
    )
    out: List[int] = []
    for p in raw:
        # Lift p (in [1, usable]) over each reserved slot it meets or passes.
        for r in reserved_sorted:
            if p >= r:
                p += 1
        out.append(p)
    return sorted(out)


def build_distribution(
    btc_block_hash: bytes,
    btc_block_height: int = BTC_BLOCK_TARGET,
) -> List[RelicAssignment]:
    """Map every relic to its destination vault sequence (deterministic).

    Relics 1–3 → founder slots (vaults #1/#2/#3) by rank; relics 4–12 → nine
    positions in ``[4, window]`` derived from the Bitcoin block, assigned in
    rank order to the sorted positions.
    """
    founders = sorted((r for r in CODEX if r.is_founder), key=lambda r: r.rank)
    derived_relics = sorted((r for r in CODEX if not r.is_founder),
                            key=lambda r: r.rank)

    assignments: List[RelicAssignment] = []
    for slot, relic in zip(FOUNDER_SLOTS, founders):
        assignments.append(RelicAssignment(relic, slot, "founder"))

    positions = derive_relic_positions(
        btc_block_hash, btc_block_height, count=len(derived_relics),
    )
    for relic, pos in zip(derived_relics, positions):
        assignments.append(RelicAssignment(relic, pos, "derived"))

    assignments.sort(key=lambda a: a.relic.rank)
    return assignments


# ---------------------------------------------------------------------------
# Commitment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HuntAssignment:
    """A relic's role in the treasure-hunt distribution."""
    relic: Relic
    placement: str               # "founder" | "huntable"
    vault_sequence: Optional[int]  # founder slot, or None when huntable


def build_hunt_distribution() -> List[HuntAssignment]:
    """Treasure-hunt distribution: founder trio reserved, the rest huntable.

    Relics of rank 1–3 are reserved for the founder vaults (1/2/3) — minted
    to them when they exist. Relics of rank > 3 are **huntable**: minted
    unclaimed with a voucher commitment (EPX-V) and claimed by whoever finds
    and scans their A4 sheet first. No Bitcoin block is needed — huntable
    relics carry no vault position; they are claimed by discovery.
    """
    out: List[HuntAssignment] = []
    for relic in sorted(CODEX, key=lambda r: r.rank):
        if relic.is_founder:
            out.append(HuntAssignment(relic, "founder",
                                      FOUNDER_SLOTS[relic.rank - 1]))
        else:
            out.append(HuntAssignment(relic, "huntable", None))
    return out


def hunt_secret(master_seed: bytes, relic_key: str) -> bytes:
    """Deterministic 32-byte voucher secret for a huntable relic.

    Derived from a **secret** master seed so the whole hunt is reproducible
    by the issuer (re-print a lost sheet) yet unguessable by finders. The
    master seed must be kept private — it opens every relic.
    """
    return hashlib.sha3_512(
        CODEX_DOMAIN + b"|hunt|" + master_seed + b"|" + relic_key.encode("utf-8")
    ).digest()[:32]


def catalog_commitment_hex() -> str:
    """SHA3-256 over the frozen identity of all relics (tamper-evidence).

    Covers ``CODEX_VERSION`` and each relic's identity tuple in rank order.
    Presentation fields (lore) are deliberately excluded so translations do
    not move the commitment.
    """
    h = hashlib.sha3_256()
    h.update(CODEX_DOMAIN)
    h.update(f"|v={CODEX_VERSION}|n={len(CODEX)}".encode("utf-8"))
    for relic in sorted(CODEX, key=lambda r: r.rank):
        h.update(b"|")
        h.update(json.dumps(relic.identity_tuple(), ensure_ascii=False,
                            sort_keys=True).encode("utf-8"))
    return h.hexdigest()


def codex_manifest(
    btc_block_hash: Optional[bytes] = None,
    btc_block_height: int = BTC_BLOCK_TARGET,
) -> Dict[str, object]:
    """Full public manifest of the Codex (catalog + optional distribution)."""
    manifest: Dict[str, object] = {
        "codex_version": CODEX_VERSION,
        "catalog_commitment_hex": catalog_commitment_hex(),
        "count": len(CODEX),
        "relics": [r.to_dict() for r in sorted(CODEX, key=lambda r: r.rank)],
    }
    if btc_block_hash is not None:
        manifest["btc_block_hash_hex"] = btc_block_hash.hex()
        manifest["btc_block_height"] = btc_block_height
        manifest["distribution"] = [
            {
                "rank": a.relic.rank,
                "key": a.relic.key,
                "vault_sequence": a.vault_sequence,
                "placement": a.placement,
            }
            for a in build_distribution(btc_block_hash, btc_block_height)
        ]
    return manifest


from .sigil import (  # noqa: E402
    LIVING_DRIFT_CAP_BYTES,
    living_relic_rows,
    randomart,
    render_living_sigil,
    render_relic_sigil,
    render_sigil,
    sigil_drift,
)
from .figure import (  # noqa: E402
    LIVING_INTERIOR_CAP,
    SILHOUETTES,
    figure_drift,
    figure_rows,
    render_living_relic_figure,
    render_relic_figure,
)

__all__ = [
    "CODEX_VERSION",
    "FOUNDER_SLOTS",
    "DISTRIBUTION_WINDOW",
    "Relic",
    "RelicAssignment",
    "CODEX",
    "CODEX_BY_KEY",
    "derive_relic_positions",
    "build_distribution",
    "catalog_commitment_hex",
    "codex_manifest",
    # treasure hunt (EPX-V)
    "HuntAssignment",
    "build_hunt_distribution",
    "hunt_secret",
    # relic sigil (ASCII brand face)
    "randomart",
    "render_sigil",
    "render_relic_sigil",
    # living sigil (state-reactive, bounded)
    "LIVING_DRIFT_CAP_BYTES",
    "living_relic_rows",
    "render_living_sigil",
    "sigil_drift",
    # figurative relic figure (looks like the object)
    "LIVING_INTERIOR_CAP",
    "SILHOUETTES",
    "figure_rows",
    "render_relic_figure",
    "render_living_relic_figure",
    "figure_drift",
]
