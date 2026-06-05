"""High-level orchestration: photo + intent -> action.

This module is the **single entry point** that mobile clients, CLI tools
and the server should call. It hides the choice between the five vault
protocols (A/B/C/D/E) behind a small typed surface:

    from eopx.flows import scan_and_route, Intent, ScanContext

    ctx = ScanContext(intent=Intent.ENROLL)
    result = scan_and_route("photo.jpg", ctx)
    if result.success:
        show_mnemonic(result.recovery_phrase)
        store_device_secret(result.enrollment.device_secret)

Design notes
------------
* The function never raises on a failed scan: callers must check
  ``result.success`` and ``result.errors``. This mirrors the
  ``VerificationResult`` model used in ``eopx.format``.
* Each ``Intent`` consumes its own subset of fields from ``ScanContext``;
  documented in the dispatch helpers below.
* ``scan_and_route`` is **pure** with respect to disk and network: it
  only touches the input image. Persistence (Keychain, IndexedDB,
  database) is the caller's responsibility.
* The return shape is stable: adding new intents must extend
  :class:`ScanResult` with optional fields, never break existing ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence, Union

from PIL import Image

from .metatron.aruco import ImageInput, autodetect_cube
from .metatron.detect import (
    erasures_from_confidences,
    extract_canonical,
    extract_robust,
)
from .vault import (
    EnrollmentRecord,
    GenesisVault,
    SASChallenge,
    card_fingerprint,
    enroll_from_card,
    genesis_enroll,
    new_challenge,
    respond,
    unlock_from_private_symbols,
    verify_card,
)
from .vault.genesis import entropy_to_recovery_phrase


class Intent(Enum):
    """What the caller wants to do with the scanned card."""

    ENROLL = "enroll"
    """First-time onboarding from a public card (Protocol D).

    Generates fresh ``device_entropy`` and returns a new
    :class:`~eopx.vault.EnrollmentRecord` plus the matching BIP-39
    recovery phrase. The caller MUST display the phrase to the user
    and store ``device_secret`` securely.
    """

    RECOVER = "recover"
    """Restore an enrollment from a previously saved recovery phrase.

    Same protocol as ENROLL but with explicit ``device_entropy``
    (typically reconstructed from a BIP-39 mnemonic via
    :func:`recovery_phrase_to_entropy`).
    """

    VERIFY = "verify"
    """Check that a scanned card matches a locally-known vault (Protocol B).

    Requires ``spinor_hash_local``. Returns a boolean attestation; no
    secret material is derived.
    """

    UNLOCK = "unlock"
    """Strong-Authentication-Sheet challenge response (Protocol C).

    Requires both ``spinor_hash_local`` and an SAS challenge. Returns a
    derived 32-byte session key on success.
    """

    UNLOCK_PRIVATE = "unlock_private"
    """Unlock a vault directly from a PRIVATE Metatron sheet (Protocol A).

    The card itself is the secret. Returns the 256-bit seed and a derived
    master key. Use only on inscriptions intended to carry vault secrets.
    """

    GENESIS = "genesis"
    """Genesis ceremony — derive a fresh vault from a shared sheet (Protocol E).

    Many devices scanning the same sheet derive independent vaults thanks
    to per-device entropy.
    """


@dataclass
class ScanContext:
    """Side-channel inputs needed by intents beyond ENROLL.

    Most fields are optional; only the fields relevant to the chosen
    ``intent`` are read. Validation errors are surfaced via
    :class:`ScanResult.errors`, not exceptions.
    """
    intent: Intent
    # RECOVER / GENESIS recovery flow
    device_entropy: Optional[bytes] = None
    # VERIFY / UNLOCK
    spinor_hash_local: Optional[bytes] = None
    # UNLOCK
    challenge: Optional[SASChallenge] = None
    # Detection tuning
    dst_size: int = 1024
    normalize: bool = True
    prefer: str = "cube"
    # Output tuning
    include_recovery_phrase: bool = True
    bip39_language: str = "english"


@dataclass
class ScanResult:
    """Aggregated outcome of :func:`scan_and_route`.

    ``success`` is True iff the requested intent completed end-to-end.
    Inspect ``errors`` to learn which step failed.
    """
    success: bool = False
    intent: Optional[Intent] = None

    # Common metadata, populated as soon as detection succeeds.
    card_fingerprint_hex: Optional[str] = None
    symbols: Optional[List[int]] = None
    detection_method: Optional[str] = None
    markers_used: Optional[int] = None

    # Intent-specific payloads (at most one is non-None).
    enrollment: Optional[EnrollmentRecord] = None
    recovery_phrase: Optional[List[str]] = None
    session_key: Optional[bytes] = None
    vault_master_key: Optional[bytes] = None
    vault_seed: Optional[bytes] = None
    genesis_vault: Optional[GenesisVault] = None
    verify_ok: Optional[bool] = None

    errors: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.success


# ---------------------------------------------------------------------------
# Detection front-end
# ---------------------------------------------------------------------------

def _load_image(img: Union[ImageInput, str, Path]) -> Image.Image:
    if isinstance(img, Image.Image):
        return img
    if isinstance(img, (str, Path)):
        return Image.open(img)
    # numpy array path is handled directly by autodetect_cube
    return img  # type: ignore[return-value]


def _detect_and_extract(image: Union[ImageInput, str, Path],
                         ctx: ScanContext,
                         result: ScanResult) -> Optional[List[int]]:
    """Run the photo -> 91 symbols pipeline. Populates ``result`` in place.

    Returns the list of symbols on success, or ``None`` if the pipeline
    failed (in which case ``result.errors`` has been extended).
    """
    try:
        raw = _load_image(image)
        detection = autodetect_cube(
            raw, dst_size=ctx.dst_size,
            normalize=ctx.normalize, prefer=ctx.prefer,
        )
    except Exception as exc:
        result.errors.append(f"ArUco autodetect failed: {exc}")
        return None

    result.detection_method = detection.method
    result.markers_used = detection.markers_used

    try:
        symbols, _dists = extract_robust(detection.cube_image)
    except Exception as exc:
        result.errors.append(f"symbol extraction failed: {exc}")
        return None

    if len(symbols) != 91:
        result.errors.append(
            f"unexpected symbol count: {len(symbols)} (need 91)"
        )
        return None

    result.symbols = list(symbols)
    try:
        result.card_fingerprint_hex = card_fingerprint(symbols).hex()
    except Exception as exc:  # pragma: no cover - defensive
        result.errors.append(f"fingerprint failed: {exc}")
        return None
    return result.symbols


# ---------------------------------------------------------------------------
# Per-intent handlers
# ---------------------------------------------------------------------------

def _do_enroll(symbols: List[int], ctx: ScanContext,
                result: ScanResult) -> None:
    try:
        rec = enroll_from_card(symbols, device_entropy=ctx.device_entropy)
    except Exception as exc:
        result.errors.append(f"enrollment failed: {exc}")
        return
    result.enrollment = rec
    if ctx.include_recovery_phrase:
        try:
            # We expose the recovery phrase for the RAW device_entropy, not
            # the derived device_secret: recovery must reproduce the same
            # enrollment, which is a function of (card_fp, device_entropy).
            # The entropy is held inside the EnrollmentRecord-producing
            # call; we passed it through ctx.device_entropy or generated it
            # inside enroll_from_card. Re-derive the phrase here using a
            # canonical entropy source.
            entropy = (
                ctx.device_entropy
                if ctx.device_entropy is not None
                else _entropy_from_enrollment(rec)
            )
            result.recovery_phrase = entropy_to_recovery_phrase(
                entropy, language=ctx.bip39_language,
            )
        except Exception as exc:
            result.errors.append(f"mnemonic encoding failed: {exc}")
            return
    result.success = True


def _entropy_from_enrollment(rec: EnrollmentRecord) -> bytes:
    """Fallback when the caller didn't pass ``device_entropy`` upfront.

    ``enroll_from_card`` does NOT return the raw entropy (only the
    derived ``device_secret``), so when the caller relies on automatic
    generation we cannot recover a recovery phrase after the fact. This
    helper exists to make the limitation explicit: it raises so the
    caller is forced to pass ``device_entropy`` to ``ScanContext`` for
    recovery-phrase enrollment.
    """
    raise RuntimeError(
        "to receive a recovery phrase, pass ScanContext.device_entropy "
        "explicitly (e.g. secrets.token_bytes(32)); enroll_from_card does "
        "not expose its internally generated entropy"
    )


def _do_recover(symbols: List[int], ctx: ScanContext,
                 result: ScanResult) -> None:
    if ctx.device_entropy is None:
        result.errors.append("RECOVER requires ScanContext.device_entropy")
        return
    _do_enroll(symbols, ctx, result)


def _do_verify(symbols: List[int], ctx: ScanContext,
                result: ScanResult) -> None:
    if ctx.spinor_hash_local is None:
        result.errors.append("VERIFY requires ScanContext.spinor_hash_local")
        return
    try:
        ok = verify_card(symbols, ctx.spinor_hash_local)
    except Exception as exc:
        result.errors.append(f"verify_card failed: {exc}")
        return
    result.verify_ok = ok
    result.success = ok


def _do_unlock(symbols: List[int], ctx: ScanContext,
                result: ScanResult) -> None:
    if ctx.spinor_hash_local is None:
        result.errors.append("UNLOCK requires ScanContext.spinor_hash_local")
        return
    if ctx.challenge is None:
        result.errors.append("UNLOCK requires ScanContext.challenge")
        return
    try:
        response = respond(symbols, ctx.spinor_hash_local, ctx.challenge)
    except Exception as exc:
        result.errors.append(f"SAS respond failed: {exc}")
        return
    # The verifier path (verify_response) is what actually derives the
    # session key. Callers using a single-device flow can call it here;
    # multi-device flows would send ``response`` over the wire.
    from .vault import verify_response
    try:
        session_key = verify_response(
            response, ctx.spinor_hash_local, symbols,
        )
    except Exception as exc:  # keep the "never raises" contract of scan_and_route
        result.errors.append(f"SAS verify failed: {exc}")
        return
    if session_key is None:
        result.errors.append("SAS challenge response did not verify")
        return
    result.session_key = session_key
    result.success = True


def _do_unlock_private(symbols: List[int], ctx: ScanContext,
                        result: ScanResult) -> None:
    try:
        seed, master_key = unlock_from_private_symbols(symbols)
    except Exception as exc:
        result.errors.append(f"private unlock failed: {exc}")
        return
    result.vault_seed = seed
    result.vault_master_key = master_key
    result.success = True


def _do_genesis(symbols: List[int], ctx: ScanContext,
                 result: ScanResult) -> None:
    try:
        vault = genesis_enroll(symbols, device_entropy=ctx.device_entropy)
    except Exception as exc:
        result.errors.append(f"genesis enroll failed: {exc}")
        return
    result.genesis_vault = vault
    if ctx.include_recovery_phrase and ctx.device_entropy is not None:
        try:
            result.recovery_phrase = entropy_to_recovery_phrase(
                ctx.device_entropy, language=ctx.bip39_language,
            )
        except Exception as exc:
            result.errors.append(f"mnemonic encoding failed: {exc}")
            return
    result.success = True


_DISPATCH = {
    Intent.ENROLL: _do_enroll,
    Intent.RECOVER: _do_recover,
    Intent.VERIFY: _do_verify,
    Intent.UNLOCK: _do_unlock,
    Intent.UNLOCK_PRIVATE: _do_unlock_private,
    Intent.GENESIS: _do_genesis,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_and_route(image: Union[ImageInput, str, Path],
                    ctx: ScanContext,
                    ) -> ScanResult:
    """Photo + intent -> action. Single entry point for clients.

    Parameters
    ----------
    image:
        A PIL image, a BGR numpy array, or a path to any image readable
        by PIL.
    ctx:
        Caller-supplied intent and side-channel data.

    Returns
    -------
    ScanResult
        Always returned, never raises. ``result.success`` indicates
        end-to-end completion; ``result.errors`` describes any failure.
    """
    result = ScanResult(intent=ctx.intent)
    symbols = _detect_and_extract(image, ctx, result)
    if symbols is None:
        return result

    handler = _DISPATCH.get(ctx.intent)
    if handler is None:
        result.errors.append(f"unknown intent: {ctx.intent}")
        return result
    handler(symbols, ctx, result)
    return result


def scan_only(image: Union[ImageInput, str, Path],
               *,
               dst_size: int = 1024,
               normalize: bool = True,
               prefer: str = "cube",
               ) -> ScanResult:
    """Detection-only convenience wrapper.

    Useful when the caller wants to display the card fingerprint to the
    user (e.g. for visual verification) before choosing an intent.
    """
    ctx = ScanContext(
        intent=Intent.VERIFY,    # placeholder; handler is not invoked
        dst_size=dst_size, normalize=normalize, prefer=prefer,
        include_recovery_phrase=False,
    )
    result = ScanResult(intent=None)
    symbols = _detect_and_extract(image, ctx, result)
    result.success = symbols is not None
    return result


__all__ = [
    "Intent",
    "ScanContext",
    "ScanResult",
    "scan_and_route",
    "scan_only",
]
