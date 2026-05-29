"""JSON serialization for ``eopx.flows`` results.

Single source of truth for the wire format consumed by the PWA and any
future native mobile client. Only public, non-sensitive fields are
serialised by default; secret material (``device_secret``, ``vault_seed``,
``vault_master_key``, ``session_key``) is opt-in via explicit flags.

Rule of thumb
-------------
* ``include_secrets=False`` (default) → safe to log and store as JSON.
* ``include_secrets=True``           → caller is responsible for TLS,
  client-side storage encryption, and never persisting the response.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from ..flows import Intent, ScanResult
from ..vault import EnrollmentRecord, GenesisVault


def extract_result_to_dict(result: ScanResult) -> Dict[str, Any]:
    """Serialise a ``scan_only``-style result for the ``/extract`` endpoint.

    Only public detection metadata + the 91 symbol vector is exposed; no
    vault material is involved because no intent ran.
    """
    return {
        "success": result.success,
        "card_fingerprint_hex": result.card_fingerprint_hex,
        "symbols": list(result.symbols) if result.symbols is not None else None,
        "detection_method": result.detection_method,
        "markers_used": result.markers_used,
        "errors": list(result.errors),
    }


def _b64(b: Optional[bytes]) -> Optional[str]:
    return base64.b64encode(b).decode("ascii") if b is not None else None


def _hex(b: Optional[bytes]) -> Optional[str]:
    return b.hex() if b is not None else None


# ---------------------------------------------------------------------------
# Per-dataclass encoders
# ---------------------------------------------------------------------------

def enrollment_to_dict(rec: EnrollmentRecord,
                        *,
                        include_secrets: bool = False) -> Dict[str, Any]:
    """Serialise an :class:`EnrollmentRecord` to a JSON-safe dict.

    The ``device_secret`` is always SENSITIVE; it is omitted unless the
    caller explicitly opts in.
    """
    out: Dict[str, Any] = {
        "vault_fp_hex": rec.vault_fp.hex(),
        "enrollment_fp_hex": rec.enrollment_fp.hex(),
        "public_tag_hex": rec.public_tag.hex(),
        "shadow_hologram_hex": rec.shadow_hologram.hex(),
    }
    if include_secrets:
        out["device_secret_hex"] = rec.device_secret.hex()
    return out


def genesis_vault_to_dict(vault: GenesisVault,
                           *,
                           include_secrets: bool = False) -> Dict[str, Any]:
    """Serialise a :class:`GenesisVault` to a JSON-safe dict.

    Public-only by default.
    """
    out: Dict[str, Any] = {
        "ceremony_fp_hex": vault.ceremony_fp.hex(),
        "vault_fp_hex": vault.vault_fp.hex(),
    }
    if include_secrets:
        out["vault_seed_hex"] = vault.vault_seed.hex()
        out["master_key_hex"] = vault.master_key.hex()
        out["device_entropy_hex"] = vault.device_entropy.hex()
    return out


def scan_result_to_dict(result: ScanResult,
                         *,
                         include_secrets: bool = False) -> Dict[str, Any]:
    """Serialise a :class:`ScanResult` to a JSON-safe dict.

    Secret fields (``vault_seed``, ``vault_master_key``, ``session_key``,
    ``device_secret`` inside ``enrollment``) are included only when the
    caller explicitly opts in.
    """
    out: Dict[str, Any] = {
        "success": result.success,
        "intent": result.intent.value if result.intent else None,
        "card_fingerprint_hex": result.card_fingerprint_hex,
        "detection_method": result.detection_method,
        "markers_used": result.markers_used,
        "errors": list(result.errors),
    }
    # Public fields
    if result.verify_ok is not None:
        out["verify_ok"] = result.verify_ok
    if result.recovery_phrase is not None:
        out["recovery_phrase"] = list(result.recovery_phrase)
    if result.enrollment is not None:
        out["enrollment"] = enrollment_to_dict(
            result.enrollment, include_secrets=include_secrets,
        )
    if result.genesis_vault is not None:
        out["genesis_vault"] = genesis_vault_to_dict(
            result.genesis_vault, include_secrets=include_secrets,
        )

    # Strictly secret fields
    if include_secrets:
        if result.session_key is not None:
            out["session_key_hex"] = result.session_key.hex()
        if result.vault_master_key is not None:
            out["vault_master_key_hex"] = result.vault_master_key.hex()
        if result.vault_seed is not None:
            out["vault_seed_hex"] = result.vault_seed.hex()
        # Symbols are not strictly secret for VERIFY, but leaking them
        # makes card-vault linkage easier across servers, so gate them
        # behind the same flag.
        if result.symbols is not None:
            out["symbols"] = list(result.symbols)
    return out


# ---------------------------------------------------------------------------
# Intent input parsing
# ---------------------------------------------------------------------------

def intent_from_str(s: str) -> Intent:
    """Parse an intent string (case-insensitive) into the enum.

    Raises ``ValueError`` on unknown intents, which the calling route
    should translate into a 400 response.
    """
    try:
        return Intent(s.lower())
    except ValueError as exc:
        valid = ", ".join(sorted(i.value for i in Intent))
        raise ValueError(
            f"unknown intent {s!r}; valid values: {valid}"
        ) from exc
