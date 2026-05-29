"""HTTPDelegateSequenceState — Genesis sequence numbers sourced from the
Eidolon Lock Server (default endpoint ``lock.eidolon-connect.xyz``,
override via the ``ESOPTRON_LOCK_SERVER_URL`` environment variable).

The lock server is the canonical assigner of ``vault_number`` for the
whole ecosystem: every Eidolon client calls
``POST /api/v1/register`` at provisioning time, and the lock server's
``vault_to_machine`` map serializes the global ordering. The Esoptron
anchor service must NOT write to the lock server (that would clobber
machine-binding state); it only reads.

Two read paths feed the local cache:

  * **Hint-driven** — when the caller (e.g. Eidolon
    ``vault_auto_provision``) already knows the assigned vault_number
    from a fresh ``register`` call, it passes it via ``sequence_hint``.
    The hint is trusted as authoritative.
  * **Stats-driven fallback** — if no hint is provided (e.g. a client
    that didn't go through the Eidolon CLI), we GET ``/api/v1/stats`` on
    the lock server (unauthenticated endpoint) and use
    ``next_vault_number`` as the assignment. The local cache then
    serializes concurrent calls by ``vault_fp_hex``.

Idempotence + persistence live in an embedded
:class:`~eopx.server.sequence_state.SequenceState` instance. We avoid
inheritance to keep the contract explicit.

Lock Server API surface (read-only from Esoptron's perspective):
  GET  /api/v1/stats        -> {success, data: {total_vaults, next_vault_number}}
  GET  /api/v1/health       -> {status: "ok", timestamp}
  POST /api/v1/verify       -> verify a vault binding (signed request)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import random
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .sequence_state import AnchorRecord, SequenceState

_log = logging.getLogger("eopx.server.http_delegate")

DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE = 0.5
DEFAULT_BACKOFF_MAX = 8.0


class LockServerError(RuntimeError):
    """Raised when the lock server is unreachable or returns garbage."""


@dataclass(frozen=True)
class LockServerConfig:
    """Configuration for the remote Eidolon Lock Server.

    ``api_secret`` is required for signed endpoints (``/api/v1/verify``).
    Read-only endpoints like ``/api/v1/stats`` do not require signing.
    """

    base_url: str
    api_secret: Optional[str] = None
    stats_path: str = "/api/v1/stats"
    health_path: str = "/api/v1/health"
    verify_path: str = "/api/v1/verify"
    request_timeout: float = 5.0
    max_retries: int = DEFAULT_MAX_RETRIES
    backoff_base: float = DEFAULT_BACKOFF_BASE
    backoff_max: float = DEFAULT_BACKOFF_MAX


@dataclass
class LockServerHealth:
    """Health check result from the lock server."""
    reachable: bool
    latency_ms: float
    server_time: Optional[str] = None
    error: Optional[str] = None


@dataclass
class VerifyResult:
    """Result of a vault binding verification against the lock server."""
    verified: bool
    vault_number: Optional[int] = None
    machine_fp_hex: Optional[str] = None
    error: Optional[str] = None


class HTTPDelegateSequenceState:
    """SequenceState backed by the Eidolon Lock Server.

    The class exposes the same public surface as
    :class:`SequenceState` (anchor_vault, total, max_sequence, lookup,
    lookup_by_sequence, seed_initial) so it is swappable in the anchor
    API blueprint without touching the route code.
    """

    def __init__(
        self,
        cache_db_path: Path,
        lock_server: LockServerConfig,
        *,
        stats_cache_ttl: float = 2.0,
    ) -> None:
        self._cache = SequenceState(Path(cache_db_path))
        self._lock_server = lock_server
        self._stats_cache_ttl = float(stats_cache_ttl)
        self._stats_cache: Optional[Tuple[float, int]] = None

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------

    def _request_with_retry(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        signed: bool = False,
    ) -> Dict[str, Any]:
        """Execute an HTTP request with exponential backoff retry.

        Returns the parsed JSON response on success.
        Raises LockServerError on persistent failure.
        """
        url = self._lock_server.base_url.rstrip("/") + path
        hdrs = {
            "accept": "application/json",
            "user-agent": "esoptron-anchor/1.0",
        }
        if headers:
            hdrs.update(headers)
        if body is not None:
            hdrs["content-type"] = "application/json"

        last_exc: Optional[Exception] = None
        for attempt in range(self._lock_server.max_retries):
            if attempt > 0:
                backoff = min(
                    self._lock_server.backoff_base * (2 ** attempt)
                    + random.uniform(0, 0.5),
                    self._lock_server.backoff_max,
                )
                _log.debug("retry %d after %.2fs backoff", attempt, backoff)
                time.sleep(backoff)

            req = urllib.request.Request(url, method=method, headers=hdrs, data=body)
            try:
                with urllib.request.urlopen(
                    req, timeout=self._lock_server.request_timeout
                ) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                    return payload
            except urllib.error.HTTPError as exc:
                # 4xx errors are not retryable
                if 400 <= exc.code < 500:
                    try:
                        err_body = json.loads(exc.read().decode("utf-8"))
                        msg = err_body.get("message", str(exc))
                    except Exception:
                        msg = str(exc)
                    raise LockServerError(f"HTTP {exc.code}: {msg}") from exc
                last_exc = exc
                _log.warning("HTTP %d on %s (attempt %d)", exc.code, path, attempt + 1)
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                last_exc = exc
                _log.warning("request failed: %s (attempt %d)", exc, attempt + 1)

        raise LockServerError(
            f"lock server request failed after {self._lock_server.max_retries} "
            f"attempts: {last_exc}"
        ) from last_exc

    # ------------------------------------------------------------------
    # Lock-server I/O
    # ------------------------------------------------------------------

    def health_check(self) -> LockServerHealth:
        """Check lock server reachability and latency."""
        start = time.perf_counter()
        try:
            payload = self._request_with_retry("GET", self._lock_server.health_path)
            latency = (time.perf_counter() - start) * 1000
            return LockServerHealth(
                reachable=True,
                latency_ms=round(latency, 2),
                server_time=payload.get("timestamp"),
            )
        except LockServerError as exc:
            latency = (time.perf_counter() - start) * 1000
            return LockServerHealth(
                reachable=False,
                latency_ms=round(latency, 2),
                error=str(exc),
            )

    def verify_vault_binding(
        self,
        vault_fp_hex: str,
        machine_fp_hex: str,
    ) -> VerifyResult:
        """Verify that a vault is bound to a specific machine on the lock server.

        This is a signed request that proves we have api_secret access.
        Returns VerifyResult with the binding status.
        """
        if not self._lock_server.api_secret:
            return VerifyResult(
                verified=False,
                error="api_secret not configured; cannot verify binding",
            )

        payload = {
            "vault_fp_hex": vault_fp_hex.lower(),
            "machine_fp_hex": machine_fp_hex.lower(),
        }
        sig, ts, nonce = self._sign(payload)
        headers = {
            "x-signature": sig,
            "x-timestamp": ts,
            "x-nonce": nonce,
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")

        try:
            resp = self._request_with_retry(
                "POST",
                self._lock_server.verify_path,
                body=body,
                headers=headers,
                signed=True,
            )
            data = resp.get("data", {})
            return VerifyResult(
                verified=data.get("verified", False),
                vault_number=data.get("vault_number"),
                machine_fp_hex=data.get("machine_fp_hex"),
            )
        except LockServerError as exc:
            return VerifyResult(verified=False, error=str(exc))

    def _fetch_next_vault_number(self) -> int:
        """Return ``next_vault_number`` reported by the lock server.

        Cached for ``stats_cache_ttl`` seconds to throttle traffic when
        many anchors fire in quick succession. Raises
        :class:`LockServerError` on failure.
        """
        now = time.time()
        if self._stats_cache is not None:
            cached_at, cached_value = self._stats_cache
            if now - cached_at < self._stats_cache_ttl:
                return cached_value

        payload = self._request_with_retry("GET", self._lock_server.stats_path)

        # The lock server wraps responses in {success, message, data:{...}}
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise LockServerError(
                f"unexpected stats payload shape: {payload!r}"
            )
        nvn = data.get("next_vault_number")
        if not isinstance(nvn, int) or nvn < 1:
            # Fallback: derive from total_vaults if next_vault_number
            # is missing on older lock server builds.
            total = data.get("total_vaults")
            if isinstance(total, int) and total >= 0:
                nvn = total + 1
            else:
                raise LockServerError(
                    f"lock server returned no usable counter: {data!r}"
                )
        self._stats_cache = (now, int(nvn))
        return int(nvn)

    def _sign(self, payload: Dict[str, Any]) -> tuple[str, str, str]:
        """Compute an HMAC-SHA256 signature compatible with the lock
        server's ``_verify_signature`` helper.

        Returns ``(signature_hex, timestamp_str, nonce_hex)``.

        The signed canonical string is::

            f"{timestamp}\\n{nonce}\\n{json.dumps(payload, sort_keys=True)}"

        This binds the signature to a per-request timestamp AND nonce so the
        intercepted request cannot be replayed and the timestamp cannot be
        manipulated independently of the body. The lock server MUST validate
        the same canonical form and reject requests where the timestamp drift
        exceeds the configured window.
        """
        if not self._lock_server.api_secret:
            raise LockServerError(
                "lock server api_secret not configured; cannot sign"
            )
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        body = json.dumps(payload, sort_keys=True)
        canonical = f"{ts}\n{nonce}\n{body}".encode("utf-8")
        secret = self._lock_server.api_secret.encode("utf-8")
        sig = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
        return sig, ts, nonce

    # ------------------------------------------------------------------
    # SequenceState surface (same names, same semantics)
    # ------------------------------------------------------------------

    def anchor_vault(
        self,
        vault_fp_hex: str,
        source: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        sequence_hint: Optional[int] = None,
    ) -> AnchorRecord:
        """Idempotent anchor; assigns a sequence sourced from the lock
        server (via hint or stats) and caches it locally.

        If ``sequence_hint`` is provided, it is honored verbatim. If a
        cached record already exists for ``vault_fp_hex``, that record
        is returned regardless of hint (the cache is authoritative for
        re-entries; this prevents drift on retries).
        """
        # Fast path: cached hit short-circuits any HTTP traffic.
        existing = self._cache.lookup(vault_fp_hex)
        if existing is not None:
            return existing

        effective_hint = sequence_hint
        if effective_hint is None:
            effective_hint = self._fetch_next_vault_number()
            # Bust the cache so the next call gets a fresh value once
            # we've consumed this one; ttl is just an upper bound.
            self._stats_cache = None

        try:
            return self._cache.anchor_vault(
                vault_fp_hex=vault_fp_hex,
                source=source,
                meta=meta,
                sequence_hint=effective_hint,
            )
        except ValueError as exc:
            # Collision on the proposed sequence — likely two racing
            # callers got the same `next_vault_number`. Retry once,
            # bumping past the conflict.
            if "already used" not in str(exc):
                raise
            _log.warning(
                "anchor sequence collision on %d (%s); retrying",
                effective_hint, vault_fp_hex[:12],
            )
            self._stats_cache = None
            retry_hint = self._cache.max_sequence() + 1
            return self._cache.anchor_vault(
                vault_fp_hex=vault_fp_hex,
                source=source,
                meta=meta,
                sequence_hint=retry_hint,
            )

    def total(self) -> int:
        return self._cache.total()

    def max_sequence(self) -> int:
        return self._cache.max_sequence()

    def lookup(self, vault_fp_hex: str) -> Optional[AnchorRecord]:
        return self._cache.lookup(vault_fp_hex)

    def lookup_by_sequence(self, sequence: int) -> Optional[AnchorRecord]:
        return self._cache.lookup_by_sequence(sequence)

    def seed_initial(
        self,
        records: list[tuple[int, str, Optional[float]]],
    ) -> int:
        return self._cache.seed_initial(records)

    def sync_from_lock_server(
        self,
        *,
        vault_list_path: str = "/api/v1/vaults",
        limit: int = 1000,
    ) -> int:
        """Synchronize local cache from the lock server's vault registry.

        Fetches the paginated vault list and seeds any missing records
        into the local SQLite cache. Returns the count of newly imported
        records.

        This is useful for bootstrapping a new Esoptron instance or
        recovering after data loss.
        """
        imported = 0
        offset = 0

        while True:
            try:
                payload = self._request_with_retry(
                    "GET",
                    f"{vault_list_path}?limit={limit}&offset={offset}",
                )
            except LockServerError as exc:
                _log.error("sync aborted: %s", exc)
                break

            data = payload.get("data", {})
            vaults = data.get("vaults", [])
            if not vaults:
                break

            records = []
            for v in vaults:
                seq = v.get("vault_number")
                fp = v.get("vault_fp_hex")
                ts = v.get("registered_at")
                if seq and fp:
                    records.append((int(seq), str(fp), float(ts) if ts else None))

            if records:
                imported += self._cache.seed_initial(records)

            if len(vaults) < limit:
                break
            offset += limit

        _log.info("sync complete: imported %d records", imported)
        return imported

    def get_ecosystem_stats(self) -> Dict[str, Any]:
        """Fetch ecosystem statistics from the lock server.

        Returns raw stats including total_vaults, next_vault_number,
        genesis positions claimed, etc.
        """
        try:
            payload = self._request_with_retry("GET", self._lock_server.stats_path)
            return payload.get("data", {})
        except LockServerError as exc:
            return {"error": str(exc)}
