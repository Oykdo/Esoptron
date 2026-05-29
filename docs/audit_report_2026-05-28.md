# Esoptron Ecosystem Audit Report

**Date:** 2026-05-28
**Auditor:** Worker droid
**Scope:** Full ecosystem — Python core (`src/eopx/`), Python SDK (`sdk/python/`), TypeScript SDK (`sdk/typescript/`), PWA (`pwa/`), tests, scripts and documentation.

---

## Executive Summary

| Metric | Value |
| --- | --- |
| Overall health score | **7.0 / 10** |
| Total findings | **23** (P0: 6, P1: 9, P2: 8) |
| Publication readiness | **NEEDS WORK** |

Cryptographic primitives (ML-DSA-87, ML-KEM-1024, SHA3, HKDF, Argon2id, ChaCha20-Poly1305) are wired correctly and the domain-separation discipline is unusually clean. Every HKDF `info` string and every AEAD AAD encountered in `src/eopx/` and `pwa/src/lib/` is unique, namespaced, and version-tagged. Constant-time comparisons are consistently used wherever a tag/fingerprint is checked. Shamir GF(2⁸) is implemented correctly on both sides (Python and TypeScript) using identical Rijndael tables and random sources are CSPRNG-only inside core flows.

The weak spots cluster in three places:

1. **Server-side hardening** — Flask apps (`server/app.py`, `server/pwa_api.py`, `server/anchor_api.py`) ship without rate limiting, signed-endpoint replay protection, structured error envelopes or wildcard-blocking CORS defaults, and `app.py` writes uploaded user photos verbatim to `out/last_upload.jpg`.
2. **Protocol F (migration)** — `verify_proof_with_tag()` is documented as a third-party witness API but is only a structural placeholder (does not cryptographically bind the proof to the tag); it is publicly exported and re-exported from `eopx.vault`.
3. **PWA inline crypto in `server/app.py`** — `app.py` re-implements SHA-256, HKDF-HMAC-SHA256 and HKDF info strings inline in the served HTML (`esoptron.mobile.*`) that **differ** from the Python core's `esoptron.vault.*` domain separators. This creates two parallel, divergent crypto schemes that share the word "vault".

Tests are extensive (≈ 359 cases listed in README; collection currently fails locally because `pqcrypto` is not installed in the active interpreter — not a code defect), but parser fuzzing, property-based tests and oversized-input edge cases are largely missing.

---

## P0 Critical Findings

### P0-1 — `verify_proof_with_tag` is a cryptographic stub but is exported as public API
- **Location:** `src/eopx/vault/migrate.py:378-431`, `src/eopx/vault/__init__.py:58,85`.
- **Description:** The function is exported in `__all__` and documented as the API a "third-party witness (e.g. a migration server) can attest that a valid proof was presented without learning the master_key". In practice the body only checks `len(...)` on the proof fields and the TTL. There is **no** cryptographic binding between `verify_tag` and the supplied `MigrationProof`; an attacker can submit any random `commitment`/`response`/`nonce` of the correct lengths and it returns `True`.
- **Recommendation:** Either (a) remove from `__all__` and the public package surface until a real tag-bound verification is implemented (the source code already notes "This is a placeholder for the witness-based flow"), or (b) implement the embedded `tag_commitment = HKDF(verify_tag, salt=nonce, ...)` scheme that the comments describe and add tests covering forgery rejection. Until either is done, a third-party "witness" relying on this function provides zero assurance.
- **Effort:** Half a day for option (a); 1-2 days for option (b) including tests and PWA parity if the witness flow is desired.

### P0-2 — Two divergent "mobile" KDF chains shipped to phones via `server/app.py`
- **Location:** `src/eopx/server/app.py` — inline `<script>` of `SCAN_HTML` defines and uses HKDF-HMAC-**SHA-256** with the info strings:
  - `esoptron.mobile.genesis.vault_seed.sha256.v1`
  - `esoptron.mobile.vault.master_key.sha256.v1`
  - `esoptron.mobile.vault_fp.sha256.v1\n`
  - `esoptron.mobile.enrollment_fp.sha256.v1`
  - `esoptron.mobile.public_tag.sha256.v1`
- **Description:** The Python core (`vault/unlock.py`, `vault/genesis.py`, `vault/enroll.py`) uses HKDF-**SHA3-512** with `esoptron.vault.*`, `esoptron.genesis.*`, `esoptron.enroll.*`. A `.psnx` produced by the phone via `app.py` is therefore **bytewise incompatible** with the Python core's view of the same vault. The PWA in `pwa/src/lib/` correctly uses the SHA3-512 / `esoptron.vault.*` chain; only the legacy `app.py` HTML drifts.
- **Recommendation:** Align `app.py` with the PWA so a single canonical KDF chain exists per `vault_id`. Add a test vector cross-check (`scripts/gen_test_vectors.py`) that boots `app.py`'s HTML routine via headless JS or, simpler, removes the bespoke implementation in favour of redirecting the phone to the PWA endpoints.
- **Effort:** 1-2 days plus regression tests; the inline JS adds ~200 lines of hand-rolled SHA-256 that should be retired entirely.

### P0-3 — No replay protection on lock-server signed verify requests
- **Location:** `src/eopx/server/http_delegate.py:212-242`, `_sign()` at line 290-303.
- **Description:** The HMAC signature is computed over `json.dumps(payload, sort_keys=True)` only; the timestamp is sent in the `x-timestamp` header but **not** included in the signed bytes. An attacker who intercepts a request can replay it indefinitely, or pivot it to a different timestamp without invalidating the signature. The lock-server side may compensate, but the Esoptron client must defend in depth.
- **Recommendation:** Include `x-timestamp` in the canonical signed string (`f"{ts}\n{body}"`) and reject responses where `now - ts > window`. Add a nonce header for additional uniqueness. Provide a documented signing-spec compatible with what `lock.eidolon-connect.xyz` actually validates.
- **Effort:** ~1 day including coordination with Eidolon Lock Server.

### P0-4 — `app.py` writes raw uploaded user images to disk on every call
- **Location:** `src/eopx/server/app.py:1015-1019` (`(out / "last_upload.jpg").write_bytes(data)`), `_save_diagnostic_img` writes `out/diagnostic_cube_crop.png`, `_save_diagnostic` writes `out/diagnostic_rectified_a4.png`.
- **Description:** Every uploaded frame — including PRIVATE Metatron sheets which contain the 256-bit vault seed — is persisted unauthenticated to a predictable path. The path is shared across users/sessions: a second user's upload overwrites the first user's last private sheet, and the file is not removed after decode. On a multi-user host this is an exfiltration channel.
- **Recommendation:** Disable persistence by default; gate behind a `ESOPTRON_DEBUG_DUMP_FRAMES=1` env var; if kept, write to per-request temp files with `0600` mode and delete on response. Never persist when `cfg.mode == "private"`.
- **Effort:** ~2 hours.

### P0-5 — No upload size limit on `app.py /api/frame`, only a Flask global cap on `pwa_api.py`
- **Location:** `src/eopx/server/app.py:1006-1041` reads `f.read()` unbounded after `app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024`. PNG/JPEG decoding via `cv2.imdecode` happens on the full buffer. `pwa_api.py` caps at 12 MB but the limit is enforced post-`read()`.
- **Description:** Decompression bombs (zip-bomb-equivalent PNG with extreme dimensions) can OOM the worker. `Image.open` is called without `Image.MAX_IMAGE_PIXELS` adjustment in `pwa_api.py`. `cv2.imdecode` does not enforce a pixel cap.
- **Recommendation:** Enforce `MAX_CONTENT_LENGTH` consistently, validate the image dimensions before `tobytes()`, set `Image.MAX_IMAGE_PIXELS` explicitly, and consider streaming reads with chunked size checks.
- **Effort:** Half a day.

### P0-6 — No rate limiting on any HTTP endpoint
- **Location:** All Flask blueprints (`server/app.py`, `server/pwa_api.py`, `server/anchor_api.py`).
- **Description:** `/api/v1/scan`, `/api/v1/extract`, `/api/v1/genesis/anchor`, `/api/v1/genesis/seal/<sequence>`, `/api/frame` and `/api/register_psnx` are all openly invocable. The anchor API mints Genesis seals; an attacker can drain CPU by forcing repeated Dilithium signing operations. The phone-scan API performs ML-DSA crypto + image decode per call. No backoff on the lock server beyond exponential retry inside the client.
- **Recommendation:** Add Flask-Limiter (or equivalent) with per-IP and per-vault-fp buckets. Tighten the anchor endpoint to require a signed source (Eidolon-issued auth token) before minting seals. Document expected production deployment behind a reverse proxy with WAF.
- **Effort:** 1 day including config plumbing.

---

## P1 High-Priority Findings

### P1-1 — CORS defaults are off-by-default, but the dev script accepts arbitrary origins
- **Location:** `src/eopx/server/pwa_api.py:243-263`, `scripts/serve_pwa_api.py:30-43`.
- **Description:** `create_app()` only enables CORS if `allow_origins` is set; good. However the CLI accepts repeatable `--cors` flags with no validation, so an operator can trivially enable `--cors '*'` which `flask_cors` treats as wildcard with credentials. Anchor and phone-scan apps have no CORS plumbing at all (acceptable while the surface is server-side only, but worth flagging).
- **Recommendation:** Validate that `--cors` arguments parse as URLs with explicit schemes/hosts and refuse `*`. Document expected production origin allow-list. Consider centralising CORS via a single helper.
- **Effort:** 2 hours.

### P1-2 — Bootstrapping the anchor service silently falls back to a zero Bitcoin block hash
- **Location:** `src/eopx/server/anchor_api.py:325-330`.
- **Description:** When `ESOPTRON_BTC_BLOCK_HASH` / `ESOPTRON_BTC_BLOCK_HEIGHT` are not set, `bootstrap_from_env` defaults to `("ff" * 32, BTC_BLOCK_TARGET)`. This is convenient for tests but means a misconfigured production launch will mint Genesis seals against the dummy hash and brick the deployment (the 88 positions are not the published positions). The mistake is undetectable until a Bitcoin block consumer tries to verify a seal.
- **Recommendation:** Require both env vars in production; gate the fallback behind `ESOPTRON_ALLOW_DEV_DEFAULTS=1`. Log a loud warning if the dummy hash is used.
- **Effort:** 1 hour.

### P1-3 — Deployment private key written without explicit POSIX mode
- **Location:** `src/eopx/server/anchor_api.py:159-179` (`_DeploymentContext._persist`).
- **Description:** The Dilithium5 + Kyber1024 deployment **secret** keys are written verbatim to a JSON file via `tmp.write_text(...)` and `tmp.replace(self.path)`. The comment notes "we do not chmod here because cross-platform; the operator sets the permissions via systemd / ACL." In practice many operators won't notice, and the file may be world-readable.
- **Recommendation:** Attempt `os.chmod(path, 0o600)` after `replace` (with a try/except for Windows) and emit a startup warning when the file permissions are too open. Document the expectation in `docs/`.
- **Effort:** 1 hour.

### P1-4 — `EopxKey.save` returns silently on Windows where `chmod(0o600)` is a no-op
- **Location:** `src/eopx/format/keys.py:204-211`.
- **Description:** `os.chmod` is wrapped in `try/except OSError: pass`. On Windows this silently leaves the key world-readable. The same JSON envelope can carry Dilithium **and** Kyber secret keys.
- **Recommendation:** On Windows, use `pywin32`/`subprocess icacls` to set DACL, or document explicitly that callers must wrap the file in DPAPI/Eidolon machine_lock. Add a runtime warning.
- **Effort:** 4 hours (Windows ACL plumbing is non-trivial).

### P1-5 — Argon2 parameters are workstation-tuned, no mobile profile published
- **Location:** `src/eopx/recovery.py:65-68`, `pwa/src/lib/recovery.ts:29-30`.
- **Description:** `ARGON2_CLOUD_PARAMS = m=128 MiB, t=4` is fine on a laptop but is documented in the whitepaper as "may be slow on low-end devices". The PWA's `RecoveryRestore.tsx` admits "~10 s of Argon2id derivations". A mid-range Android phone can take 30+ seconds per share for the cloud parameter set; this is a UX cliff. No second tier is provided for mobile-only setups.
- **Recommendation:** Either (a) keep workstation tier as canonical and document the cost, or (b) define a `ARGON2_MOBILE_PARAMS` tier (e.g. `m=32MiB, t=3`) and let the caller pick — but then the package metadata MUST record `kdf_params` per share (already done via the `kdf` field, so the wire format already supports it). Add a benchmark script to pick the tier automatically.
- **Effort:** 1 day including bench harness.

### P1-6 — `MigrationProof.timestamp` is attacker-controlled in `verify_migration`
- **Location:** `src/eopx/vault/migrate.py:243-326`.
- **Description:** The target device trusts `proof.timestamp` to evaluate TTL. An attacker who replays a stale proof can set the timestamp to "now" and `verify_migration` accepts it — there is no signed binding between `timestamp` and the rest of the proof's signed material (the timestamp is **not** mixed into `_compute_challenge_hash`). Replay protection therefore relies entirely on the target_lock check (which is fine when the target_lock is fresh) and on the source device's challenge nonce being one-shot.
- **Recommendation:** Add `timestamp` to the Fiat-Shamir challenge hash. Track consumed nonces on the target device (small bloom filter or sliding window). Document that the migration ceremony is single-use per nonce.
- **Effort:** Half a day.

### P1-7 — Public `psnx` registry is an unbounded append-only JSONL with no auth
- **Location:** `src/eopx/server/app.py:_register_public_psnx`, `out/registry/vault_registry.jsonl`.
- **Description:** Anyone reaching `/api/register_psnx` can write arbitrary entries (subject to format validation) and append to `vault_registry.jsonl` on the host's filesystem. No quota, no auth, no log rotation; combined with P0-6 this is a denial-of-service vector and an unbounded disk-fill primitive.
- **Recommendation:** Move the registry behind authenticated POST (HMAC token or signed JWS), cap file size, and put it on a dedicated volume.
- **Effort:** 1 day.

### P1-8 — `decode_private` ceremony seed is treated as a secret AND a fingerprint
- **Location:** `src/eopx/vault/genesis.py:97-126` (`ceremony_seed` is used both as HKDF IKM and as input to `card_fingerprint`).
- **Description:** The fingerprint `ceremony_fp` is derived from raw symbols (good), but `ceremony_seed` itself is a 32-byte secret recovered from a printed sheet. Any device that re-scans the sheet learns the seed. Subsequent vaults are independent (HKDF over device entropy) but the seed itself never rotates. If the ceremony sheet leaks, an attacker can not unlock anyone's vault — but they can mint a fraudulent ceremony with the same fingerprint, confusing downstream tooling.
- **Recommendation:** Add an authenticated ceremony-launch attestation (Dilithium signature by the organizer over `ceremony_fp || timestamp || metadata`) and verify it before deriving any vault from the sheet.
- **Effort:** 1-2 days including PWA parity.

### P1-9 — `EopxManifest.kyber_pk_fp` chunk-mismatch check is skipped when chunk equals `ZEROS_32`
- **Location:** `src/eopx/format/eopx_format.py:163-174`.
- **Description:** When a kyber public key is present but the embedded `kyber_pk_fp` chunk is `ZEROS_32`, the consistency check is bypassed. An attacker can embed a non-matching Kyber pubkey and a zeroed fingerprint chunk; the manifest passes structural validation because Kyber is not covered by the Dilithium signature directly (the canonical payload covers `kyber_pk_fp`, derived from the embedded pubkey, but the bypass branch trusts the chunk).
- **Recommendation:** Always recompute `key_fingerprint(kyber_pk).hex()` and compare. Never accept a zero fingerprint when the corresponding key is present.
- **Effort:** 2 hours plus regression test.

---

## P2 Medium-Priority Findings

### P2-1 — `_DeploymentContext.load_or_init` does not lock the file
- **Location:** `src/eopx/server/anchor_api.py:96-145`.
- **Description:** Two anchor processes started simultaneously can both observe `path.exists() == False` and race to write the deployment key. Last writer wins, and the loser will read the winner's key on next start — but the in-memory objects diverge for the duration of the race.
- **Recommendation:** Use `O_EXCL` on creation or a file-lock helper.

### P2-2 — Test suite cannot collect when `pqcrypto` is not present
- **Location:** `pyproject.toml` lists `pqcrypto>=0.3` as a hard dependency; `tests/__init__.py` is empty so failure cascades.
- **Description:** `python -m pytest tests/ --collect-only` errors with "pqcrypto is required" on every test, including pure-Python ones like `test_shamir.py`. This is environment, not code, but `pqcrypto` is notoriously hard to install on Windows.
- **Recommendation:** Make the `from pqcrypto.sign import ml_dsa_87` import in `format/keys.py` lazy (only when crypto is actually invoked), so that pure-Python modules (Shamir, secure_bytes, metatron field) remain importable without it.

### P2-3 — `_hkdf_sha3_256` duplicated in 3 places
- **Location:** `src/eopx/format/visual_sharding.py:120-141`, `src/eopx/genesis_token.py:113-128`, `src/eopx/recovery.py:_kdf_kyber`.
- **Description:** Three nearly-identical implementations with different conventions (salt-zero, single-block vs multi-block). Easy to drift over time.
- **Recommendation:** Centralise in `metatron.field` (or a new `format.kdf`) and re-export.

### P2-4 — No fuzz / property tests for `.eopx` and Metatron parsers
- **Location:** `tests/test_eopx_format.py`, `tests/test_metatron_*`.
- **Description:** Tests exercise round-trip and a few targeted tampering cases (good). Missing: hypothesis-based property tests, mutation-based fuzzing of PNG chunks, oversized/zero-byte payload tests, malformed base64 in `dilithium_pk_b64`, oversized image dimensions, and chunk-order shuffling.
- **Recommendation:** Add `hypothesis` (declared as a dev dep already?) — currently only `pytest` and `pytest-cov` are listed in `pyproject.toml`. Introduce a `tests/fuzz/` directory with one hypothesis test per parser entry point.

### P2-5 — `secure_bytes._zeroize` uses a Python loop
- **Location:** `src/eopx/format/secure_bytes.py:24-29`.
- **Description:** A tight Python `for i in range(len(buf)): buf[i] = fill` is unnecessarily slow for large buffers and not constant-time. While Python cannot guarantee zeroization anyway, replacing with `ctypes.memset` provides a faster zero and is closer to "real" wiping intent.
- **Recommendation:** Use `ctypes.memset(ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf)), fill, len(buf))` for the inner loop.

### P2-6 — `card_fingerprint` is defined as `SHA3-256(domain || (s % 13 for s in symbols))`
- **Location:** `src/eopx/vault/verify_card.py:21-29`, `pwa/src/lib/crypto.ts:34-44`.
- **Description:** Implementations match exactly (good); however, when symbols are produced by an out-of-distribution decoder that yields negative ints, Python's `% 13` returns a positive residue while the TS path uses `((v % 13) + 13) % 13`. The two paths agree mathematically, but it would be safer to validate `0 <= s < 13` first and raise.
- **Recommendation:** Add an explicit `if not (0 <= s < 13): raise ValueError` guard on both ends and a parity test.

### P2-7 — `app.py` `mode` is set from a config field at server start and cannot change per request
- **Location:** `src/eopx/server/app.py:_run_protocol`.
- **Description:** Mixing operator-supplied `spinor_hex` / `known_seed_hex` with HTTP-supplied frames creates an unusual trust model (single global vault per process). Not a defect, but worth surfacing in an audit: the docs should make clear that `app.py` is a dev/demo tool, not a production multi-tenant service.

### P2-8 — `dataclasses.asdict` over `GenesisSeal` could surface unexpected fields if extended
- **Location:** `src/eopx/genesis_token.py:_seal_message` / `GenesisSeal.to_dict`.
- **Description:** Future additions to `GenesisSeal` will be silently included in `to_dict` output but not in `_seal_message`, breaking signature compatibility unintentionally.
- **Recommendation:** Add an explicit "canonical fields" tuple checked by a unit test that enumerates exactly the signed fields.

---

## Module Health Map

| Module | Status | Coverage | Notes |
|--------|--------|----------|-------|
| `src/eopx/format/shamir.py` | Good | High (`tests/test_shamir.py`) | Clean GF(2⁸); TS port matches Python via vectors. |
| `src/eopx/format/secure_bytes.py` | OK | High | Best-effort zeroization; documented limits. |
| `src/eopx/format/keys.py` | OK | Indirect | Windows chmod is a no-op (P1-4). |
| `src/eopx/format/eopx_format.py` | OK | High | `kyber_pk_fp == ZEROS_32` bypass (P1-9). |
| `src/eopx/format/visual_sharding.py` | Good | High | AAD binding + per-shard KEM; KDF duplication (P2-3). |
| `src/eopx/metatron/*` | Good | High | Hardware path (ArUco, color grid) covered by `test_metatron_*`. |
| `src/eopx/vault/unlock.py` | Good | High | Pure HKDF chain. |
| `src/eopx/vault/verify_card.py` | Good | High | Constant-time. |
| `src/eopx/vault/sas.py` | Good | High | Proper challenge TTL. |
| `src/eopx/vault/enroll.py` | Good | High | Domain separation clean. |
| `src/eopx/vault/genesis.py` | OK | High | Ceremony attestation gap (P1-8). |
| `src/eopx/vault/migrate.py` | Mixed | High for happy path | `verify_proof_with_tag` stub (P0-1); timestamp not signed (P1-6). |
| `src/eopx/recovery.py` | Good | Very high | Argon2 tiers may be too heavy on mobile (P1-5). |
| `src/eopx/server/app.py` | Risky | Medium | P0-2, P0-4, P0-5, P0-6, P1-7. Demo-grade. |
| `src/eopx/server/pwa_api.py` | OK | High | CORS validation (P1-1) and size enforcement (P0-5). |
| `src/eopx/server/anchor_api.py` | OK | High (`test_anchor_api.py`) | Bootstrap fallback (P1-2); key file mode (P1-3); race (P2-1). |
| `src/eopx/server/http_delegate.py` | Mixed | High | Replay protection gap (P0-3). |
| `src/eopx/server/sequence_state.py` | Good | High | SQLite-locked correctly. |
| `pwa/src/lib/recovery.ts` | Good | High (`recovery.test.ts`) | Wire-compatible with Python. |
| `pwa/src/lib/enrollment.ts` | Good | High | Vectors in `vectors.json`. |
| `pwa/src/lib/shamir.ts` | Good | High | Identical GF table to Python. |
| `pwa/src/lib/crypto.ts` | Good | High | Single source of truth for HKDF/SHA3 in TS. |
| `sdk/typescript/` | Light | Light | Verifier-only by design; expand README on intended scope. |
| `sdk/python/` | Light | Light | Standalone verifier; no tests in the SDK subtree. |
| `tests/` | Extensive | 359 tests claimed | Cannot collect locally without `pqcrypto` (P2-2); no fuzz/property tests (P2-4). |

---

## Scalability Bottlenecks

1. **Anchor SQLite + module-level lock** — `SequenceState` serialises every anchor via a Python `threading.Lock` + SQLite `BEGIN IMMEDIATE`. Fine up to ~100 anchors/sec on commodity hardware; falls over under burst (e.g. simultaneous Genesis ceremony of 88 vaults). Mitigation: front the anchor API with a queue (Redis, NATS), or migrate the state store to PostgreSQL with `SERIALIZABLE` once the schema stabilises. The protocol intentionally requires a monotonic counter so horizontal scaling is bounded by the writer.
2. **Argon2id on mobile** — Cloud tier (128 MiB × 4 iterations) takes 10-30 s on mid-range Android. UX impact compounds for 2-of-3 recovery if both shares use card-pin or passphrase. Mitigation: ship a "mobile" tier (32 MiB × 3) and let the wire format record it (already supported, see `kdf` field).
3. **Eidolon Lock Server is a SPOF** — `HTTPDelegateSequenceState._fetch_next_vault_number` blocks on `lock.eidolon-connect.xyz`. If the lock server is down, no new vaults can be anchored, even though existing vaults still verify. Mitigation: add a configurable fallback to local SQLite when the lock server is unreachable beyond a configurable grace period (and reconcile on recovery), or expose the lock server behind a CDN-cached read-only mirror.
4. **`.eopx` CDN-friendliness** — `.eopx` files are static PNGs with embedded text chunks; they are already byte-for-byte cacheable. Verification is offline. No bottleneck here, but no signed `Cache-Control: immutable` headers are emitted by `app.py`, so production deployment should make sure the reverse proxy adds them.
5. **`cv2.imdecode` + Argon2id on the same Python worker** — `pwa_api.py` runs OpenCV + post-quantum + Argon2 in the same thread. A single 12 MB upload pushes CPU + memory pressure into the same process. Mitigation: offload image decode to a separate worker pool, or split the API across two services (extract vs. KDF).
6. **No CDN-cacheable Genesis position document** — `/api/v1/genesis/positions` is computed on every call. Cheap (a single HKDF expansion) but worth caching, especially if the position list becomes a public anchor that wallets refresh frequently.

---

## Action Plan

Ordered list for publication readiness; each item is gated by the prior one for a vanilla rollout, but most can run in parallel.

1. **Remove or implement `verify_proof_with_tag`** (P0-1). Export-time fix is the cheapest path; do not ship the misleading "witness" semantics.
2. **Disable raw-frame persistence in `server/app.py`** (P0-4) and tighten upload size handling (P0-5).
3. **Decide the fate of `server/app.py` mobile crypto** (P0-2). Either retire it in favour of the PWA, or align its KDF chain bit-for-bit with `vault/unlock.py` and add cross-test vectors.
4. **Add a request-rate limit to all Flask blueprints** (P0-6) and lock the anchor API down to authenticated callers in production.
5. **Sign timestamps in HMAC requests to the lock server** (P0-3) and document the resulting wire format jointly with the Eidolon team.
6. **Sign `timestamp` field inside `MigrationProof` Fiat-Shamir hash** (P1-6) and add a `consumed-nonce` window on the target.
7. **Tighten Kyber fingerprint check in `EopxManifest.from_chunks`** (P1-9).
8. **Production-only env-var enforcement in `anchor_api.bootstrap_from_env`** (P1-2) and DACL-aware key persistence (P1-3, P1-4).
9. **Document CORS allow-list rules and add `--cors '*'` rejection** (P1-1).
10. **Ship an Argon2 mobile tier** (P1-5) with a benchmark CLI and updated docs.
11. **Add ceremony-launch attestation to Genesis Protocol E** (P1-8) with PWA parity.
12. **Refactor the three `_hkdf_sha3_256` copies** (P2-3); add fuzz / property tests for `.eopx`, Metatron and recovery parsers (P2-4); make `pqcrypto` import lazy so the pure-Python tests collect (P2-2).
13. **Re-run the full test suite (target: `pytest -q tests/`) on a clean environment with `pqcrypto` installed; capture coverage and post-publish baseline.**
14. **Final ops review** — reverse proxy headers, log redaction (no master keys in any logger; current usage is clean), and key-rotation procedure for the deployment Dilithium key.

---

## Threat-Model Completeness

| Documented threat (whitepaper §9.1) | Code mitigation found | Status |
|---|---|---|
| Private sheet physical theft | Not mitigated by code (paper-only) | OK by design |
| Public card photography | One-way HKDF in `metatron/public.py` and `vault/verify_card.py` | OK |
| `.eopx` tampering | SHA3-512 image hash + Dilithium signature in `format/eopx_format.py` | OK |
| Recovery share theft | Shamir + per-kind AEAD; AAD binds index/group | OK |
| Migration MITM | NIZK bound to `(source_lock, target_lock)`; constant-time check | OK (modulo P1-6) |
| Quantum master-key recovery | ML-DSA-87, ML-KEM-1024, SHA3 throughout | OK |

**Threats observed in code that are NOT in the whitepaper:**

* Replay of signed lock-server requests (P0-3).
* Replay of `MigrationProof` via timestamp manipulation (P1-6).
* DoS / disk fill via `app.py` `/api/frame` and `/api/register_psnx` (P0-4, P0-5, P0-6, P1-7).
* Operational drift between `app.py`'s inline `esoptron.mobile.*` KDF chain and the canonical `esoptron.vault.*` chain (P0-2).
* Misconfigured anchor service silently producing dummy Genesis positions (P1-2).
* Ceremony sheet impersonation in Protocol E (P1-8).

---

## Sign-off

The cryptographic core is **strong** and reflects significant care: well-named domain separators, exact PWA parity, constant-time equality, CSPRNG everywhere it matters, and a clean Shamir implementation. The **operational surface** (Flask apps, lock-server delegation, deployment key handling) is the area that demands the most work before public release. Treat the items in *Action Plan* §1-5 as blockers and §6-10 as strongly recommended pre-publication.

— End of report —
