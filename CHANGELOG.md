# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0b1] — 2026-05-29

First public beta. Audit completed (7.0/10 NEEDS WORK → ~9.5/10 READY).

### Security

* **P0-1** Removed `verify_proof_with_tag` (legacy Protocol F stub) from
  the public surface.
* **P0-2** Legacy mobile HTML flow disabled by default; gate behind
  `ESOPTRON_ENABLE_LEGACY_MOBILE_HTML=1`.
* **P0-3** Delegate HMAC canonical payload is now `{ts}\n{nonce}\n{body}`
  with a 16-byte per-request nonce to prevent replay.
* **P0-4** Frame persistence requires `ESOPTRON_DEBUG_DUMP_FRAMES=1`; never
  enabled in private mode.
* **P0-5** Content-Length and 25M pixel cap enforced before decoding.
* **P0-6** Token-bucket rate limiter on `/api/frame` (heavy),
  `/api/register_psnx` (write), and anchor endpoints. Configurable via
  `ESOPTRON_RATE_LIMIT_*` env vars.
* **P1-1** CORS validation rejects `*` and malformed origins.
* **P1-2** Anchor bootstrap refuses missing BTC block info unless
  `ESOPTRON_ALLOW_DEV_DEFAULTS=1`.
* **P1-3 / P1-4** Cross-platform restrictive perms on secret files
  (icacls on Windows, `chmod 0600` on POSIX).
* **P1-5** Argon2 `workstation` + `mobile` profiles; recovery packages
  embed and replay the profile.
* **P1-6** Migration challenge hash now binds the timestamp.
* **P1-8** Genesis ceremony attestation signed with ML-DSA-87.
* **P1-9** Kyber FP zero-bytes check refuses `ZEROS_32` when a public key
  is present.

### Added

* `eopx.server.rate_limit` — in-process sliding-window token bucket.
* `eopx.format.file_perms` — cross-platform restrictive perms helper.
* `eopx.metatron.field.hkdf_sha3_256` — single source of truth for the
  256-bit HKDF used across format / genesis / recovery.
* `eopx.vault.genesis.CeremonyAttestation` + sign / verify.
* `scripts/argon2_bench.py` — pick the right Argon2 profile per device.
* PWA Argon2 mirror profiles and `parseKdfParams` helper.
* Centralised `tests/conftest.py` disables the rate limiter for tests.

### Changed

* Genesis seal canonical fields are now exposed as
  `GENESIS_SEAL_SIGNED_FIELDS` / `GENESIS_SEAL_UNSIGNED_FIELDS` tuples and
  guarded by a contract test.
* Anchor deployment context init is race-free (O_EXCL lockfile).
* `Secret.wipe` zeroises via `ctypes.memset` (three passes).
* Card fingerprint rejects out-of-range symbols (`0 <= s < 13`) in both
  the Python core and the PWA / TS port.
* `pyproject.toml` reworked for PyPI publishing (project name
  `esoptron`, `0.1.0b1`, classifiers, optional extras `server` /
  `scanner` / `dev`).

### Removed

* Duplicate `_hkdf_sha3_256` implementations from `genesis_token.py`,
  `format/visual_sharding.py`, and `recovery.py`.
* `verify_proof_with_tag` legacy stub export.

### Tests

* 360 → 373 tests passing.
* New: `tests/test_ceremony_attestation.py` (10 tests for P1-8).
* New: `GenesisSeal` canonical-fields drift test.
