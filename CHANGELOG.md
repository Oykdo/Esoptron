# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* **Figurative relic figure.** `eopx.collection.figure` draws each Codex relic
  as the *object it is* — a mirror, key, ember, lantern, crown… (12 bespoke
  ASCII silhouettes). The fixed silhouette makes the object recognisable; its
  interior is filled **deterministically** from the card fingerprint (the
  relic's unique texture); and a **bounded** (`LIVING_INTERIOR_CAP`) number of
  interior cells *shimmer* with the relic's real, current ledger state
  (controller + seq) — a *living* face. `render_relic_figure` is the frozen
  "at the mint" face (what a printed badge would carry);
  `render_living_relic_figure` / `figure_rows(..., state_bytes=, activity=)` is
  the relic "now"; `figure_drift` measures the shimmer. The Eidolon relics menu
  and `scripts/show_relic_sigils.py` / `relic_status.py` now render these
  figures. Brand only, never security — the interior is a hash of public state
  and the shimmer is a visual hint, not a proof (POSITIONING). The earlier
  abstract `render_living_sigil` / `sigil_drift` randomart remains available as
  a secondary fingerprint view.
* **PWA path-mount deploy kit (`/pwa/`).** The PWA now builds for a path-mount:
  `vite.config.ts` `base` defaults to `/pwa/` (override with `VITE_BASE`), and
  the API base is configurable via `VITE_API_BASE` (mirrors the existing
  `VITE_ANCHOR_URL`). New `deploy/nginx-pwa.conf` (static front-end + `/pwa/api/v1/`
  proxy to the pwa_api), `deploy/deploy_pwa.sh` (build → upload → reload), and
  `docs/guides/deploy_pwa.md`.
* **`claim_relic.py` auto-records the public claim.** On a successful claim it
  upserts a `relic_claims.json` entry (`key` + `artifact_id_hex` +
  `controller_pub_hex` — public only, no secret) at `$ESOPTRON_RELIC_CLAIMS`
  (or `./relic_claims.json`, or `--claims-file`), so the Eidolon relics menu
  shows the relic as held with no manual step. The sealed controller secret
  still goes to its own offline file as before.
* **Committed Genesis block is now the default in code.**
  `eopx.genesis_token` exposes `COMMITTED_BTC_BLOCK_HASH_HEX` /
  `COMMITTED_BTC_BLOCK_HEIGHT` (block 951848, hash `…d43ee6`) and a
  `resolve_btc_block()` helper that returns the committed block with
  `committed=True` and **no configuration** — the CLI, the Eidolon relics/eggs
  menus and the SDK now serve the frozen distribution out of the box. The
  `ESOPTRON_BTC_BLOCK_HASH/HEIGHT` env vars remain a testing override (reported
  as `committed=false` when they differ from the committed block). The local
  **"demo block" fallback is removed**; the live anchor still requires the env
  on first bootstrap so a persisted genesis is never silently re-derived.
  Pinned by `tests/test_committed_block.py` (reproduces the documented
  `catalog_commitment`); `docs/GENESIS_COMMITMENT.md` updated + re-signed.
* **Figurative golden-egg figure (ASCII).** `eopx.egg_figure` draws a Golden
  Egg as an egg — a fixed silhouette with an interior filled *deterministically*
  from the (immutable) `egg_hash`. Unlike a relic, an egg is **sealed**, so the
  figure is **frozen** (no living shimmer) — honouring the egg's immutable-seal
  pitch. `egg_figure_rows(egg_hash_hex)` / `render_egg_figure(egg)`; the Eidolon
  Golden Eggs menu now renders it, tinted by tier. Brand only, never security.
* **Golden-egg emblem engraving.** `eopx.metatron.render_egg_emblem(egg)`
  draws a tier-tinted egg insignia (glyph + `GE-NNN · Tier` caption);
  `scripts/print_sheet.py --egg-vault <hex>` engraves it in the right margin
  beside the Metatron cube when the vault wins an egg on the committed Genesis
  block. Brand/legend only — the signed `EggSeal` remains the cryptographic
  record.
* **`docs/GENESIS_COMMITMENT.md`** — the committed Genesis Bitcoin block
  (height 951848) that freezes all deterministic distributions; hash-tracked
  in `SPECS.SHA3-256`.
* **EPX-K — Keys of Office.** Each Codex relic now confers one verifiable
  ecosystem capability (a "Council of Twelve"). The office follows the relic:
  the EPX-T controller currently recorded for a relic's `artifact_id` is the
  office-holder, and a power is exercised by signing a domain-separated
  statement (ML-DSA-87) verified against that live controller. New module
  `eopx.capabilities`, anchor endpoints `GET /capability`,
  `GET /capability/<cap_id>`, `POST /capability/verify`, spec
  `docs/specs/EPX-K_keys_of_office.md`.

### Changed

* **Codex relics 8–12 renamed to Latin** for naming consistency with relics
  1–7: `le_masque`→`persona` (Persona), `atre`→`focus` (Focus),
  `le_seuil`→`limen` (Limen), `le_phenix`→`phoenix` (Phoenix),
  `mot_de_garde`→`tessera` (Tessera). This changes their `artifact_id`,
  badge seed, and the catalog commitment — done before any mint on the
  committed Genesis block. EPX-C spec updated and re-signed.

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
