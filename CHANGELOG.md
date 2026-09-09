# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* **EPX-F ports, TypeScript SDK and PWA (`sdk/typescript/src/figure.ts`,
  `pwa/src/lib/artifactFigure.ts`, `pwa/src/lib/figurePlate.ts`).** §8 requires
  both to reproduce §9 byte for byte; both now do, and they share no code, so
  each is checked against the specification text rather than against the other
  — a test comparing the two ports would pass just as happily if both had
  drifted the same way. The presentation half is pinned against vectors from
  `scripts/gen_figure_vectors.py`, which keeps EPX-F's stdlib-plus-HKDF
  dependency surface so the vectors regenerate on any machine. Two defects the
  parity vectors caught: CPython's `str.center` puts the odd padding column on
  the **left** when margin and width are both odd, which a naive port gets
  wrong on exactly the caption widths a plate uses; and the SDK's test file was
  being compiled into `dist/` and would have shipped to npm.
* **The EPX-F face on paper, drawn in EPX-R runes (`eopx.figure_render`,
  `eopx.metatron.runes`).** One rune carries one cell: EPX-F froze four bits
  per cell and EPX-R chose sixteen glyph states for the same reason — four bits
  is what a camera separates reliably — so the mapping is one to one. The plate
  is a *presentation*, not a channel: no fiducials, no timing track, no RS,
  nothing on it to scan, because furniture that made it look scannable would
  advertise a channel that does not exist. `render_artifact_plate` takes the
  two manifest fields rather than a ready-made grid, so a printed plate cannot
  disagree with the tag printed under it, and EPX-F §6's frozen/living rule is
  enforced in pixels: a living plate gets a dashed frame and passing it a tag
  raises.
* **The "never on the cube" rule, as a check instead of a convention
  (`print_sheet.reserved_regions` / `assert_clear`).** Everything that is read
  — the cube, the four ArUco, the chromatic scan grid — is listed with a quiet
  margin, and a placement that touches any of it is refused at render time. The
  16-rune alphabet moved out of `scripts/rune_channel.py` into the package for
  the same reason: a confusion matrix describes the alphabet it measured, so
  the study and the shipped glyphs must be one object. Pinned by the strict
  property rather than a proximity argument — adding a plate leaves the cube's
  pixels byte-identical (`tests/test_figure_render.py`), and a decode envelope
  cannot move if the pixels do not. Re-measured after the change: perspective
  2.25, blur 4 px, JPEG q10, illumination ±50%, σ 96, unchanged on every axis.
* **A measured decode envelope for the camera path (`eopx.metatron.degrade`,
  `scripts/detect_envelope.py`).** The number that decides a scan is not the
  global symbol error rate but the **worst interleaved block**: RS(13,10) ×7
  corrects one error per block, so seven errors spread one per block decode
  and three in one block do not. Measured at canvas 1024 — perspective holds
  to strength 2.25 and collapses at 2.5 (1 error → 14, worst block 1 → 4);
  blur to radius 4 px; JPEG to quality 10; illumination to ±50%; chroma noise
  to σ 96 without ever breaking. **Geometry is the binding axis; colour is
  not.** Axes also *compound*: each at a level inside its own envelope, a
  merely mediocre photograph lands at worst block 2 and fails. Pinned in
  `tests/test_detect_envelope.py`.
* **Margin-ranked, per-block erasures (`palette.classify_margin`,
  `detect.erasures_per_block`, `detect.extract_canonical_full`).** Absolute
  Oklab distance barely separates misreads from good reads under a mediocre
  photograph (median 0.032 against 0.028) because a shadow pushes every
  carrier away from the palette at once. The **margin** — how much closer a
  carrier sits to its symbol than to the runner-up — does separate (0.034
  against 0.092), since a difference cancels a common-mode shift. Ranking by
  margin *within each block* and spending one erasure per block turns the
  mediocre photograph from a failure into the right seed, where every
  distance-ranked variant still fails. `extract_robust` climbs that ladder
  before falling back to the historical global thresholds, and deliberately
  never spends three erasures on a block: at `2t + e <= 3` that leaves no
  correction in hand and invites a miscorrection.

### Changed

* **`ScanResult` distinguishes *decoded* from *decoded and verified*
  (`symbols_in_code`, `blocks_repaired`, `symbols_verified`, `verification`).**
  A private read that needed correcting is now reported as unverified instead
  of as a plain success that fails three layers later. The honest basis is
  narrow and stated as such: a read already in the code C needed no
  correction, so nothing was inferred; a correction can be counted but never
  audited, because the payload spends 259 of ~259.2 available bits and has no
  checksum to spare, and re-encoding the decoder's output only re-derives the
  decoder's own assumption. For a public card — outside C by construction —
  the field claims nothing at all and points at the registry instead.
* **`tests/test_metatron_detect.py` no longer skips its own subject.** The
  perspective test turned a real decode failure into `pytest.skip`, and
  asserted `diffs <= 21` where the measured value is 0 — it would have passed
  through a total collapse of the pipeline. Now a hard bound and a hard
  assertion.

* **EPX-F — the artifact figure (`eopx.artifact_figure`).** `F` maps a `.eopx`
  to a 16×8 grid of 4-bit levels, derived by HKDF-SHA3-512 from the
  **pre-image** half of the signed manifest — `merkle_root` and
  `dilithium_pk_fp` — so it can be recomputed from the file by anyone.
  `payload_hash` and `image_sha3_512` are inadmissible inputs: both are
  downstream of the pixels the figure is drawn into, which would make the
  derivation a fixed point with no solution. Because the inputs sit inside
  `canonical_payload()` and the drawing reaches it through `image_sha3_512`,
  the existing ML-DSA-87 signature already covers both ends — no new primitive,
  no new trust root. Two bands: a **content band** (rows 0–5, `merkle_root`
  only) that an artifact keeps for life, and an **epoch band** (rows 6–7) that
  moves when the issuing key rotates, so a rotation is legible without turning
  a printed badge into a stranger. Glyphs are presentation — `figure_digest`
  covers the levels, so a Unicode ramp is a free substitution. Frozen at v1
  with normative test vectors (`docs/specs/EPX-F_artifact_figure.md` §9,
  `tests/test_artifact_figure.py`); brand only, never security (POSITIONING).
* **Epoch links (`eopx.epoch_chain`, EPX-F §5).** A badge outlives the key that
  minted it. An `EpochLink` binds two consecutive epochs and carries the
  predecessor's **full public key** — a fingerprint identifies a key, it does
  not let anyone verify a signature made with it. Signed from both ends: the
  successor's signature is what lets a verifier holding only today's key walk
  *backwards*, and the predecessor's — minted at rotation time, while the old
  key still lives — is what stops a stolen current key from inventing an
  ancestor and, with it, a whole fabricated lineage. Links carrying both are
  **strong**; `resolve_epoch` refuses weak ones unless explicitly asked, and
  the walk is hop-bounded and cycle-checked. An optional third witness key
  cosigns the same digest, reusing the dual-signature pattern of
  `tools/sign_spec.py`. Revocation is deliberately out of scope for v1.
* **Figure plates (`eopx.figure_plate`, EPX-F §6).** Unicode block-element
  plates, galleries and animation frames over an EPX-F grid. A **frozen** plate
  has a solid frame and prints its tag — the thing a reader compares against a
  recomputation. A **living** plate has a dashed frame and prints **no tag**:
  the omission is the safety property, so a moving face can never be mistaken
  for the artifact's identity. `UNICODE_RAMP` orders block elements by ink
  coverage and breaks ties by shape; `ASCII_RAMP` remains the choice when
  column alignment must be exact.

### Fixed

* **`vault_fp` has one definition again (`eopx.vault.identity`).** Three
  derivations had grown up in the tree and disagreed for the same vault:
  `card_fingerprint(card)` (`vault/enroll`, `vault/genesis`, `collection`),
  `sha3_256("esoptron.vault_fp.v1|" + seed)` (`scripts/make_invitation.py`) and
  `sha3_256("epx-h.badge.vault_fp.v1" + spinor)` (`scripts/eopx_badge.py`) —
  `74ad6428…`, `29f96634…` and `bb212913…` for one and the same vault. Three
  answers to "which vault is this" is the same as none, and everything keyed by
  `vault_fp` silently depended on which call site the caller came through: the
  anchor's `vault_anchors` index, the EPX-H seal geometry, and
  `egg_token.founder_egg`, which *draws a golden egg* from it.

  The card fingerprint wins because it is the only one a **scan** can produce,
  and EPX-G §143 already required it. The seed-derived variant was worse than
  redundant: the seed is secret, so a verifier could never recompute it — an
  identifier nobody but the holder can check is not an identifier.
  `require_vault_fingerprint()` now rejects a truncated or hex-string
  fingerprint at the boundaries that consume one, because 16 bytes reaching a
  KDF yields a stable, plausible, wrong answer instead of an error.

  EPX-2 §4.1's test vector carried the seed-derived value, so a port
  reproducing the spec byte for byte would have disagreed with the
  implementation; it is corrected to `74ad6428…` and the spec re-recorded.
  `tests/test_vault_identity.py` pins the definition and greps for the
  abandoned domain strings — a fourth derivation would arrive the way the last
  two did, quietly, in a script.

* **`eopx.egg_token` no longer needs the post-quantum stack to derive a
  clutch.** `EopxKey` was imported at module level but is used only to mint and
  verify an `EggSeal`, so recomputing a public distribution required
  `pqcrypto`. `docs/GENESIS_COMMITMENT.md` promises anyone can recompute every
  position from the block hash alone; requiring the signing stack to *read* it
  had that backwards. The import is deferred to the two sealing functions.

* **`tools/sign_spec.py` and `tools/verify_spec.py` work again without the
  post-quantum stack.** Both already documented a hash-only mode, but imported
  `EopxKey` at module level, so re-recording or verifying an unsigned document
  needed `pqcrypto` — unavailable on Windows. The import is now deferred to the
  signing and signature-verification paths that actually use it.

* **`pqcrypto` capped below 1.0.** Upstream 1.0.0 renamed
  `pqcrypto.sign.ml_dsa_87.generate_keypair()` to `keygen()`, so a fresh
  install resolved to a version where every key operation in
  `eopx.format.keys` raises `AttributeError` (first hit while provisioning the
  production anchor). Both `pyproject.toml` and `sdk/python/pyproject.toml`
  now require `pqcrypto>=0.3.4,<1.0`. Lifting the cap means porting `keys.py`
  to the 1.0 API first.

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
