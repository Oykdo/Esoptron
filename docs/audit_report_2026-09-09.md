# Esoptron Ecosystem Audit Report — re-audit

**Date:** 2026-09-09
**Scope:** Re-verification of every finding in `docs/audit_report_2026-05-28.md`
against the current tree, plus findings raised since.
**Supersedes:** nothing. The 2026-05-28 report is a dated record of what was
true then and is left untouched; this document records what is true now.

**Lineage.** Three audit documents precede this one and they are not
interchangeable: `audit_report_2026-05-28.md` is the P0/P1/P2 security sweep
re-verified here; `audit_report_2026-05-30.md` is a hygiene and
release-engineering snapshot; `audit_ecosystem_triangulation_2026-05-31.md`
covers the cross-repo seams. **Only the 05-28 sweep was re-verified.** The
counts below are relative to it, not to the project as a whole. Spot-checked
from the 05-30 report: its three high-priority items (`RELEASE.md`, a
pre-commit configuration, encoding and manifest checks wired into CI) are all
present, and its low-priority §4.3.1 (property-based fuzz tests) is done. Its
medium-priority section and the 05-31 triangulation were not re-verified.

---

## Declared conflict of interest

Several of the fixes assessed below were written on the same day as this
re-audit, by the same author. **An assessment of one's own patch is not an
independent audit.** Every such item is marked *(same-day)* and should be
treated as a claim to be checked, not as a clearance. The items inherited from
the previous report — the server hardening, the migration protocol, the key
handling — were fixed by others before this session and were verified here by
reading the current code.

---

## Executive Summary

| Metric | 2026-05-28 | 2026-09-09 |
| --- | --- | --- |
| Findings open, 05-28 sweep only | 23 (P0: 6, P1: 9, P2: 8) | **0** |
| Of the original 23 | — | 23 fixed |
| New findings raised since | — | 9, all fixed |
| Test files | — | 62 |
| Suite (Windows, local) | could not collect | **901 collected, green**, 8 skipped |
| CI (Linux/Win/macOS ×2 + TS + PWA) | — | green, 8/8 jobs |

The previous report's central judgement — *"the cryptographic core is strong,
the operational surface demands the most work"* — has been acted on. All six P0
items are closed or reduced, and the Flask surface now has rate limiting,
decompression-bomb caps, CORS wildcard rejection, replay-resistant HMAC
signing, and a production gate on the anchor's dummy-block fallback.

Two structural problems found since are worth more attention than anything left
on the original list, because neither was visible as a bug: **an identifier with
three definitions**, and **a frozen wire format whose parameters were read from
a dependency at import time**. Both are now fixed. Both had the same shape —
something that looked settled was not, and nothing failed to say so.

---

## Part 1 — Disposition of the 2026-05-28 findings

### Closed (19)

| ID | Finding | Evidence |
| --- | --- | --- |
| P0-1 | `verify_proof_with_tag` cryptographic stub, publicly exported | Removed. `vault/migrate.py:383` carries a NOTE recording the removal; no longer in `vault/__init__`. |
| P0-3 | Lock-server HMAC did not cover the timestamp | `http_delegate._sign` now signs `f"{timestamp}\n{nonce}\n{body}"` (`:289-303`). A nonce was added beyond the recommendation. |
| P0-5 | Unbounded upload / decompression bomb | `Image.MAX_IMAGE_PIXELS` set explicitly (`app.py:988`, `pwa_api.py:53`), `MAX_CONTENT_LENGTH` enforced, and an explicit `h * w > _MAX_IMAGE_PIXELS` check returning 413 (`app.py:1100`). |
| P0-6 | No rate limiting on any endpoint | `server/rate_limit.py` (token bucket); `@rate_limit(...)` applied across `app.py`, `pwa_api.py`, `anchor_api.py`. |
| P1-1 | `--cors '*'` accepted | `_validate_cors_origin` (`pwa_api.py:340`) refuses `*` and any origin containing it, and requires an explicit scheme and host. |
| P1-2 | Anchor silently bootstrapped a dummy BTC block | Now requires `ESOPTRON_ALLOW_DEV_DEFAULTS=1` to fall back (`anchor_api.py:410-423`). |
| P1-3 | Deployment secret key written without an explicit mode | `_persist` calls `restrict_secret_file(self.path)` (`anchor_api.py:198`). *See N-4: a residual window remains.* |
| P1-4 | `EopxKey.save` chmod is a silent no-op on Windows | `format/file_perms.py`: POSIX `0o600`, Windows DACL via `icacls`, warning when neither succeeds. |
| P1-5 | No Argon2 mobile tier | `ARGON2_PROFILES` now carries `workstation` and `mobile` (`recovery.py:83-92`). |
| P1-6 | `MigrationProof.timestamp` not bound into the proof | `_compute_challenge_hash` mixes `struct.pack(">d", timestamp)` into the Fiat-Shamir hash (`migrate.py:145`). |
| P1-8 | No ceremony-launch attestation (Protocol E) | Implemented in `vault/genesis.py`; covered by `tests/test_ceremony_attestation.py`. |
| P1-9 | `kyber_pk_fp == ZEROS_32` bypassed the consistency check | The zero fingerprint with a key present now raises (`eopx_format.py:163-167`), as does a missing chunk. |
| P2-1 | `load_or_init` key-file race | `os.O_CREAT \| os.O_EXCL` claim (`anchor_api.py:124`). |
| P2-2 | Suite could not collect without `pqcrypto` | *(same-day)* Import deferred behind `_backend()` in `format/keys.py`; pure-Python modules import without the stack. Applied to five other modules the same day. |
| P2-3 | `_hkdf_sha3_256` duplicated three times | One definition in `metatron/field.py`. |
| P2-4 | No fuzz / property tests | `tests/test_property_fuzz.py`; `hypothesis` is a declared dev dependency. |
| P2-5 | `_zeroize` used a Python loop | `_ctypes_memset` with a documented fallback (`secure_bytes.py:25-32`). |
| P2-6 | `card_fingerprint` coerced instead of validating | Explicit `0 <= s < 13` guard raising `ValueError` (`verify_card.py:40`). |
| P2-8 | `GenesisSeal` signed-field drift | `tests/test_genesis_token.py:322` enumerates the canonical fields. |

### Closed later the same day (3)

The three residuals below were written up as partial, then closed in the same
session. They are kept as separate entries rather than folded into the table
above because the shape of each residual is the interesting part.


**P0-4 — raw frame persistence.** The reported `out/last_upload.jpg` is gone and
the upload dump is now gated (`_DEBUG_DUMP_FRAMES and config.mode != "private"`,
`app.py:1080`), exactly as recommended. **But two diagnostic writes in the
decode path are not gated at all**: `_save_diagnostic_img(pil,
"diagnostic_cube_crop.png")` (`app.py:219`) and `_save_diagnostic(rect_a4,
cfg)` (`app.py:231`) write to `out/` on every decode, and `_save_diagnostic`
takes `cfg` without consulting `cfg.mode`. The residual is the more sensitive
half of the original finding: the cube crop is precisely the decodable region
of a PRIVATE sheet, written to a predictable shared path. See N-3.

**P0-2 — divergent `esoptron.mobile.*` KDF chain.** Not removed, but no longer
shipped: the `/scan` HTML route is disabled by default and gated behind
`ESOPTRON_ENABLE_LEGACY_MOBILE_HTML=1`, and the module docstring now opens with
"DEV / DEMO ONLY". Five `esoptron.mobile.*` SHA-256 info strings remain in the
file (`app.py:878-889`). The exposure is closed; the divergence is not, and a
second chain that can be re-enabled by an environment variable is a chain that
will eventually be re-enabled.

**P1-7 — unauthenticated `psnx` registry.** Now rate-limited (`@rate_limit`) and
documented as demo-grade, which addresses the DoS half. There is still no
authentication on the write path, as the recommendation asked for.

### Reclassified (1)

**P2-7 — `app.py` single-tenant trust model.** The report asked only that the
docs make the demo status clear. The module docstring now leads with "DEV /
DEMO ONLY … NOT suitable for" production. Closed as documented.

---

## Part 2 — Findings raised since 2026-05-28

### N-1 — `vault_fp` had three definitions *(same-day fix)*

**Severity: high.** Three derivations coexisted and disagreed for one vault:

```
card_fingerprint(card)                        74ad6428…7123f910   vault/enroll, vault/genesis, collection
sha3_256("esoptron.vault_fp.v1|" + seed)      29f96634…b3bd96a5   scripts/make_invitation.py
sha3_256("epx-h.badge.vault_fp.v1" + spinor)  bb212913…cd5b02f2   scripts/eopx_badge.py
```

Everything keyed by `vault_fp` therefore depended on which call site the caller
had come through: the anchor's `vault_anchors` index, the EPX-H seal geometry,
and `egg_token.founder_egg`, which **draws a golden egg from it** — so an
attribution whose whole legitimacy rests on being a fair draw was a draw over an
identity nobody had agreed on.

EPX-G §143 already required the card fingerprint. It is also the only one of the
three a *scan* can produce, and the seed-derived variant could never be
recomputed by a verifier at all. Fixed in `eopx.vault.identity`; the abandoned
domain strings are now grepped for by `tests/test_vault_identity.py`.

### N-2 — the wire format took its parameters from the dependency *(same-day fix)*

**Severity: high.** `format/keys.py` read the six ML-DSA-87 / ML-KEM-1024 sizes
off `pqcrypto` at import time, and `eopx_format` validates a `.eopx` against
them — `pack` rejects a public key that is not `SIG_PUBLIC_KEY_SIZE` bytes,
`verify` rejects a signature that is not `SIG_SIGNATURE_SIZE`. The admissibility
rules of a **frozen** format therefore moved with whatever the installed library
defined; a backend rebound to another parameter set would have been followed
rather than refused. Sizes are now pinned to the FIPS 204 / FIPS 203 literals
and the backend is checked against them on first use.

### N-3 — diagnostic image dumps are ungated (OPEN)

**Severity: medium.** See P0-4 above. `app.py:219` and `:231` persist the
rectified A4 and the cube crop unconditionally. Recommendation: gate both on
`_DEBUG_DUMP_FRAMES` and refuse them outright when `cfg.mode == "private"`,
matching the treatment the upload path already received. Effort: under an hour.

### N-4 — the deployment key's temp file is written before it is restricted (OPEN)

**Severity: low-medium.** `_persist` writes the secret keys with
`tmp.write_text(...)`, renames, and only then calls `restrict_secret_file`
(`anchor_api.py:194-198`). The temporary file is created with the process
umask — commonly world-readable — and holds the Dilithium and Kyber secret keys
for the duration of the write and rename. Recommendation: create the temp file
with `os.open(..., O_CREAT | O_WRONLY | O_EXCL, 0o600)` so it is never
permissive, and keep `restrict_secret_file` as the cross-platform backstop.

### N-5 — a fourth derivation is *named* `vault_fp` (OPEN)

**Severity: low, but a trap.** `collection/forge.relic_vault_fp()` is
`sha3_256(relic.artifact_id())` — a fourth thing called a vault fingerprint. It
is legitimate: a relic is an artifact, not a vault, and the value only seeds the
seal geometry. But the name invites exactly the confusion N-1 was about, and the
grep guard in `tests/test_vault_identity.py` does not catch it.

**Do not change its value**: the twelve relics minted on the live anchor derive
their badge seals from it. Rename only — `relic_seal_seed` — and add a test
pinning the value across the rename.

### N-6 — the founder egg draw is not verifiable (OPEN)

**Severity: medium (integrity of a published claim).**
`docs/GENESIS_COMMITMENT.md` states that "anyone can recompute every position
from the block hash alone — no secret input". That is true for the 555-egg
clutch, which this audit re-derived and confirmed field for field (GE-111,
Lunar, position 106,186,118, `egg_hash f37eaeef…`). It is **false for the
founder draw**, whose input is the vault fingerprint and which the document
records only truncated (`f02cc7…d7be`). Nobody can check that GE-111 is the egg
vault #1 drew.

The vault in question has since been abandoned, so the attribution is moot — but
the promise is unqualified in a committed document, and the next attribution
must record the full fingerprint or it will inherit the same gap.

### N-7 — CI never installed OpenCV *(fixed)*

`ci.yml` installed `.[dev,server]` and nothing else; `cv2` was absent on all six
Python jobs and ~15 test modules failed at import. `main` was red from the merge
of #24 until it was fixed. The `typescript` and `pwa` jobs were unaffected,
which is how a fully red Python matrix went unnoticed.

### N-8 — a property test asserted something false *(fixed)*

`test_fewer_than_k_does_not_recover` generated secrets from one byte up and
asserted that a sub-quorum reconstruction differs from the secret. Below `k`
shares Shamir reveals nothing, which means the reconstruction is independent of
the secret and uniform — so for a one-byte secret it equals the secret one time
in 256. The assertion was false at that size and failed on macOS CI.
`min_size` is now 16.

### N-9 — a spec test vector contradicted another spec *(fixed)*

`EPX-2 §4.1` pinned `vault_fp_hex = 29f96634…`, the seed-derived value, while
`EPX-G §143` defines `vault_fp` as the card fingerprint. A port reproducing
EPX-2 byte for byte would have disagreed with the implementation. Corrected and
re-recorded in `SPECS.SHA3-256`.

---

## Part 3 — What this pass did not cover

An audit is worth as much as its stated limits.

* **No independent review of the same-day fixes** (N-1, N-2, P2-2). Declared above.
* **No dynamic testing of the deployed services.** The live anchor was queried
  read-only (`/anchor/api/v1/artifact/capability`: 12 relics, 0 instated, 0
  controller). No penetration testing, no load testing, no TLS or reverse-proxy
  review of the Caddy configuration on the VPS.
* ~~No review of the Eidolon side.~~ Partially lifted — see N-11. The
  golden-egg integration is still absent there (one mention, in
  `src/ui/launcher.py`), and no security review of that tree was attempted.
* **No cryptographic review of primitives.** The 2026-05-28 report's judgement on
  domain separation, constant-time comparison and CSPRNG use was accepted rather
  than re-derived.
* ~~No coverage measurement.~~ **Measured after the fact: 84%** over 7110
  statements (`--cov=src/eopx`). Now reported by CI on every run — reported,
  not gated: a threshold on a number that moves with every new module turns a
  signal into a chore. Weakest modules: `server/postgres_ledger.py` 15% (its
  tests skip without a DSN), `server/app.py` 58% (the demo tool),
  `server/http_delegate.py` 73%, `server/pwa_api.py` 75%. One result deserved
  a finding of its own — see N-10.
* **Scalability bottlenecks** from the previous report (anchor SQLite writer
  lock, Argon2 on mobile, the lock server as a SPOF) were not re-measured. Only
  the Argon2 item has a code change (the mobile profile).

---

## Part 4 — Recommended order

1. **N-3** — gate the diagnostic dumps. Smallest item, and it closes the last
   piece of a P0.
2. **N-4** — create the deployment key's temp file at `0o600`.
3. **N-6** — record the full vault fingerprint with the next founder attribution,
   and either qualify or repair the recomputability claim in
   `GENESIS_COMMITMENT.md`.
4. **N-5** — rename `relic_vault_fp` to `relic_seal_seed`, value unchanged,
   pinned by a test.
5. **P0-2 residual** — decide whether the legacy mobile chain is retired or kept.
   An environment variable is a decision deferred, not a decision made.
6. **P1-7 residual** — authenticate the `psnx` registry write path.

Nothing on this list blocks publication in the way the 2026-05-28 P0s did.

---

## Addendum, same day — two findings from measuring coverage

### N-10 — `metatron/local_rectify.py` is unreached, and the reason is a trade

**Severity: low as code, high as a question.** Coverage reported it at **0%**,
and the cause is not a missing test: **nothing imports it**.

*Corrected after first publication.* This entry first called it "an
unreferenced duplicate of `metatron/aruco.py`". That is wrong, and the mistake
buried the interesting part. It is a **third rectification strategy**, and the
most accurate of the three:

| Strategy | Fiducials | Status |
| --- | --- | --- |
| page-corner ArUco (IDs 0-3) | far from the cube | live |
| cube-adjacent ArUco (IDs 10-13) | beside the cube | disabled — OpenCV did not detect them on the dense sheet |
| **inner ArUco (IDs 20-25)** | **drawn into the cube at V[7]..V[12]** | never rendered (`local_rectify`) |

Its own docstring gives the rationale, and this audit's own measurements
endorse it: page-corner markers "are far from the cube and introduce
homography error", and **geometry is the binding axis** of the decode envelope
— perspective collapses at strength 2.5 while blur tolerates 4 px, JPEG
quality 10 and chroma noise σ 96. Fiducials that travel with the cube give the
most precise warp available, on precisely the axis that limits the system.

*Corrected a second time.* The paragraph that stood here claimed that
rendering the markers "puts ink on six of the 91 carriers". **That is also
wrong.** `_render_inner_aruco` states, and does, the opposite: each marker is
"pushed radially outward … so it sits **outside** the colored ring of the
vertex disk, **in the white margin area**". No carrier is sacrificed.

Two wrong readings of one module, in opposite directions, both from inferring
behaviour from a name — "duplicate" from the file's similarity to `aruco.py`,
"ink on carriers" from the identifier `ARUCO_INNER_IDS`. The module was read
properly only on the third pass. Recorded here rather than quietly amended,
because an audit that hides its own error rate is worth less than one that
shows it.

**The real reason it was never rendered is a one-line bug.**
`INNER_ARUCO_OFFSET = 1.50` places each marker at 1.5 × the drawable radius,
and on a 1024 px canvas the drawable radius is 410 px — so all six land at
1.5 × 410 = 615 px from centre, past the 512 px edge. Computed for every
marker: **6 of 6 fall outside the canvas.** The function runs and paints
nothing visible. There is roughly 100 px of white margin between the hexagon
and the edge, and the marker is 39 px, so an offset near 1.10 would place them
inside it. 1.50 appears never to have been tried.

Worth recording for whoever takes the trade: **even if the six carriers did
have to be sacrificed, the cost would be near zero.** Their positions map to
blocks 0-5 of 7 under the interleave — one erasure in six distinct blocks,
none doubled. At `2t + e ≤ 3` per block, one spent erasure still leaves
`t = 1`. The interleave spreads them perfectly. But the markers sit in the
margin, so the question does not arise.

So "wire it up or delete it" is the wrong question. The right one is **does
moving the fiducials inward buy more than the ink costs**, and it is not
answerable today: `scripts/detect_envelope.py` states in its own docstring that
"fiducials are handed to the rectifier exactly, so fiducial *detection* error
is excluded" — and detection error is exactly the term that separates the three
strategies. The bench is blind to what killed the module.

**Recommendation: extend the bench before disposing of the module.** Adding a
fiducial-localisation axis (a) makes the envelope honest, which the handover
already flags as optimistic, (b) answers this question as a by-product, and
(c) attacks the binding axis rather than one with headroom to spare. EPX-H §2.5
already shows how to draw near carriers without touching them, if the
measurement says the trade is worth taking.

### N-10.2 — the bench was extended, and then the numbers it produced were wrong

**Corrected the same day, after N-10.1 below was written.** Everything in
N-10.1 stands as a description of *what was measured*; the measurements
themselves were distorted by a defect one layer down, and the conclusion drawn
from them is withdrawn.

`detect._compute_homography` advertised "normalized DLT + SVD" in its docstring
and performed no normalisation. The DLT minimises an *algebraic* residual; on
raw pixel coordinates — 0..1024, every fiducial hundreds of units from the
origin — that residual weights each correspondence by its distance from the
origin. It is the shipping path: `detect.rectify` calls it on every photograph,
with six detected fiducials that are never projectively consistent, which is
precisely the regime where the conditioning decides the answer.

Fitting six deliberately inconsistent points, then translating and scaling both
sets and refitting, must return the same homography. The un-normalised version
differed by ~1.0 in matrix entries; normalised, by 4e-13.

With the fit corrected, on seeds 2026 and 77:

| Envelope | as published in N-10.1 | corrected |
| --- | --- | --- |
| perspective | 2.25 | **12** |
| fiducial, differential | 0.5 px | **6 px** |
| fiducial, common mode | 12 px | 12 px — unchanged |
| blur / chroma noise | 4 px / σ 96 | unchanged |

The common-mode envelope not moving is the control: a pure translation is
fitted exactly under either weighting, so had it moved the cause would have
been something else.

**Three claims are withdrawn.**

*"About one pixel of relative accuracy over a 410 px figure radius, a quarter
of a percent."* Mostly a measurement of the missing normalisation. The honest
figure is nearer **6 px over 410 px, about 1.5%**.

*"Geometry is the binding axis."* Inherited from the earlier handover and
repeated here. Perspective produced **zero errors at every level of the tested
ladder** after the fix, and breaks only at 16 — five times the pinned 2.25.
There was no cliff at 2.5; there was a fitter that degraded with displacement.

*The N-10 argument for `local_rectify`* — that the relative-accuracy budget is
so tight only cube-adjacent fiducials could meet it. With a correct fit the
budget is twelve times looser, and page-corner ArUco may well clear it. The
question is open again, and on weaker grounds than N-10.1 gave it.

**A prior result loses its demonstration.** `tests/test_erasure_budget.py`
showed that a mediocre photograph fails to decode, is not rescued by
distance-ranked erasures, and is rescued by margin-ranked ones. After the fix
that photograph decodes with **no erasures at all**. Searching perspective
7–10, blur 3.0–3.5 in steps of 0.1 and JPEG q50/q40/q30 found **no window**
where margin ranking rescues what nothing else does — the transition from
"decodes unaided" to "nothing decodes" is one blur step. This does not show
margin ranking to be wrong: common-mode cancellation is a real effect and
harsher photographs will still need it. It shows the bench no longer
demonstrates the benefit, and the tests now say so rather than asserting a
result nobody can reproduce.

**Sequencing note for anyone repeating this.** The corrected perspective axis
is still not a *tilt* axis — `PERSPECTIVE_UNIT` remains six displacements no
homography can realise (N-10.1). Fixing the fitter removed the larger error;
the axis's own defect is still there and is the next piece of work.

### N-10.1 — the bench was extended; here is what it says

Done the same day (`degrade.fiducial_shift`, `degrade.fiducial_jitter`,
`degrade.fiducial_radius`, two new tables in `scripts/detect_envelope.py`).
The error is reported in the two parts the fit treats differently, and they
cost wildly different amounts on a 1024 px canvas:

| Fiducial error | Envelope (worst block ≤ 1) |
| --- | --- |
| **common mode** — the whole estimate slides | **12 px** |
| **differential** — the six points stop describing one rigid figure | **0.5 px**, every seed |

**A prediction failed, which is the useful part.** Both this analyst and the
module's own reasoning assumed a homography would absorb a uniform
mislocation. It does not: the *destination* is the fixed canonical frame, so
sliding every source correspondence reads every carrier off-centre by the same
amount. Cheap — 12 px — but not free.

The differential term is roughly **twenty-four times dearer**. Sigma 1 px
already loses draws, and single draws vary enormously (at sigma 2 px the worst
block across five seeds ranged 0, 0, 2, 0, 13) because one badly-placed
fiducial dominates the fit. The requirement this implies is the number the
question needed: **about one pixel of *relative* accuracy over a 410 px figure
radius — a quarter of a percent.**

That is a demanding budget, and it is the argument `local_rectify` was making
without evidence: fiducials drawn into the cube are localised in the same
image patch as the carriers, so their *relative* error is far smaller than
markers read across a whole A4 sheet under perspective. The measurement now
leans toward its premise.

It does not settle the trade, but the remaining work is now small and
sequenced: fix the offset so the markers land in the margin, detect them with
OpenCV on the degraded image instead of handing positions over, and re-measure
the perspective envelope against the current path — which locates these same
six vertices by the centroid of the most colourful cluster
(`detect._refine_vertex_position`), a method unlikely to hold the ~1 px of
relative accuracy measured above.

### N-11 — Eidolon: coverage was configured, shadowed, and never measured

**Severity: medium (a declared floor that was never enforced).** Three
independent problems, found while measuring:

1. **CI runs no tests.** `.github/workflows/ci.yml` compiles the public sources,
   validates `pyproject.toml` and checks `.gitignore`. There are **58 test
   files** and the workflow executes none of them.
2. **The coverage configuration was inert.** `setup.cfg` carried
   `addopts = … --cov=src` and `[coverage:report] fail_under = 70`. pytest
   prefers `pyproject.toml`'s `[tool.pytest.ini_options]`, which exists and has
   neither. **The repository declared a 70% floor it never measured.** Measured
   on 2026-09-09: **29%** over 33 710 statements.
3. **A guarded import that does not guard.** `src/api/server.py` prints
   `[ERROR] FastAPI not installed` and continues, then evaluates
   `class ChallengeRequest(BaseModel)` — a `NameError` at import instead of the
   clear `ImportError` that `src/api/connect.py` raises two files away.

Five test modules also failed to collect on undeclared dependencies
(`pydantic`, `fastapi`, `PyJWT`, `python-multipart`, `httpx`). With those
installed the suite runs: **52 failures**, and the dominant cause is a single
missing artifact — the `eidolon_crypto` Rust extension is not built, which
accounts for the great majority of them.

*Fixed here:* the duplicate configuration is removed from `setup.cfg`, which
now points at `pyproject.toml` and says why re-adding a section there would be
ignored; `--cov=src` and `show_missing` move to `pyproject.toml`, so coverage
is measured by default. **`fail_under` is deliberately not carried over**:
setting 70 today fails every run. Pick a floor from the real number and raise
it, rather than inheriting an aspiration.

*Not fixed, and a decision rather than a task:* wiring Eidolon's CI to run its
tests would turn that repository red immediately. Building `eidolon_crypto`
first is the sequencing that makes the switch meaningful.

---

## Addendum, same day — residuals closed

Written after the body above, and subject to the same declared conflict of
interest: these were fixed by the author of this report.

**P0-4 residual (N-3) — closed.** `_diagnostics_allowed(cfg)` now gates both
decode-path writers: off unless `ESOPTRON_DEBUG_DUMP_FRAMES=1`, and never in
`private` mode whatever the operator asked for. The mode check is not a
convenience — the cube crop is the decodable region of a sheet that
reconstructs a 256-bit seed.

**P0-2 — closed by deletion, not by a flag.** The ~390-line inline `SCAN_HTML`
page is gone, with its hand-rolled SHA-256 and all five `esoptron.mobile.*`
info strings; so is `ESOPTRON_ENABLE_LEGACY_MOBILE_HTML`. `/scan` redirects to
the PWA or answers 410. A second KDF chain that an environment variable can
revive is a second KDF chain, and the audit's own recommendation was to retire
it in favour of the PWA. `tests/test_server_loopback.py` now asserts the info
strings are absent **from the module source**, so re-adding the page fails a
test rather than a review.

**P1-7 — closed with it.** `/api/register_psnx` was the deleted page's only
client. An unauthenticated, unquota'd write endpoint with no client is worse
than no endpoint, so the route answers 410 and `_register_public_psnx`,
`_validate_public_psnx` and `_contains_private_field` are removed. If a public
registry is wanted again it should return authenticated, as the audit asked.

**N-4 — closed.** The deployment key's temp file is created with
`os.open(..., 0o600)` instead of being written at the process umask and
tightened after `replace`. `restrict_secret_file` stays as the cross-platform
backstop, since `O_CREAT`'s mode argument is ignored on Windows.

**N-5 — closed.** `relic_vault_fp` is now `relic_seal_seed`; the derivation is
byte-identical and a deprecated alias remains. A test pins the value for all
twelve relics, because their badge seals are already minted on the live anchor.

**N-6 — closed as a documentation defect.** `GENESIS_COMMITMENT.md` claimed
without qualification that anyone can recompute everything from the block hash
alone. True for the Genesis positions, the relic distribution and the 555-egg
clutch; **false for a founder draw**, which additionally takes the vault
fingerprint — recorded there only as `f02cc7…d7be`. The claim is now scoped,
the GE-111 attribution is marked void (its vault no longer exists), and three
requirements are recorded for the next one: full fingerprint, stated
definition, and the egg the draw returns rather than a chosen one.

---

## Sign-off

The operational surface that the previous report identified as the weak spot has
been substantially hardened, and the test suite went from *uncollectable on the
maintainer's own machine* to 901 green tests with CI green on eight jobs across
three operating systems.

The two most interesting findings of this pass were not in either report's
original scope, and they rhyme: an identifier with three definitions, and a
frozen format taking its parameters from a dependency. Neither produced a
failure. Both would have produced a wrong answer that looked right — which is
the failure mode worth designing tests against, and the reason the two fixes
ship with tests that assert against *specifications* rather than against the
implementation's current output.

— End of report —
