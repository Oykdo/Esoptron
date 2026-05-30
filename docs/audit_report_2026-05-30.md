# Esoptron — Code & Hygiene Audit, 2026-05-30

Author: Jérémy ZGONEC (via Droid)
Status: snapshot at the end of the EPX-1 + manifest + normalisation work.
Companion: `docs/audit_report_2026-05-28.md` (previous P0/P1/P2 sweep).

## 1. Summary

Out of the backlog inherited from the 2026-05-28 sweep, several items
turn out to already be addressed by existing code or by today's
normalisation work. Genuinely outstanding work is concentrated in
three buckets:

1. Documentation / release-engineering (RELEASE playbook, dev-loop
   wiring).
2. Three remaining direct-unit-test gaps (`server/rate_limit`,
   `server/serialization`, and the new `tools/*.py` integrity tools).
3. The EPX-2 implementation track (grid_v2, bech32, QR, tests). This
   bucket is its own roadmap; see ``docs/specs/EPX-2_card_v2.md``.

## 2. What was completed today (since 28 May)

| Area                              | Status | Where                                |
| --------------------------------- | ------ | ------------------------------------ |
| Inscription on Genesis seal       |   ✓    | `src/eopx/genesis_token.py` + 10 tests |
| Distribution scaffolding          |   ✓    | LICENSE/SECURITY/CHANGELOG/MANIFEST.in/CI |
| pyproject rebrand (esoptron)      |   ✓    | `pyproject.toml` v0.1.0b1            |
| Invitation generator (V1 layout)  |   ✓    | `scripts/make_invitation.py`         |
| EPX-2 spec (Reinforced Card V2)   |   ✓    | `docs/specs/EPX-2_card_v2.md`        |
| `SPECS.SHA3-256` manifest         |   ✓    | 9 records (specs + whitepapers + audit) |
| Normalised hashing pipeline       |   ✓    | `tools/sign_spec.py` + `verify_spec.py` |
| Encoding guards (UTF-8 / LF)      |   ✓    | `.editorconfig` + `.gitattributes` + `tools/check_encoding.py` |
| Tests passing                     |  389 ✓ | full pytest suite                    |

## 3. Items that were *thought* outstanding but are actually done

| Backlog item                  | Reality | Evidence                                  |
| ----------------------------- | ------- | ----------------------------------------- |
| P2-2 lazy `pqcrypto` import   | DONE    | imports live inside fn bodies in `keys.py`, `genesis.py`, `recovery.py`, `visual_sharding.py`. Module top is bare. |
| No TODO/FIXME residue in src  | DONE    | `rg 'TODO\|FIXME\|XXX\|HACK' src/eopx → 0 hits`. |
| Distribution scaffolding      | DONE    | LICENSE/MANIFEST.in/SECURITY/CONTRIBUTING/CHANGELOG/CI all present. |
| Mojibake hardening            | DONE    | `tools/check_encoding.py` + .gitattributes + .editorconfig. |

## 4. Outstanding work (ranked)

### 4.1 High priority (1-2 days)

#### 4.1.1 RELEASE.md

A step-by-step playbook for cutting v0.1.0-beta.1. Should cover:

- pre-flight: `pytest`, `pyright` (if enabled), `pwa npm test`, `mypy`.
- build: `py -m build` + `twine check dist/*` + `npm pack`.
- TestPyPI dry-run smoke (`pip install -i testpypi esoptron`).
- PyPI publish workflow trigger.
- npm publish workflow trigger.
- git tag + GitHub release notes (lifted from CHANGELOG.md).
- post-release: spec re-sign (`tools/sign_spec.py --all`), commit
  manifest, push.

#### 4.1.2 Pre-commit configuration

A `.pre-commit-config.yaml` wiring:

- `tools/check_encoding.py` over all staged text files.
- `tools/verify_spec.py --all` whenever any
  `docs/(specs|whitepaper|audit)*.md` or `SPECS.SHA3-256` is staged.

Hook installer line in `CONTRIBUTING.md`.

#### 4.1.3 Wire encoding + manifest checks into CI

`.github/workflows/ci.yml` already runs pytest. Add two steps:

```yaml
- run: python tools/check_encoding.py
- run: python tools/verify_spec.py --all
```

This makes the manifest a hard CI gate.

### 4.2 Medium priority (1-2 days each)

#### 4.2.1 Dedicated tests for `server/rate_limit.py`

Cover:

- the IP→bucket mapping for both X-Forwarded-For and direct
  RemoteAddr cases,
- the token-bucket refill arithmetic at boundary values (0, 1, full,
  burst),
- the override env var `ESOPTRON_RATE_LIMIT_DISABLE=1`,
- the 429 emission with `Retry-After` and the structured-error body.

Target: ~120 lines in `tests/test_rate_limit.py`, ~8 cases.

#### 4.2.2 Dedicated tests for `server/serialization.py`

Cover canonical JSON serialization round-trip for the four
top-level dataclasses (Vault, Seal, Inscription, Anchor) and the
ordering guarantees of the canonical form.

#### 4.2.3 Dedicated tests for `tools/sign_spec.py` + `tools/verify_spec.py`

- round-trip: write manifest, mutate a doc by 1 byte, expect FAIL.
- normalisation: same doc with CRLF should produce same hash.
- BOM stripping should not change the hash.
- with `--key`: forge signature with another key → FAIL.

#### 4.2.4 Dedicated tests for `tools/check_encoding.py`

- accept clean UTF-8 LF file,
- reject UTF-8 with BOM,
- reject Windows-1252-misencoded file,
- reject CRLF (except `.ps1` / `.bat` / `.cmd`),
- `--fix` correctly normalises a BOM file.

### 4.3 Low priority (research / not blocking)

#### 4.3.1 Property-based fuzz tests (P2-4)

Add `tests/test_property_*.py` using `hypothesis`. Two highest-value
properties:

```python
@given(seed=binary(min_size=32, max_size=32))
def test_encode_decode_roundtrip(seed):
    cw = encode_private(seed)
    decoded = decode_private(cw)
    assert decoded == seed

@given(symbols=lists(integers(0, 12), min_size=91, max_size=91))
def test_grid_roundtrip_v1(symbols):
    assert decode_grid(encode_grid_cells(symbols)) == symbols
```

`hypothesis` is already in `pyproject.toml [project.optional-dependencies].dev`.

#### 4.3.2 `README_old.md` cleanup

Still present in working tree (gitignored). Either delete or move
into `docs/legacy/` so it doesn't surface in encoding scans.

#### 4.3.3 Reduce `SPECS.SHA3-256` blast radius

Today every whitepaper triggers a manifest rewrite if any single
trailing-space is added. Consider a per-doc author field so multiple
maintainers can sign their own docs without conflict (already supported
by the parser, just needs surfacing in `--scan`).

### 4.4 Standalone roadmap: EPX-2 implementation

Tracked separately in the spec doc and the implementation TODO list.
Not in this audit's scope, but for reference:

- `src/eopx/metatron/grid_v2.py`
- `src/eopx/metatron/bech32_card.py`
- `src/eopx/metatron/qr_companion.py`
- `tools/gen_card_v2_vectors.py`
- `scripts/print_sheet.py` extension (variant private/street)
- `scripts/make_invitation.py` V2 with QR
- Tests: round-trip, RS erasure, MAC tamper, bech32 forgery.

## 5. Risks & mitigations

| Risk                                                    | Mitigation                                |
| ------------------------------------------------------- | ----------------------------------------- |
| Editor re-saves spec in cp1252 → hash drift             | `.editorconfig` + `.gitattributes` + pre-commit check (in place). |
| Spec author signing key loss → manifest can't be re-signed | Hash-only mode keeps integrity without signature; signature is optional. |
| New whitepaper added but not in `KNOWN_DOCS`            | `tools/sign_spec.py` shows missing on `--scan`; CI step would catch it. |
| Manifest divergence on different OS line endings        | Normalisation pipeline strips CR before hashing; `write_bytes` writes LF. |

## 6. Suggested commit grouping

If pushing tonight, split into three commits:

1. `chore(repo): editor + git encoding guards` — `.editorconfig`,
   `.gitattributes`, `tools/check_encoding.py`, README_old removal.
2. `feat(spec): EPX-2 + signed-doc manifest` — `docs/specs/EPX-2_card_v2.md`,
   `tools/sign_spec.py`, `tools/verify_spec.py`, `SPECS.SHA3-256`.
3. `docs(audit): 2026-05-30 snapshot` — this file.

This keeps each commit focused so reviewers can fast-forward through
the tooling changes and concentrate on the spec.

## 7. Verification commands

To reproduce the audit findings locally:

```powershell
cd C:\chimera\esoptron
py tools/check_encoding.py            # must say "OK: N files clean"
py tools/verify_spec.py --all         # must say "all M record(s) verified."
py -m pytest -q                       # 389 passed
```
