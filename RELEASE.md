# Release Playbook

End-to-end runbook for cutting an Esoptron release. Each section is
self-contained; copy-paste blocks are PowerShell unless noted (CI/Linux
boxes use the equivalent `bash` form).

The reference target is **v0.1.0-beta.1** (the first public beta on
PyPI + npm). Later releases follow the same flow with the next
SemVer.

---

## 0. Prerequisites (one-time)

You need:

- `gh` (GitHub CLI) authenticated as a repo collaborator.
- `twine` (`python -m pip install --upgrade build twine`).
- An npm account with publish rights for `@esoptron/*` packages.
- Three secrets configured on the repo:
  - `PYPI_API_TOKEN` in the `pypi` environment (PyPI scoped, classic).
  - `TESTPYPI_API_TOKEN` in the `testpypi` environment.
  - `NPM_TOKEN` (a project-scoped automation token).
- A persistent Dilithium-5 deployment key (see § 8) if you want the
  manifest to be **signed** rather than hash-only.

Sanity check before doing anything irreversible:

```powershell
gh auth status
python -m pip show twine
npm whoami
```

---

## 1. Pre-flight checklist

Run every check locally before any tag is pushed. CI will repeat
these on the next push but a tag should never be cut against a red
working tree.

```powershell
cd C:\chimera\esoptron

# Tests
py -m pytest -q

# Encoding + manifest gates
py tools/check_encoding.py
py tools/verify_spec.py --all

# PWA + SDK
cd pwa;            npm ci; npm test; npm run build; cd ..
cd sdk/typescript; npm ci; npm test; npm run build; cd ../..
```

Expected:

- `389 passed` (or higher).
- `OK: N files clean (UTF-8, no BOM, LF endings).`
- `all M record(s) verified.`
- PWA & SDK builds succeed; `npm test` exits 0 (the `--passWithNoTests`
  flag on the SDK is intentional).

If any of these is red, **STOP**. Do not proceed to step 2 until
green.

---

## 2. Bump version

Three places to bump consistently:

```diff
# pyproject.toml
- version = "0.1.0b1"
+ version = "0.1.0b2"

# sdk/typescript/package.json
- "version": "0.1.0-beta.1",
+ "version": "0.1.0-beta.2",

# pwa/package.json  (only if PWA changed)
- "version": "0.1.0-beta.1",
+ "version": "0.1.0-beta.2",
```

Also append a section to `CHANGELOG.md` summarising:

- New features (link to issues/PRs).
- Breaking changes (call out specifically if any wire-format bumps).
- Security fixes.
- Known issues (e.g. "EPX-2 implementation pending").

Commit the bump and changelog together:

```powershell
git add pyproject.toml sdk/typescript/package.json pwa/package.json CHANGELOG.md
git commit -m "chore(release): bump version to 0.1.0-beta.2"
```

---

## 3. Re-sign the manifest

If any tracked document (`docs/specs/*`, `docs/whitepaper_*`,
`docs/audit_*`, etc.) was modified since the last manifest update, the
hashes drift. Refresh everything:

```powershell
py tools/sign_spec.py --all --timestamp $(Get-Date -AsUtc -Format yyyy-MM-ddTHH:mm:ssZ)
py tools/verify_spec.py --all
```

If you have a persistent deployment key (see § 8):

```powershell
py tools/sign_spec.py --all --key $HOME/.esoptron/jeremy.key.json
```

Commit:

```powershell
git add SPECS.SHA3-256
git commit -m "chore(spec): refresh SPECS.SHA3-256 for v0.1.0-beta.2"
```

---

## 4. Build distribution artifacts

### 4.1 Python wheel + sdist

```powershell
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
py -m build
py -m twine check dist/*
```

Expected: two artifacts under `dist/` (a `.whl` and a `.tar.gz`),
both passing `twine check`.

### 4.2 npm tarballs

```powershell
cd sdk/typescript
npm run build
npm pack          # produces esoptron-sdk-X.Y.Z.tgz
cd ../..
```

Inspect the tarball quickly:

```powershell
tar -tzf sdk/typescript/esoptron-sdk-*.tgz | Select-Object -First 30
```

Reject the release if the tarball contains test fixtures, source
maps, or any of `node_modules/`, `*.test.ts`, `coverage/`.

---

## 5. TestPyPI dry-run

Publish to TestPyPI first; smoke-install from a clean venv; then move
to production PyPI only if the smoke passes.

### 5.1 Trigger the workflow

```powershell
gh workflow run publish-pypi.yml --ref main -f target=testpypi
```

Wait for it to finish:

```powershell
gh run list --workflow=publish-pypi.yml --limit 1
gh run watch
```

### 5.2 Smoke-install

In a fresh shell, in a fresh directory:

```powershell
py -m venv smoke; cd smoke
.\Scripts\Activate.ps1
py -m pip install --index-url https://test.pypi.org/simple/ `
    --extra-index-url https://pypi.org/simple/ `
    esoptron==0.1.0b2
py -c "import eopx; print(eopx.__version__)"
py -m eopx.cli --help    # if a CLI entry-point exists
deactivate; cd ..
```

If `pip install` or the import fails, **STOP**. Investigate, fix,
re-run from § 2.

---

## 6. Production publish

### 6.1 PyPI

```powershell
gh workflow run publish-pypi.yml --ref main -f target=pypi
gh run watch
```

Verify it appears on https://pypi.org/project/esoptron/ within ~5 min.

### 6.2 npm

```powershell
gh workflow run publish-npm.yml --ref main
gh run watch
```

Verify on https://www.npmjs.com/package/@esoptron/sdk.

---

## 7. Tag + GitHub Release

```powershell
git tag -a v0.1.0-beta.2 -m "Esoptron v0.1.0-beta.2"
git push origin main --follow-tags

# Build release notes from CHANGELOG.md
gh release create v0.1.0-beta.2 `
    --title "Esoptron v0.1.0-beta.2" `
    --notes-file CHANGELOG.md `
    --prerelease `
    dist/esoptron-0.1.0b2-py3-none-any.whl `
    dist/esoptron-0.1.0b2.tar.gz `
    sdk/typescript/esoptron-sdk-0.1.0-beta.2.tgz
```

The `--prerelease` flag is required for any version with a SemVer
suffix (`-alpha`, `-beta`, `-rc`). Promote to a normal release only at
v0.1.0 GA.

---

## 8. Persistent deployment key (one-time)

For the manifest to carry a Dilithium-5 signature that anyone can
verify, the author needs a persistent key. Generate one **off-host**
if possible (an air-gapped machine), or at minimum on the dev box and
back it up immediately to an encrypted USB.

```powershell
py scripts/eopx_keygen.py --out $HOME/.esoptron/jeremy.key.json
```

The file contains both the public and the **secret** Dilithium-5 key;
guard it like an SSH key:

```powershell
# Restrict to current user.
icacls $HOME\.esoptron\jeremy.key.json /inheritance:r /grant:r "${env:USERNAME}:F"
```

Publish only the public key (for verification):

```powershell
py -c "import json,sys; k=json.load(open(sys.argv[1])); print(k['dilithium_pk'])" `
    $HOME\.esoptron\jeremy.key.json | Out-File docs/jeremy_zgonec.pubkey.hex
git add docs/jeremy_zgonec.pubkey.hex
git commit -m "docs: publish persistent Dilithium-5 public key for spec signing"
```

Anyone can then verify a signed manifest:

```powershell
py tools/verify_spec.py docs/specs/EPX-2_card_v2.md `
    --pk-hex (Get-Content docs/jeremy_zgonec.pubkey.hex)
```

---

## 9. Rollback

If a published artifact has a critical bug:

### 9.1 PyPI

PyPI does **not** allow re-using a version number. You must publish a
new patch:

```powershell
# bump pyproject.toml to 0.1.0b3, repeat §2-§6
```

You can yank the broken version so `pip install esoptron` skips it:

```powershell
# Sign in to https://pypi.org/manage/project/esoptron/release/0.1.0b2/
# and click "Yank release".
```

### 9.2 npm

npm allows unpublishing within 72 hours of the publish:

```powershell
npm unpublish @esoptron/sdk@0.1.0-beta.2
```

After 72 hours, publish a fix release instead.

### 9.3 Git tag

```powershell
git push --delete origin v0.1.0-beta.2
git tag -d v0.1.0-beta.2
```

---

## 10. Post-release

- Open the next milestone on GitHub (e.g. v0.1.0-beta.3).
- Move closed issues/PRs from the previous milestone if any spill
  over.
- Announce in the project channel(s) with a link to the GH release
  page.
- If this is a stable / GA release, update the README badges
  (PyPI version, downloads) and pin the docs site to the new version.

---

## Appendix A — common failure modes

| Symptom                                              | Diagnosis                                         | Fix                                          |
| ---------------------------------------------------- | ------------------------------------------------- | -------------------------------------------- |
| `twine check` fails with "long_description has reST" | README has Markdown but pyproject declares reST   | Confirm `pyproject.toml` `readme = "README.md"` |
| `pip install` fails with "ml_dsa_87 not found"       | `pqcrypto` wheel mismatch                         | Pin `pqcrypto>=0.3.4` in pyproject           |
| Wheel includes `*.pyc` / `__pycache__`               | sdist/MANIFEST.in glob too broad                  | Tighten `MANIFEST.in` exclusion patterns     |
| CI passes locally, fails on Windows runner          | CRLF leaked back into a `.py` file                | `py tools/check_encoding.py --fix`, commit   |
| `npm publish` rejects with E403                      | NPM_TOKEN scope or 2FA gating                     | Generate a new automation token; rotate secret |
| Manifest verify fails after editor save              | cp1252 mojibake in the doc                        | Repair with `tools/check_encoding.py`; re-sign |

## Appendix B — release cadence guideline

- **Patch** (`0.1.0-beta.N`): every 1-2 weeks while in beta.
- **Minor** (`0.X.0`): when a feature is shipped + tested in the wild.
- **Major** (`X.0.0`): only on wire-format / API-breaking changes; pair
  with a `docs/migration_<X>.md`.

Always wait at least 30 minutes between two consecutive publishes to
the same registry to avoid race conditions in CDN propagation.
