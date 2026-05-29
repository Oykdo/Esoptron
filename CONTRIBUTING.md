# Contributing

Thanks for considering a contribution.

## Quick start

```bash
git clone https://github.com/oykdo/esoptron.git
cd esoptron
python -m venv .venv
. .venv/bin/activate          # POSIX
# or: .venv\Scripts\Activate.ps1   (PowerShell)
pip install -e ".[dev,server]"
pytest -q
```

For the TypeScript SDK:

```bash
cd sdk/typescript
npm install
npm test
```

For the PWA:

```bash
cd pwa
npm install
npm test
```

## Local checks before opening a PR

1. `pytest -q` — full Python suite must pass.
2. `npm test` (in `sdk/typescript` and `pwa`) — JS suites must pass.
3. New crypto-touching code MUST include parity tests across the
   Python and TS ports when applicable.
4. Update `CHANGELOG.md` under the `[Unreleased]` section.

## Branching

* `main` is always green.
* Feature branches: `feat/<short-topic>`.
* Fix branches: `fix/<short-topic>`.

## Commit style

* Imperative present tense (`Add ...`, `Fix ...`, `Refactor ...`).
* Reference the audit finding ID when applicable (e.g. `P0-3:`).
* Keep the subject line ≤ 72 chars.

## Security-sensitive changes

If your change touches any of:

* `eopx.format.eopx_format` (wire format)
* `eopx.vault.migrate` (Protocol F NIZK)
* `eopx.vault.genesis` (ceremony attestation)
* `eopx.server.http_delegate` (HMAC canonicalization)
* `eopx.recovery` (Argon2 / Kyber key derivation)
* `eopx.metatron.field` (KDF / hashing primitives)

...please add a paragraph to the PR description explaining the threat model
implication. A reviewer with security domain knowledge will be tagged.

## Releasing

Maintainers only.

1. Bump version in `pyproject.toml` and `sdk/typescript/package.json`.
2. Update `CHANGELOG.md` with the release date.
3. Tag `vX.Y.Z` and create a GitHub release.
4. CI workflows `publish-pypi.yml` and `publish-npm.yml` will publish.
