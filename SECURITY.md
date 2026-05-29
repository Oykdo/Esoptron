# Security Policy

## Supported Versions

| Version  | Supported |
|----------|-----------|
| 0.1.x    | yes       |
| < 0.1    | no        |

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Esoptron, please
**do not** open a public issue. Instead:

1. Email `security@esoptron.dev` (PGP key forthcoming).
2. Include a minimal reproducer when possible.
3. Allow up to 14 days for an initial triage before public disclosure.

We commit to:

* Acknowledge receipt within 5 business days.
* Provide an initial assessment within 14 days.
* Publish a CVE and a fixed release coordinated with the reporter.

## Scope

In scope:

* Cryptographic flaws in the EOPX format, Genesis token, Visual sharding,
  Recovery (Argon2 / Kyber), or Migration (Protocol F NIZK).
* Bypasses of the rate limiter, HMAC delegate signing, or anchor
  bootstrap gating.
* Memory disclosure via the `Secret` / `secure_bytes` API.

Out of scope:

* DoS against the *single-tenant developer demo* `eopx.server.app` (it is
  explicitly documented as DEV / DEMO ONLY).
* Side-channels in third-party dependencies (`pqcrypto`, `argon2-cffi`,
  `cryptography`). Please report those upstream.

## Hardening Notes

* Production deployments must set:
  - `ESOPTRON_ENABLE_LEGACY_MOBILE_HTML` **unset** (legacy mobile HTML is
    served only when explicitly enabled).
  - `ESOPTRON_DEBUG_DUMP_FRAMES` **unset** (no frames are persisted).
  - `ESOPTRON_ALLOW_DEV_DEFAULTS` **unset** (no zero-block fallback).
  - `ESOPTRON_RATE_LIMIT_DISABLE` **unset**.
  - `ESOPTRON_CORS_ALLOWED_ORIGINS` set to an explicit allow-list (never
    `*`).
* Keys persisted by the anchor service are written with restrictive
  permissions (`0o600` on POSIX, owner-only DACL on Windows).
* The deployment Dilithium key is the trust root of the Genesis seal —
  protect it like an HSM key.
