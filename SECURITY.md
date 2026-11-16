# Security Policy — BFT QR Pay

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately via [GitHub Security Advisories]
(https://github.com/security/advisories) on this repository
(**Security → Report a vulnerability**), or contact the maintainers
directly. We aim to acknowledge reports within **5 business days**.

Please include: a description of the issue, steps to reproduce,
affected endpoints/files, and any proof-of-concept payload.

## QR code trust model

Ticket QR payloads are `BFT1:<ticket_id>:<hmac-sha256[:16]>`, signed with a
per-installation secret stored at `data/.secret` (never committed — see
`.gitignore`). All ticket state (validity, rides remaining, status) is
resolved **server-side at scan time**; the QR is a signed pointer, not the
source of truth. Signature comparison uses constant-time
`hmac.compare_digest`.

## Known demo limitations

This is an evaluation build. The following are intentional simplifications
that **must** be addressed before real deployment:

1. **Demo authentication** — sign-in is email-only with auto-account
   creation and no password. Production needs real identity (passwords or
   SSO), email verification, and session rotation.
2. **Simulated payments** — wallet top-ups are not real charges. Wire
   `POST /api/topup` to a payment service provider (Stripe/Adyen) with
   server-side amount calculation and webhook-based settlement.
3. **Open admin endpoints** — `/api/admin/analytics` and
   `/api/admin/export.csv` are unauthenticated for easy evaluation.
   Protect them behind staff SSO/role checks in production.
4. **Signing secret handling** — `data/.secret` lives on disk next to the
   DB. In production, move it to a secrets manager (e.g. AWS Secrets
   Manager, Vault) and plan a rotation strategy (rotation invalidates all
   outstanding QR tickets).
5. **No TLS** — run behind a TLS-terminating proxy; cookies are `httponly`
   and `samesite=lax` but not marked `secure` for local development.
6. **No rate limiting** — add request throttling (e.g. slowapi/nginx) on
   auth, top-up, and validate endpoints.
7. **Demo data seeder** — the first run inserts synthetic riders and
   transactions. Disable seeding (`init_db(seed_demo=False)`) for any real
   deployment.

## Scanner-side guidance

- Validate only over HTTPS against the official API.
- Never trust a locally "decoded" ticket — the accept/reject decision must
  always come from `/api/validate`.
- Stop-poster QRs deep-link riders to the purchase flow; they never carry
  fare value.

## GitHub repository security

This repository enables secret scanning, push protection, and Dependabot
(see `.github/dependabot.yml`). Keep `data/` gitignored so the signing
secret and database never enter version history.
