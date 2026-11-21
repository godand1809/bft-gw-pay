# Security Policy — BFT QR Pay

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| 1.1.x | ✅ | Security hardening release (admin token, rate limits, headers, race fixes) |
| 1.0.x | ⚠️ Superseded | Upgrade to 1.1.x — admin endpoints were unauthenticated |

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
per-installation secret stored at `data/.secret` (file mode `0600`, never
committed — see `.gitignore`). All ticket state (validity, rides remaining,
status) is resolved **server-side at scan time**; the QR is a signed pointer,
not the source of truth. Signature comparison uses constant-time
`hmac.compare_digest`.

## Security controls (v1.1.0)

- **Admin token gate** — `/api/admin/analytics` and `/api/admin/export.csv`
  require `BFT_ADMIN_TOKEN` (sent as `X-Admin-Token` header or
  `?admin_token=`). If the env var is unset, a token is generated once and
  written to `data/.admin_token` (mode `0600`).
- **Rate limiting** — per-IP fixed-window limits on sign-in (10/min),
  top-up (10/min), purchase (20/min), and validate (120/min).
- **Security headers** — `Content-Security-P`, `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` on every response.
- **Transaction integrity** — wallet debits run inside `BEGIN IMMEDIATE`
  with a conditional `UPDATE ... WHERE wallet_cents >= price` guard; receipt
  numbers retry on collision. Concurrent purchases cannot overdraft.
- **Static-file traversal hardening** — `realpath` + separator-prefixed
  boundary check; traversal sequences and dotfiles are refused.
- **XSS defense-in-depth** — all dynamic values are HTML-escaped
  (`esc()`) before `innerHTML` in every frontend surface.
- **Automated bug finding** — CodeQL (`security-extended`) on every
  push/PR/week (`.github/workflows/codeql.yml`) and an e2e CI gate
  (`.github/workflows/ci.yml`) with security regression checks.

## Known demo limitations

This is an evaluation build. The following are intentional simplifications
that **must** be addressed before real deployment:

1. **Demo authentication** — sign-in is email-only with auto-account
   creation and no password. Production needs real identity (passwords or
   SSO), email verification, and session rotation.
2. **Simulated payments** — wallet top-ups are not real charges. Wire
   `POST /api/topup` to a payment service provider (Stripe/Adyen) with
   server-side amount calculation and webhook-based settlement.
3. **Shared admin token** — the admin gate uses a single static token.
   In production, replace it with staff SSO + role-based authorization.
   The token is echoed to the server log on first start — retrieve it
   then, and never commit `data/.admin_token`.
4. **Signing secret handling** — `data/.secret` lives on disk next to the
   DB. In production, move it to a secrets manager (e.g. AWS Secrets
   Manager, Vault) and plan a rotation strategy (rotation invalidates all
   outstanding QR tickets).
5. **No TLS by default** — run behind a TLS-terminating proxy and set
   `BFT_COOKIE_SECURE=1` so session cookies carry the `Secure` flag.
6. **In-memory rate limiter** — per-process only; use a shared store
   (e.g. Redis) or proxy-level throttling for multi-worker deployments.
7. **Schema note** — `boardings.route_id` became nullable in v1.1.0.
   Delete `data/bft.db` when upgrading a v1.0.x install so the schema
   is recreated.
8. **Demo data seeder** — the first run inserts synthetic riders and
   transactions. Disable seeding (`init_db(seed_demo=False)`) for any real
   deployment.

## Scanner-side guidance

- Validate only over HTTPS against the official API.
- Never trust a locally "decoded" ticket — the accept/reject decision must
  always come from `/api/validate`.
- Stop-poster QRs deep-link riders to the purchase flow; they never carry
  fare value.

## GitHub repository security

This repository enables secret scanning, push protection, Dependabot
(pip **and** github-actions ecosystems — see `.github/dependabot.yml`),
CodeQL code scanning (`.github/workflows/codeql.yml`), and a CI test gate
(`.github/workflows/ci.yml`). Keep `data/` gitignored so the signing
secret, admin token, and database never enter version history.
