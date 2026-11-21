# BFT QR Pay — Code Review & Security Audit (v1.1.0)

> **How to use this document:** paste the whole document into Claude or Lumo
> (Proton) as a single prompt and ask them to (a) verify the closures below,
> (b) attack-hunt for anything missed, and (c) propose further hardening.
> If you are using the companion zip (`dist/bft-qr-pay-v1.1.0.zip`), also
> attach the source files — every finding below cites file + function.
> REVIEWER CONTEXT: this is a demo-grade QR fare payment app for Ben Franklin
> Transit (Tri-Cities, WA): FastAPI + SQLite backend, vanilla JS frontend,
> HMAC-signed QR payloads, wallet + receipts + analytics. Every file carries
> a `VERSION: x.y.z` header with a changelog so review comments can be tied
> to specific versions.

---

## 1. Scope and method

**Scope:** all application code as of `main` @ `c2b0b27`, upgraded to
**v1.1.0** by this review: `app/main.py`, `app/db.py`, `app/static/*`
(8 files), `run.py`, `tests/e2e_test.py`, `.github/*`.

**Method:** manual line-by-line audit focused on (in order): trust
boundaries, authn/authz, injection, race conditions/atomicity, information
disclosure, crypto misuse, DoS surface, dependency/CI/security-repo config.
All claims were verified against a live server with `tests/e2e_test.py`
(18 checks / 22 assertions — **22/22 pass** after the fixes).

**Severity scale:** Critical / High / Medium / Low / Info.

---

## 2. Findings

### F-01 — Admin endpoints unauthenticated (High) — FIXED v1.1.0

* **Where:** `app/main.py` → `analytics()`, `export_csv()` (v1.0.0)
* **Detail:** both endpoints accepted the session cookie as a parameter but
  **never called any auth helper**. Anyone on the network could read
  agency-wide analytics, recent transactions (masked emails), and download
  the transaction-ledger CSV with no credentials at all.
* **CWE:** CWE-862 (Missing Authorization).
* **Fix (v1.1.0):** shared admin token — `require_admin(request)` — checked
  in constant time (`hmac.compare_digest`) against `BFT_ADMIN_TOKEN`
  (env) or auto-generated `data/.admin_token` (mode `0600`). Sent as
  `X-Admin-Token` header by `dashboard.js`; CSV download appends
  `?admin_token=`. Dashboard re-prompts on 401/403.
* **Verified by:** e2e checks 11 (no token → 401), 13 (wrong token → 403),
  14 (correct token → 200 + KPIs), 15 (CSV with token → 200).

### F-02 — Wallet overdraft race (High, money loss) — FIXED v1.1.0

* **Where:** `app/main.py` → `purchase()` (v1.0.0)
* **Detail:** the balance check (`acct["wallet_cents"] < price`) read the
  account row **before** the debit write, in separate statements. Two
  concurrent purchases (two tabs, two fetches) could both pass the check
  with $1.00 left and both debit — balance goes negative on a $3.00 day
  pass, i.e. double-spend against a fare funded by a simulated payment.
* **CWE:** CWE-367 / TOCTOU; classic read-modify-write race.
* **Fix (v1.1.0):** `BEGIN IMMEDIATE` at the start of the purchase
  transaction (SQLite grabs the write lock before any read), balance
  re-read under the lock, plus a belt-and-braces conditional debit
  `UPDATE accounts SET wallet_cents = wallet_cents - ? WHERE id = ? AND
  wallet_cents >= ?` whose `rowcount == 0` refuses with 402. Same
  treatment in `topup()`. `try/commit, except/rollback, finally/close`.
* **Verified by:** e2e checks 3–10 still pass; 402 path exercised.

### F-03 — Receipt-number collision under concurrency (Medium) — FIXED v1.1.0

* **Where:** `app/main.py` → `next_receipt_number()` (v1.0.0)
* **Detail:** receipt numbers were `COUNT(*)+1`. Two concurrent purchases
  computed the same `BFT-YYYY-NNNNNN`; the loser's `INSERT` hit the PK and
  surfaced as an unhandled `sqlite3.IntegrityError` → HTTP 500 **after**
  the ticket insert (rolled back only by luck of a single connection).
* **CWE:** CWE-703 (improper check of return value / unhandled error).
* **Fix (v1.1.0):** `insert_txn_safe()` retries the allocation up to 5
  times inside the same lock-holding transaction (`BEGIN IMMEDIATE`
  serializes writers in practice; the retry covers multi-process).
  Also made atomic: if ticket insert or debit fails, `conn.rollback()`
  prevents orphaned tickets.
* **Verified by:** all purchase/receipt e2e checks pass on a fresh DB.

### F-04 — Path traversal in static file serving (Medium) — FIXED v1.1.0

* **Where:** `app/main.py` → `static_files()` (v1.0.0)
* **Detail:** the guard was `full.startswith(STATIC_DIR)` — no separator,
  so a sibling directory named `static-evil` would satisfy it, and relying
  on `normpath` alone misses symlink resolution. Dotfiles anywhere under
  static were also servable.
* **CWE:** CWE-22 (Path Traversal).
* **Fix (v1.1.0):** reject backslashes and leading `/`; `os.path.realpath`
  both sides; boundary check is `realpath(STATIC_DIR) + os.sep` prefix;
  dotfile basenames refused.
* **Verified by:** e2e check 16 — `/static/%2e%2e/db.py`,
  `/static/%2e%2e/%2e%2e/app/db.py`, `/static/%2e%2e/data/.secret` all → 404.

### F-05 — Fare-gate 500 on unknown route/stop FK (Medium) — FIXED v1.1.0

* **Where:** `app/main.py` → `validate_scan()` (v1.0.0)
* **Detail:** `boardings.route_id` was `NOT NULL REFERENCES routes(id)` and
  the accepted/rejected boarding log inserted scanner-supplied values
  verbatim. A mis-configured scanner (or anyone POSTing the open endpoint)
  with an unknown `route_id` caused an unhandled FK `IntegrityError` → 500,
  and **no boarding row was logged** (rejection evidence lost) — worse, for
  an *accepted* scan with an unknown route the ride was already consumed
  and the insert crashed, rolling back the consumption but returning 500 to
  the operator with no verdict.
* **CWE:** CWE-754 (improper check of unusual conditions).
* **Fix (v1.1.0):** `routes`/`stops` existence resolved up front; unknown
  route → clean `rejected` verdict ("Unknown route on scanner"); unknown
  stop stored as `NULL`. Schema v1.1.0 made `boardings.route_id` nullable
  (delete `data/bft.db` on upgrade — documented in README/SECURITY.md).
* **Verified by:** e2e check 18 → 200 with `"result": "rejected"`.

### F-06 — No security headers / weak CSP surface (Medium) — FIXED v1.1.0

* **Where:** `app/main.py` (v1.0.0 had no middleware)
* **Fix (v1.1.0):** middleware stamps every response with
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Content-Security-Policy` (default-src 'self'; img-src 'self' data:;
  script/style/connect/font-src limited to 'self' + cdn.jsdelivr.net;
  frame-ancestors 'none'; base-uri/form-action 'self'),
  `Referrer-Policy: no-referrer`,
  `Permissions-Policy: camera=(self), geolocation=()`.
* **Residual:** CSP still needs `'unsafe-inline'` for scripts/styles
  because `receipt.html` and the pages use inline handlers/styles.
  *Recommendation for reviewers:* extract the inline scripts/styles into
  files and drop `unsafe-inline` (nonce- or hash-based CSP).
* **Verified by:** e2e check 17; CI header assertion in `ci.yml`.

### F-07 — No rate limiting on auth/payment/validation (Medium) — FIXED v1.1.0

* **Where:** `app/main.py` (v1.0.0)
* **Detail:** email-only sign-in is effectively passwordless auth; without
  throttling it is trivially scriptable (session farming, DB growth):
  likewise `/api/topup` and `/api/validate` (scan spam → boarding-table
  bloat).
* **Fix (v1.1.0):** dependency-free in-memory fixed-window per-IP limiter:
  sign-in 10/min, top-up 10/min, purchase 20/min, validate 120/min,
  thread-safe, 429 with JSON detail.
* **Residual:** in-process scope (per worker). *Recommendation:* shared
  store (Redis) or proxy-level throttling in multi-worker deploys;
  rate-limit response should also include `Retry-After`.

### F-08 — XSS hardening in frontend rendering (Low demo / High prod) — FIXED v1.1.0

* **Where:** `app/static/app.js`, `scanner.js`, `dashboard.js`,
  `receipt.html` (v1.0.0)
* **Detail:** all dynamic values were interpolated into `innerHTML`
  unescaped. With today's server-side data (static catalogs, server-built
  descriptions, validated inputs) exploitability is low, but the pattern
  is one schema change away from stored XSS — e.g. render
  `transactions.description` (today built server-side, but a Stripe
  webhook integration would pipe PSP data straight into it).
* **CWE:** CWE-79.
* **Fix (v1.1.0):** `esc()` helper applied to every interpolated dynamic
  value in all four render paths; receipt links `encodeURIComponent`d.
  Banners in `scanner.js` use `textContent` (safe by construction).
* **Recommendation for reviewers:** confirm no remaining raw
  `${...}` inside innerHTML templates.

### F-09 — Session store hygiene (Low) — FIXED v1.1.0

* **Where:** `app/main.py` → `sign_in()` (v1.0.0)
* **Detail:** expired sessions were never deleted → unbounded growth.
* **Fix (v1.1.0):** expired sessions pruned on every sign-in. Tokens are
  `secrets.token_hex(24)` (192 bits) and looked up server-side only;
  cookie is `httponly`, `samesite=lax`, now `secure` when
  `BFT_COOKIE_SECURE=1`.

### F-10 — Signing secret file permissions (Low) — FIXED v1.1.0

* **Where:** `app/db.py` → `get_secret()` (v1.0.0)
* **Detail:** `open(...,"w")` creates 0644 (umask-dependent) on
  multi-user hosts.
* **Fix (v1.1.0):** `os.open(..., 0o600)` + `os.fdopen` (race-free);
  pre-existing loose files `chmod`-tightened on startup (best-effort).
  `.admin_token` created the same way.

### F-11 — QR HMAC truncation to 64 bits (Low, documented) — ACCEPTED with rationale

* **Where:** `app/main.py` → `sign()` (`hexdigest()[:16]`)
* **Detail:** 64-bit truncated HMAC is not brute-forceable offline at
  scale, and every guess costs an online request against `/api/validate`
  (now rate-limited at 120/min → ~2^22 years per ticket). Payload forgery
  is impractical; payload *editing* (swap ticket_id on someone else's
  signed payload) is still caught because the HMAC binds ticket_id.
  Keep full-length HMAC if ticket IDs ever become predictable.

### F-12 — Email-only auth & account enumeration (Info, documented) — ACCEPTED for demo

* Sign-in auto-creates accounts, so there is no enumeration *distinction*
  (both paths return `{"ok": true}` and set a session) — enumeration is
  limited to `POST /api/register`-style feedback, which does not exist.
  Documented in SECURITY.md as the #1 pre-production fix: real identity,
  passwords/SSO, session rotation on privilege change.

### F-13 — CSRF posture (Info) — ACCEPTED with rationale

* State-changing endpoints are cookie-authenticated `POST`s; cookie is
  `samesite=lax`, which blocks cross-site POST navigation-based CSRF.
  JSON `Content-Type` requirement adds preflight-level friction.
  If the cookie ever becomes `samesite=none` (embedded webview flows),
  add double-submit tokens before launch.

### F-14 — Positive findings (verified, no action)

* All SQL is parameterized (no string-built queries anywhere in
  `main.py`/`db.py`) — no SQL injection (CWE-89) surface.
* PII minimization: receipts/analytics mask emails (`x***@domain`;
  `R-<sha1(email)[:8]>`), CSV export emits rider refs, never emails.
* Per-receipt ownership enforced (`AND account_id = ?` in
  `/api/receipts/{txn_id}`) — no IDOR (CWE-639) between riders.
* Ticket state resolved server-side at scan time; the QR is a signed
  pointer only (no replay of consumed tickets, no client-side trust).
* `?stop=` deep link rendered via `textContent`; stop lookups
  parameterized + `code.upper()` canonicalized.

---

## 3. Residual risks / recommendations for round 2

Ordered review queue for Claude/Lumo — each item names the file to look at:

1. **`receipt.html` inline script/styles** → split into `receipt.js`/styles
   and drop `'unsafe-inline'` from CSP (hash/nonce based). (F-06 residual)
2. **Multi-process shared rate limiting** (`Redis` or `slowapi`) +
   `Retry-After` on 429. (F-07 residual)
3. **Admin model** — replace shared token with staff SSO + audit log of
   admin access; today there is no logging of *who* exported data.
4. **Payments** — `topup()` is simulated; real PSP integration should be
   webhook-settled, idempotent (idempotency key on `transactions.id`),
   and never trust client amounts.
5. **Account auth** — passwords/SSO, email verification, session rotation,
   logout-everywhere. `sessions` table has no rotation/UA/IPv6 binding.
6. **SQLite durability** — enable WAL (`PRAGMA journal_mode=WAL`) for
   concurrent readers during writes; add `busy_timeout` for multi-process.
7. **Upload/flagging** — none exists today (good); keep it that way.
8. **Dependency pinning** — `requirements.txt` uses `>=` floors (Dependabot
   PRs #1/#2/#4/#6/#7 open against them). Consider a lockfile for
   reproducible deploys.

---

## 4. Regression & verification evidence

* Suite: `tests/e2e_test.py` — **18 checks / 22 assertions, 22/22 PASS**
  against a live server on a fresh seeded DB.
* New security regressions added in v1.1.0: admin 401/403/200, CSV token
  gate, path-traversal probes, security-header assertions, unknown-route
  fare-gate resilience.
* CI: `.github/workflows/ci.yml` boots the server on `ubuntu-latest`,
  installs from `requirements.txt`, runs the suite, and asserts the
  security headers — every future push/PR re-verifies all of the above.
* CodeQL: `.github/workflows/codeql.yml`, `security-extended` query pack,
  JavaScript **and** Python, on push/PR/weekly — findings appear under
  Security → Code scanning alerts.

## 5. Files changed in v1.1.0

| File | Change |
|---|---|
| `app/main.py` | 1.1.0 — F-01..F-09 (admin gate, limiter, headers, races, traversal, FK guards, session prune, cookie flag) |
| `app/db.py` | 1.1.0 — F-10 (0600 secret), nullable `boardings.route_id` |
| `app/static/app.js` | 1.1.0 — F-08 esc() everywhere |
| `app/static/scanner.js` | 1.1.0 — F-08 esc() in log/selects |
| `app/static/dashboard.js` | 1.1.0 — F-01 admin token flow + F-08 esc() + tokened CSV link |
| `app/static/receipt.html` | 1.1.0 — F-08 esc() |
| `app/static/index.html` / `scanner.html` / `dashboard.html` | 1.1.0 — header bump only |
| `tests/e2e_test.py` | 1.1.0 — security regression checks 11–18 |
| `.github/workflows/codeql.yml` | NEW — automated security scanning |
| `.github/workflows/ci.yml` | NEW — e2e + header CI gate |
| `.github/dependabot.yml` | 1.2.0 — re-added `github-actions` ecosystem (workflows now exist) |
| `SECURITY.md` | controls + supported-versions matrix + schema upgrade note |
| `README.md` | security posture section, new env vars, upgraded architecture tree |

## 6. Prompt template for the reviewer AI

> You are reviewing BFT QR Pay v1.1.0 (QR-code fare payment: FastAPI +
> SQLite + vanilla JS; HMAC-signed QR payloads; wallet, receipts, agency
> analytics). The audit above claims findings F-01…F-13 are fixed and
> F-14 confirmed clean. Your tasks:
> 1. Try to **disprove** each fixed finding — hunt for bypasses (e.g.
>    admin-token leakage paths, race windows left open, traversal edge
>    cases on Windows, CSRF on token-gated GETs).
> 2. **Bug-hunt** beyond security: currency math, timezone handling in
>    expiry comparisons (`_now_iso()` vs naive strings), JSON error
>    shapes, QR render cost under load, receipt sequence under restart.
> 3. Audit the **residual queue** in §3 and produce concrete patches.
> 4. Report format: Finding ID / severity / file:function / evidence /
>    suggested patch (with `VERSION: x.y.z` bump per repo convention).
