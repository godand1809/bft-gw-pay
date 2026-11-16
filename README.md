# BFT QR Pay

QR-code fare payment for **Ben Franklin Transit** (bft.org) — the public
transit agency serving the Tri-Cities, WA (Kennewick, Pasco, Richland).
Riders pay for fares in-app, board by showing a tamper-proof scannable QR
code, get instant proof of purchase, and the agency gets a full analytics
dashboard.

> **Demo notice:** authentication and payments are intentionally simplified
> for evaluation. See `SECURITY.md` for the full list of known demo
> limitations and the production hardening path.

## What the application is

A self-contained web application (FastAPI + SQLite + vanilla JS, no build
step) with three surfaces:

| Surface | URL | Who uses it |
|---|---|---|
| **Rider app** | `/` | Riders: wallet, buy fares, show QR tickets, view receipts |
| **Fare validator** | `/static/scanner.html` | Operators: camera-scan rider QRs, accept/reject, print stop posters |
| **Analytics dashboard** | `/static/dashboard.html` | Agency staff: KPIs, revenue/ridership charts, CSV export |

## How it functions

1. **Paying** — the rider signs in (demo: email only), tops up a wallet
   with a simulated card payment ($1–$200), then buys a fare product.
   The purchase debits the wallet, mints a ticket, and records a receipt.
2. **Riding with the QR** — each ticket renders as a QR code encoding
   `BFT1:<ticket_id>:<hmac-sha256[:16]>`, signed with a per-install secret.
   The operator's scanner camera-decodes it and POSTs it to `/api/validate`,
   which resolves **all** ticket state server-side (signature → existence →
   status → expiry → rides) before consuming a ride and logging the boarding.
   Forged, edited, expired, and replayed codes are all rejected.
3. **Proof of purchase** — every top-up and purchase writes an immutable
   transaction row with a receipt number (`BFT-YYYY-NNNNNN`), viewable as a
   printable receipt page (`/static/receipt.html?id=...`).
4. **Analytics** — every purchase, top-up, and boarding feeds the dashboard:
   revenue/day, boardings by route, product mix, payment mix, recent
   transactions (masked riders), and a raw CSV export.

## Fares (BFT 2025 structure)

| Product | Price | Reduced | Rides | Validity |
|---|---|---|---|---|
| Single Ride | $1.00 | $0.50 | 1 | 2 h from first scan |
| Day Pass (mobile only) | $3.00 | $1.50 | Unlimited | 24 h |
| 10-Ride Book | $8.00 | $4.00 | 10 | 12 months |
| Monthly Pass | $10.00 | $5.00 | Unlimited | 30 days |
| Yearly Pass (mobile only) | $120.00 | $60.00 | Unlimited | 12 months |

## Run it

```bash
pip install -r requirements.txt
python run.py            # http://127.0.0.1:8000
```

First run creates `data/bft.db` and seeds ~90 days of deterministic demo
data (seed 42) so the dashboard is populated immediately. Delete `data/`
to reset.

Test suite (12 end-to-end checks against a running server):

```bash
python tests/e2e_test.py
```

## Architecture

```
bft-qr-pay/
├── app/
│   ├── main.py          # FastAPI API: auth, wallet, purchases, QR mint/validate, analytics
│   ├── db.py            # SQLite schema, BFT catalogs, HMAC secret, demo seeder
│   └── static/          # index/app (rider), scanner, dashboard, receipt, styles.css
├── tests/e2e_test.py    # 12-check end-to-end suite
├── data/                # runtime only (gitignored): bft.db + .secret
├── SECURITY.md          # security policy + demo limitations
└── .github/dependabot.yml
```

## Production notes

- Replace the simulated top-up with a real PSP (Stripe/Adyen PaymentIntent).
- Put `/api/admin/*` behind staff SSO.
- Add rate limiting, TLS termination, and real account recovery.
- The HMAC secret (`data/.secret`) must be backed up securely; rotating it
  invalidates all outstanding QR tickets.
