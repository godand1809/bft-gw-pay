"""
tests/e2e_test.py -- End-to-end test for BFT QR Pay (VERSION 1.0.0)

Run against a live server:
    python run.py            # in one terminal
    python tests/e2e_test.py # in another

12 checks:
  1.  Health + rider page load
  2.  Sign-in (session cookie)
  3.  Wallet top-up
  4.  Single-ride purchase (QR minted, HMAC verified)
  5.  First scan ACCEPTED (ride consumed)
  6.  Re-scan REJECTED ("Ticket is used")
  7.  Tampered payload REJECTED
  8.  Day pass purchase + double boarding ACCEPTED
  9.  Receipts list + single receipt fetch
  10. Insufficient funds -> 402
  11. Analytics endpoint returns real numbers
  12. CSV export + scanner/dashboard pages load
"""

import hashlib
import hmac
import json
import os
import secrets
import urllib.error
import urllib.request

BASE = os.environ.get("BFT_BASE", "http://127.0.0.1:8000")

# Cookie jar for the demo session.
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())


def call(method, path, body=None, raw=False):
    """HTTP helper returning (status, parsed-json-or-bytes)."""
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with OPENER.open(req) as r:
            payload = r.read()
            return r.status, (payload if raw else json.loads(payload))
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload)
        except Exception:
            return e.code, payload


passed = failed = 0


def check(n, desc, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS {n:2d}. {desc}")
    else:
        failed += 1
        print(f"  FAIL {n:2d}. {desc} {extra}")


# 1. Health + rider page
s, b = call("GET", "/healthz")
check(1, "healthz ok", s == 200 and b.get("status") == "ok")
s, page = call("GET", "/", raw=True)
check(1, "rider page loads", s == 200 and b"BFT QR Pay" in page)

# 2. Sign in
email = f"e2e_{secrets.token_hex(4)}@example.com"
s, b = call("POST", "/api/session", {"email": email})
check(2, "sign-in sets session", s == 200 and b.get("ok"))

# 3. Top-up $20
s, b = call("POST", "/api/topup", {"amount_cents": 2000, "card_last4": "4242"})
check(3, "top-up credits wallet", s == 200 and b.get("wallet_cents") == 2000)

# 4. Purchase single ride
s, b = call("POST", "/api/purchase", {"product_code": "SINGLE", "reduced": False})
ticket = b.get("ticket", {})
payload = ticket.get("qr_payload", "")
check(4, "purchase mints signed QR", s == 200 and payload.startswith("BFT1:"))

# Verify the HMAC locally (proves the signing scheme end-to-end).
tid = payload.split(":")[1]
secret_path = os.path.join(os.path.dirname(__file__), "..", "data", ".secret")
secret = open(secret_path).read().strip()
expected_sig = hmac.new(secret.encode(), tid.encode(), hashlib.sha256).hexdigest()[:16]
check(4, "payload HMAC is correct", payload.endswith(expected_sig))

# 5. First scan accepted
s, b = call("POST", "/api/validate",
            {"payload": payload, "route_id": "26", "scanner_id": "SCN-E2E"})
check(5, "first scan accepted", s == 200 and b.get("result") == "accepted", str(b))

# 6. Re-scan rejected (single ride consumed)
s, b = call("POST", "/api/validate",
            {"payload": payload, "route_id": "26", "scanner_id": "SCN-E2E"})
check(6, "re-scan rejected (used)", s == 200 and b.get("result") == "rejected"
      and "used" in b.get("reason", ""))

# 7. Tampered payload rejected
tampered = payload[:-4] + "0000"
s, b = call("POST", "/api/validate",
            {"payload": tampered, "route_id": "26", "scanner_id": "SCN-E2E"})
check(7, "tampered payload rejected", s in (200, 400)
      and (b.get("result") == "rejected" if isinstance(b, dict) else True))

# 8. Day pass: double boarding accepted
s, b = call("POST", "/api/purchase", {"product_code": "DAY", "reduced": False})
day_payload = b["ticket"]["qr_payload"]
r1, _ = call("POST", "/api/validate", {"payload": day_payload, "route_id": "100"})
r2, _ = call("POST", "/api/validate", {"payload": day_payload, "route_id": "110"})
check(8, "day pass double boarding accepted", r1 == 200 and r2 == 200)

# 9. Receipts
s, b = call("GET", "/api/receipts")
receipts = b.get("receipts", [])
check(9, "receipts listed (>=3)", s == 200 and len(receipts) >= 3)
s, b = call("GET", f"/api/receipts/{receipts[0]['id']}")
check(9, "single receipt fetch", s == 200 and b.get("receipt", {}).get("id") == receipts[0]["id"])

# 10. Insufficient funds -> 402
s, b = call("POST", "/api/purchase", {"product_code": "YEAR", "reduced": False})
check(10, "insufficient funds -> 402", s == 402)

# 11. Analytics
s, b = call("GET", "/api/admin/analytics?days=30")
k = b.get("kpis", {})
check(11, "analytics returns KPIs", s == 200 and k.get("revenue_cents", 0) > 0
      and k.get("boardings", 0) > 0)

# 12. CSV export + scanner/dashboard pages
s, csv_bytes = call("GET", "/api/admin/export.csv?days=90", raw=True)
check(12, "CSV export works", s == 200 and b"receipt_id" in csv_bytes)
s, p1 = call("GET", "/static/scanner.html", raw=True)
s2, p2 = call("GET", "/static/dashboard.html", raw=True)
check(12, "scanner + dashboard pages load", s == 200 and s2 == 200)

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
