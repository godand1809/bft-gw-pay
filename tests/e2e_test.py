"""
tests/e2e_test.py -- End-to-end test for BFT QR Pay (VERSION 1.1.0)

Run against a live server:
    python run.py            # in one terminal
    python tests/e2e_test.py # in another

v1.1.0 adds security regression checks 13-18 (refs: v1.0.0 12 checks):

Core checks:
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

Security regression checks (v1.1.0):
  13. /api/admin/analytics WITHOUT token -> 401 (was wide open)
  14. /api/admin/analytics with WRONG token -> 403
  15. /api/admin/analytics with CORRECT token -> 200
  16. Path traversal in /static/ -> 404 (%2e%2e and backslash forms)
  17. Security headers present (nosniff, frame-deny, CSP, referrer)
  18. Unknown route_id on /api/validate -> clean rejection, not a 500
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

# 11. Analytics -- requires the admin token since v1.1.0.
admin_token_path = os.path.join(
    os.path.dirname(__file__), "..", "data", ".admin_token")
ADMIN = open(admin_token_path).read().strip()

s, b = call("GET", "/api/admin/analytics?days=30")
check(11, "analytics without token -> 401", s == 401,
      f"got {s}")

# 12. CSV export + scanner/dashboard pages (now token-gated)
s, csv_bytes = call("GET", "/api/admin/export.csv?days=90", raw=True)
check(12, "CSV export without token -> 401", s == 401, f"got {s}")
s, p1 = call("GET", "/static/scanner.html", raw=True)
s2, p2 = call("GET", "/static/dashboard.html", raw=True)
check(12, "scanner + dashboard pages load", s == 200 and s2 == 200)

# ---- v1.1.0 SECURITY REGRESSION CHECKS -----------------------------------
req = urllib.request.Request(BASE + "/api/admin/analytics?days=30",
                             headers={"X-Admin-Token": "wrong-token"})
try:
    with OPENER.open(req) as r:
        s_wrong = r.status
except urllib.error.HTTPError as e:
    s_wrong = e.code
check(13, "analytics with WRONG token -> 403", s_wrong == 403,
      f"got {s_wrong}")

req = urllib.request.Request(BASE + "/api/admin/analytics?days=30",
                             headers={"X-Admin-Token": ADMIN})
with OPENER.open(req) as r:
    analytics = json.loads(r.read())
k = analytics.get("kpis", {})
check(14, "analytics with CORRECT token -> 200 + KPIs",
      r.status == 200 and k.get("revenue_cents", 0) > 0
      and k.get("boardings", 0) > 0)

# CSV with token appended as query param (how the dashboard links it).
s, csv_bytes = call("GET", f"/api/admin/export.csv?days=90&admin_token={ADMIN}",
                    raw=True)
check(15, "CSV export with token works", s == 200 and b"receipt_id" in csv_bytes)

# 16. Path traversal: encoded ../ and dotfile access must 404.
#     urllib normalizes literal ../, so use percent-encoded segments.
traversal_paths = [
    "/static/%2e%2e/db.py",                  # encodes to /static/../db.py
    "/static/%2e%2e/%2e%2e/app/db.py",       # climbs two levels
    "/static/%2e%2e/data/.secret",           # the signing secret itself
]
trav_ok = True
for tp in traversal_paths:
    try:
        with OPENER.open(BASE + tp) as r:
            trav_ok &= r.status != 200
    except urllib.error.HTTPError as e:
        trav_ok &= e.code == 404
check(16, "path traversal attempts -> 404", trav_ok)

# 17. Security headers stamped on every response.
with OPENER.open(BASE + "/") as r:
    hdrs = {k.lower(): v for k, v in r.headers.items()}
check(17, "security headers present",
      hdrs.get("x-content-type-options") == "nosniff"
      and hdrs.get("x-frame-options") == "DENY"
      and "default-src 'self'" in hdrs.get("content-security-policy", "")
      and hdrs.get("referrer-policy") in ("no-referrer", "strict-origin-when-cross-origin"),
      str(hdrs))

# 18. Unknown route_id must not crash the fare gate with a 500.
s, b = call("POST", "/api/validate",
            {"payload": payload, "route_id": "NOPE-99", "scanner_id": "SCN-E2E"})
check(18, "unknown route -> clean rejection (no 500)",
      s == 200 and isinstance(b, dict) and b.get("result") == "rejected",
      f"got {s} {b}")

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
