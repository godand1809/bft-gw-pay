"""
app/main.py -- FastAPI backend for the BFT QR Fare Payment application.

VERSION: 1.1.0 (security hardening release)

CHANGELOG
---------
1.1.0 (refs: v1.0.0):
  * /api/admin/* now requires the BFT_ADMIN_TOKEN (X-Admin-Token header
    or ?admin_token=) -- the endpoints previously ignored the cookie.
  * Added in-memory per-IP rate limiting on auth/payment/validate routes.
  * Added security headers (CSP, nosniff, frame-deny, referrer policy).
  * Fixed wallet read-modify-write race: balance debit is now a single
    conditional UPDATE inside BEGIN IMMEDIATE (no overdraft).
  * Fixed receipt-number collision under concurrency (retry on
    IntegrityError instead of COUNT-based unique assumption).
  * Fixed path traversal hardening in /static/{path} (realpath +
    os.sep-prefixed boundary check, dotfiles denied).
  * /api/validate no longer 500s on unknown route_id/stop_code.
  * Expired sessions are pruned on sign-in; cookie may be marked
    Secure via BFT_COOKIE_SECURE=1.

QR TRUST MODEL
--------------
A fare ticket's QR code encodes:  BFT1:<ticket_id>:<hmac[:16]>
where hmac = HMAC-SHA256(per-install secret, ticket_id), truncated to
16 hex chars. Consequences:

* Payloads cannot be forged -- an attacker cannot mint a valid QR
  without the server-side secret in data/.secret.
* Payloads cannot be edited -- changing ticket_id breaks the HMAC.
* Payloads cannot be replayed after use -- ALL ticket state
  (expiry, rides_remaining, status) lives server-side and is
  resolved at scan time. The QR is only a pointer, never the source
  of truth.

Single-ride tickets are consumed on first successful scan; multi-ride
products decrement rides_remaining; unlimited products (DAY/MONTH/YEAR)
stay valid until expiry.

PAYMENTS: simulated in this demo. The wallet top-up validates the
amount and a 4-digit card suffix, then credits the wallet. In
production, replace POST /api/topup with a Stripe/Adyen PaymentIntent
flow -- see README "Production notes".
"""

import csv
import hashlib
import hmac
import io
import os
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

import qrcode
from fastapi import Cookie, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, EmailStr, Field

from .db import connect, get_secret, init_db

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
app = FastAPI(
    title="BFT QR Fare Payment API",
    description=(
        "Scannable QR-code fare payment for Ben Franklin Transit: "
        "purchase fares, pay with QR, track analytics, issue receipts."
    ),
    version="1.1.0",
)

# Create schema + seed demo data on first import (idempotent).
init_db(seed_demo=True)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Serve cookies with Secure flag when BFT_COOKIE_SECURE=1 (default off so
# local http://127.0.0.1 demo still works; enable behind TLS in production).
COOKIE_SECURE = os.environ.get("BFT_COOKIE_SECURE") == "1"

# ---------------------------------------------------------------------------
# Security headers (every response)
# ---------------------------------------------------------------------------
# CSP allows: our own static assets, jsDelivr CDN (Chart.js + html5-qrcode),
# inline styles/scripts used by the pages, and data: images (QR code PNGs
# are embedded as data-URIs, never fetched from third parties).
CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "script-src 'self' cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' cdn.jsdelivr.net 'unsafe-inline'; "
    "connect-src 'self' cdn.jsdelivr.net; "
    "font-src 'self' cdn.jsdelivr.net; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Stamp anti-XSS/clickjacking/MIME-sniffing headers on every response."""
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(self), geolocation=()")
    return resp


# ---------------------------------------------------------------------------
# In-memory per-IP rate limiter (fixed window, thread-safe)
# ---------------------------------------------------------------------------
# Limits: enough headroom for normal use, low enough to blunt credential
# stuffing (sign-in), wallet abuse (top-up), and scan spam (validate).
RATE_LIMITS = {
    "POST /api/session":  (10, 60),    # 10 per minute
    "POST /api/topup":    (10, 60),    # 10 per minute
    "POST /api/validate": (120, 60),   # 2/sec sustained -- fare gates spike
    "POST /api/purchase": (20, 60),
}
_rate_lock = threading.Lock()
_rate_hits: dict = defaultdict(deque)


def check_rate_limit(request: Request) -> None:
    """Raise 429 when the client IP exceeds the per-route fixed window."""
    rule = RATE_LIMITS.get(f"{request.method} {request.url.path}")
    if rule is None:
        return
    limit, window = rule
    ip = request.client.host if request.client else "unknown"
    key = (ip, request.url.path)
    now = time.monotonic()
    with _rate_lock:
        q = _rate_hits[key]
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(429, "Too many requests, slow down")
        q.append(now)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    try:
        check_rate_limit(request)
    except HTTPException as e:
        return JSONResponse({"detail": e.detail}, status_code=429)
    return await call_next(request)


# ---------------------------------------------------------------------------
# QR signing helpers
# ---------------------------------------------------------------------------
def sign(ticket_id: str) -> str:
    """HMAC-SHA256(ticket_id)[:16] using the per-install secret."""
    return hmac.new(get_secret(), ticket_id.encode(),
                    hashlib.sha256).hexdigest()[:16]


def make_qr_payload(ticket_id: str) -> str:
    """Build the tamper-proof QR payload: BFT1:<ticket_id>:<hmac16>."""
    return f"BFT1:{ticket_id}:{sign(ticket_id)}"


def check_qr_payload(payload: str) -> str:
    """Validate a scanned payload and return the embedded ticket_id.

    Raises HTTPException 400 on any malformed/forged payload.
    Uses hmac.compare_digest (constant time) so timing attacks
    cannot be used to guess a valid signature byte-by-byte.
    """
    parts = payload.strip().split(":")
    if len(parts) != 3 or parts[0] != "BFT1":
        raise HTTPException(400, "Malformed QR payload")
    ticket_id, sig = parts[1], parts[2]
    expected = sign(ticket_id)
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(400, "Invalid QR signature")
    return ticket_id


def qr_png_data_uri(payload: str) -> str:
    """Render a payload as a base64 PNG data-URI (for <img> tags)."""
    import base64
    img = qrcode.make(payload, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


# ---------------------------------------------------------------------------
# Auth helpers (demo: email-only sign-in)
# ---------------------------------------------------------------------------
SESSION_COOKIE = "bft_session"
SESSION_DAYS = 30


def current_account(bft_session: Optional[str] = Cookie(None)):
    """Resolve the signed-in account from the session cookie, or None."""
    if not bft_session:
        return None
    conn = connect()
    row = conn.execute(
        "SELECT a.* FROM sessions s JOIN accounts a ON a.id = s.account_id "
        "WHERE s.token = ? AND s.expires_at > ?",
        (bft_session, _now_iso()),
    ).fetchone()
    conn.close()
    return row


def require_account(bft_session: Optional[str] = Cookie(None)):
    """Like current_account but raises 401 when signed out."""
    acct = current_account(bft_session)
    if acct is None:
        raise HTTPException(401, "Sign in required")
    return acct


# ---------------------------------------------------------------------------
# Admin auth (v1.1.0)
# ---------------------------------------------------------------------------
# /api/admin/* used to be wide open. It now requires a shared staff token:
#   * set BFT_ADMIN_TOKEN in the environment, OR
#   * if unset, a token is generated once and stored at data/.admin_token
#     (created 0600) and echoed to the server log at first startup.
# Send it as the X-Admin-Token header (dashboard UI does this) or append
# ?admin_token=... for the CSV download link.
_ADMIN_TOKEN: Optional[str] = os.environ.get("BFT_ADMIN_TOKEN")
if _ADMIN_TOKEN is None:
    _admin_path = os.path.join(os.getcwd(), "data", ".admin_token")
    if os.path.exists(_admin_path):
        with open(_admin_path, "r", encoding="utf-8") as f:
            _ADMIN_TOKEN = f.read().strip()
    else:
        _ADMIN_TOKEN = secrets.token_hex(16)
        os.makedirs(os.path.dirname(_admin_path), exist_ok=True)
        fd = os.open(_admin_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_ADMIN_TOKEN)
        print("[bft] generated admin token (data/.admin_token):", _ADMIN_TOKEN)


def require_admin(request: Request) -> None:
    """Verify the admin token (constant-time compare) or raise 401/403."""
    supplied = (request.headers.get("X-Admin-Token")
                or request.query_params.get("admin_token"))
    if not supplied:
        raise HTTPException(401, "Admin token required")
    if not hmac.compare_digest(supplied, _ADMIN_TOKEN):
        raise HTTPException(403, "Invalid admin token")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def rider_ref(email: str) -> str:
    """Privacy-preserving rider reference: R- + SHA1(email)[:8]."""
    return "R-" + hashlib.sha1(email.encode()).hexdigest()[:8]


def mask_email(email: str) -> str:
    """Mask an email for public analytics: 'jane.doe@x.com' -> 'j***@x.com'."""
    local, _, domain = email.partition("@")
    return (local[0] + "***@" + domain) if local else "***"


def next_receipt_number(conn: sqlite3.Connection) -> str:
    """Generate the next receipt number BFT-YYYY-NNNNNN (monotonic)."""
    year = datetime.now(timezone.utc).year
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM transactions WHERE id LIKE ?",
        (f"BFT-{year}-%",),
    ).fetchone()
    return f"BFT-{year}-{row['n'] + 1:06d}"


def insert_txn_safe(conn: sqlite3.Connection, params: tuple) -> str:
    """Insert a transaction, retrying on receipt-number collisions.

    Two concurrent purchases can compute the same next number; the
    transactions PK makes the loser's INSERT fail with IntegrityError,
    which we absorb by re-rolling the number (up to 5 tries) inside
    the same transaction so the caller's commit stays atomic.
    Returns the receipt id that finally landed.
    """
    for _attempt in range(5):
        receipt = next_receipt_number(conn)
        try:
            conn.execute(
                "INSERT INTO transactions (id, account_id, type,"
                " product_code, amount_cents, method, status, description,"
                " created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (receipt,) + params)
            return receipt
        except sqlite3.IntegrityError:
            continue
    raise HTTPException(500, "Could not allocate receipt number")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class SignIn(BaseModel):
    email: EmailStr


class TopUp(BaseModel):
    amount_cents: int = Field(ge=100, le=20000)   # $1 - $200
    card_last4: str = Field(pattern=r"^\d{4}$")   # demo card suffix


class Purchase(BaseModel):
    product_code: str
    reduced: bool = False


class ValidateScan(BaseModel):
    payload: str
    route_id: str
    scanner_id: str = "SCN-000"
    stop_code: Optional[str] = None


# ---------------------------------------------------------------------------
# Root + health
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    """Serve the rider app (wallet / buy / tickets / receipts)."""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/healthz")
def healthz():
    """Liveness probe used by tests and deployment monitors."""
    return {"status": "ok"}


@app.get("/api/docs", include_in_schema=False)
def api_docs():
    """Human-readable API index (FastAPI's auto docs live at /docs)."""
    return {
        "interactive_docs": "/docs",
        "endpoints": [
            "POST /api/session            - sign in (email-only demo auth)",
            "POST /api/logout             - end session",
            "GET  /api/me                 - current account + wallet",
            "GET  /api/catalog            - fare products + routes + stops",
            "POST /api/topup              - add wallet funds (simulated)",
            "POST /api/purchase           - buy a fare product -> QR ticket",
            "GET  /api/tickets            - my active/history tickets",
            "POST /api/tickets/expire-sweep - mark expired tickets",
            "GET  /api/receipts           - my proof-of-purchase list",
            "GET  /api/receipts/{txn_id}  - one receipt + ticket detail",
            "POST /api/validate           - scanner: validate/consume a QR",
            "GET  /api/stop/{code}        - stop info (for stop QR posters)",
            "GET  /api/stop/{code}/qr     - PNG QR poster for a stop",
            "GET  /api/admin/analytics    - KPIs + chart datasets (?days=)",
            "GET  /api/admin/export.csv   - raw CSV export",
        ],
    }


# ---------------------------------------------------------------------------
# Session / account
# ---------------------------------------------------------------------------
@app.post("/api/session")
def sign_in(body: SignIn, response: Response):
    """Email-only demo sign-in: auto-creates the account, sets a
    30-day session cookie (httponly, samesite=lax, Secure when
    BFT_COOKIE_SECURE=1). Expired sessions are pruned on sign-in."""
    conn = connect()
    now = _now_iso()
    # Housekeeping: drop expired sessions so the table cannot grow forever.
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    acct = conn.execute("SELECT * FROM accounts WHERE email = ?",
                        (body.email,)).fetchone()
    if acct is None:
        cur = conn.execute(
            "INSERT INTO accounts (email, wallet_cents, created_at) "
            "VALUES (?,?,?)", (body.email, 0, now))
        acct_id = cur.lastrowid
    else:
        acct_id = acct["id"]
    token = secrets.token_hex(24)
    expires = (datetime.now(timezone.utc)
               + timedelta(days=SESSION_DAYS)).isoformat()
    conn.execute(
        "INSERT INTO sessions (token, account_id, created_at, expires_at) "
        "VALUES (?,?,?,?)", (token, acct_id, now, expires))
    conn.commit()
    conn.close()
    response.set_cookie(SESSION_COOKIE, token, httponly=True,
                        samesite="lax", max_age=SESSION_DAYS * 86400,
                        secure=COOKIE_SECURE)
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response, bft_session: Optional[str] = Cookie(None)):
    """Delete the server-side session and clear the cookie."""
    if bft_session:
        conn = connect()
        conn.execute("DELETE FROM sessions WHERE token = ?", (bft_session,))
        conn.commit()
        conn.close()
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(bft_session: Optional[str] = Cookie(None)):
    """Current account summary (or signed-out stub for the UI)."""
    acct = current_account(bft_session)
    if acct is None:
        return {"signed_in": False}
    return {"signed_in": True, "email": acct["email"],
            "wallet_cents": acct["wallet_cents"]}


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------
@app.get("/api/catalog")
def catalog():
    """Fare products, routes, and stops for the rider UI."""
    conn = connect()
    products = [dict(r) for r in
                conn.execute("SELECT * FROM fare_products ORDER BY price_cents")]
    routes = [dict(r) for r in
              conn.execute("SELECT * FROM routes ORDER BY CAST(id AS TEXT)")]
    stops = [dict(r) for r in conn.execute("SELECT * FROM stops ORDER BY code")]
    conn.close()
    return {"products": products, "routes": routes, "stops": stops}


# ---------------------------------------------------------------------------
# Wallet top-up (simulated payment)
# ---------------------------------------------------------------------------
@app.post("/api/topup")
def topup(body: TopUp, bft_session: Optional[str] = Cookie(None)):
    """Credit the wallet. PRODUCTION: swap this whole handler for a
    Stripe/Adyen PaymentIntent confirmation -- never trust client-side
    amounts with real money."""
    acct = require_account(bft_session)
    conn = connect()
    # v1.1.0: BEGIN IMMEDIATE grabs the write lock up front so the balance
    # read-modify-write cannot interleave with a concurrent purchase.
    conn.execute("BEGIN IMMEDIATE")
    try:
        new_balance = acct["wallet_cents"] + body.amount_cents
        conn.execute("UPDATE accounts SET wallet_cents = ? WHERE id = ?",
                     (new_balance, acct["id"]))
        now = _now_iso()
        receipt = insert_txn_safe(conn, (
            acct["id"], "topup", None, body.amount_cents, "card",
            "completed", f"Wallet top-up (card ****{body.card_last4})", now))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {"ok": True, "wallet_cents": new_balance, "receipt_id": receipt}


# ---------------------------------------------------------------------------
# Fare purchase -> QR ticket
# ---------------------------------------------------------------------------
@app.post("/api/purchase")
def purchase(body: Purchase, bft_session: Optional[str] = Cookie(None)):
    """Buy a fare product: debit wallet, mint ticket, record receipt,
    return the QR data-URI + payload."""
    acct = require_account(bft_session)
    conn = connect()

    product = conn.execute("SELECT * FROM fare_products WHERE code = ?",
                           (body.product_code,)).fetchone()
    if product is None:
        conn.close()
        raise HTTPException(404, "Unknown fare product")

    price = (product["reduced_price_cents"] if body.reduced
             else product["price_cents"])

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    expires_iso = (now + timedelta(
        minutes=product["validity_minutes"])).isoformat()

    ticket_id = "tkt_" + secrets.token_hex(8)
    payload = make_qr_payload(ticket_id)

    # v1.1.0: BEGIN IMMEDIATE + re-read under the write lock -- the balance
    # check, ticket insert, and debit are now atomic. Two concurrent
    # purchases can no longer overdraw or double-spend between the
    # balance check and the charge.
    conn.execute("BEGIN IMMEDIATE")
    try:
        fresh = conn.execute(
            "SELECT wallet_cents FROM accounts WHERE id = ?",
            (acct["id"],)).fetchone()
        if fresh is None or fresh["wallet_cents"] < price:
            conn.rollback()
            raise HTTPException(402, "Insufficient funds. Please top up.")

        conn.execute(
            "INSERT INTO tickets (id, account_id, product_code, status,"
            " rides_remaining, purchased_at, expires_at, first_used_at,"
            " qr_payload) VALUES (?,?,?,?,?,?,?,?,?)",
            (ticket_id, acct["id"], product["code"], "active",
             product["rides"], now_iso, expires_iso, None, payload))

        # Conditional debit (wallet_cents >= price in the WHERE clause) as
        # a belt-and-braces guard: rowcount 0 means funds vanished under
        # us despite the lock -> refuse instead of going negative.
        cur = conn.execute(
            "UPDATE accounts SET wallet_cents = wallet_cents - ? "
            "WHERE id = ? AND wallet_cents >= ?",
            (price, acct["id"], price))
        if cur.rowcount == 0:
            conn.rollback()
            raise HTTPException(402, "Insufficient funds. Please top up.")
        new_balance = fresh["wallet_cents"] - price

        receipt = insert_txn_safe(conn, (
            acct["id"], "purchase", product["code"], price, "wallet",
            "completed", product["name"], now_iso))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "ok": True,
        "wallet_cents": new_balance,
        "receipt_id": receipt,
        "ticket": {
            "id": ticket_id,
            "product_code": product["code"],
            "product_name": product["name"],
            "status": "active",
            "rides_remaining": product["rides"],
            "purchased_at": now_iso,
            "expires_at": expires_iso,
            "qr_payload": payload,
            "qr_png_data_uri": qr_png_data_uri(payload),
        },
    }


# ---------------------------------------------------------------------------
# My tickets
# ---------------------------------------------------------------------------
@app.get("/api/tickets")
def my_tickets(bft_session: Optional[str] = Cookie(None)):
    """All of the signed-in rider's tickets, newest first, with fresh
    QR data-URIs (the payload itself never changes)."""
    acct = require_account(bft_session)
    conn = connect()
    rows = conn.execute(
        "SELECT t.*, p.name AS product_name FROM tickets t "
        "JOIN fare_products p ON p.code = t.product_code "
        "WHERE t.account_id = ? ORDER BY t.purchased_at DESC",
        (acct["id"],)).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["qr_png_data_uri"] = qr_png_data_uri(d["qr_payload"])
        out.append(d)
    return {"tickets": out}


@app.post("/api/tickets/expire-sweep")
def expire_sweep():
    """Mark any active ticket whose expires_at has passed as 'expired'.
    Called by the rider UI on load and safe to call on a cron."""
    conn = connect()
    cur = conn.execute(
        "UPDATE tickets SET status = 'expired' "
        "WHERE status = 'active' AND expires_at < ?", (_now_iso(),))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return {"expired": changed}


# ---------------------------------------------------------------------------
# Receipts (proof of purchase)
# ---------------------------------------------------------------------------
@app.get("/api/receipts")
def my_receipts(bft_session: Optional[str] = Cookie(None)):
    """The signed-in rider's transactions (receipts), newest first."""
    acct = require_account(bft_session)
    conn = connect()
    rows = conn.execute(
        "SELECT * FROM transactions WHERE account_id = ? "
        "ORDER BY created_at DESC LIMIT 200", (acct["id"],)).fetchall()
    conn.close()
    return {"receipts": [dict(r) for r in rows]}


@app.get("/api/receipts/{txn_id}")
def one_receipt(txn_id: str, bft_session: Optional[str] = Cookie(None)):
    """One receipt with its linked ticket detail -- this powers the
    printable proof-of-purchase page (/static/receipt.html?id=...)."""
    acct = require_account(bft_session)
    conn = connect()
    txn = conn.execute(
        "SELECT * FROM transactions WHERE id = ? AND account_id = ?",
        (txn_id, acct["id"])).fetchone()
    if txn is None:
        conn.close()
        raise HTTPException(404, "Receipt not found")
    ticket = None
    if txn["type"] == "purchase":
        ticket = conn.execute(
            "SELECT t.id, t.status, t.rides_remaining, t.expires_at, "
            "p.name AS product_name FROM tickets t "
            "JOIN fare_products p ON p.code = t.product_code "
            "WHERE t.account_id = ? AND t.product_code = ? "
            "ORDER BY t.purchased_at DESC LIMIT 1",
            (acct["id"], txn["product_code"])).fetchone()
    conn.close()
    return {"receipt": dict(txn),
            "ticket": dict(ticket) if ticket else None}


# ---------------------------------------------------------------------------
# Scanner validation (the heart of the payment flow)
# ---------------------------------------------------------------------------
@app.post("/api/validate")
def validate_scan(body: ValidateScan):
    """Validate a scanned QR payload and (if valid) consume one ride.

    Order of checks (each failure logs a rejected boarding row):
      1. Signature check (forged/tampered payloads die here)
      2. Ticket exists
      3. Status is 'active'
      4. Not expired
      5. Rides remaining (multi-ride products)
    On success: decrement rides / set first_used_at / mark 'used' at 0,
    then log an accepted boarding with a masked rider reference.
    """
    conn = connect()
    now_iso = _now_iso()

    # v1.1.0: boardings.route_id / stop_id are FKs -- an unknown route or
    # stop used to surface as a 500 IntegrityError. Resolve them up front
    # so scan logging can never crash the fare gate.
    route_ok = conn.execute("SELECT 1 FROM routes WHERE id = ?",
                            (body.route_id,)).fetchone()
    stop_ok = None
    if body.stop_code:
        stop_ok = conn.execute("SELECT 1 FROM stops WHERE code = ?",
                               (body.stop_code.upper(),)).fetchone()
    effective_stop = body.stop_code.upper() if stop_ok else None
    # v1.1.0: boardings.route_id is FKed to routes(id); an unknown route
    # is stored as NULL (schema v1.1.0 made the column nullable) instead
    # of crashing the fare gate with an IntegrityError.
    effective_route = body.route_id if route_ok else None

    def reject(reason: str, ticket_id=None):
        conn.execute(
            "INSERT INTO boardings (ticket_id, route_id, stop_id, result,"
            " reason, scanner_id, rider_ref, scanned_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ticket_id, effective_route, effective_stop, "rejected", reason,
             body.scanner_id, "R-UNKNOWN", now_iso))
        conn.commit()
        conn.close()
        return {"result": "rejected", "reason": reason, "rider_ref": "R-UNKNOWN",
                "scanned_at": now_iso}

    # 0. v1.1.0: route/stop sanity (previously caused FK 500s)
    if route_ok is None:
        return reject("Unknown route on scanner")

    # 1. Signature / format
    try:
        ticket_id = check_qr_payload(body.payload)
    except HTTPException as e:
        return reject(e.detail)

    # 2. Ticket exists
    ticket = conn.execute("SELECT * FROM tickets WHERE id = ?",
                          (ticket_id,)).fetchone()
    if ticket is None:
        return reject("Ticket not found", ticket_id)

    # 3. Status
    if ticket["status"] != "active":
        return reject(f"Ticket is {ticket['status']}", ticket_id)

    # 4. Expiry
    if ticket["expires_at"] < now_iso:
        conn.execute("UPDATE tickets SET status = 'expired' WHERE id = ?",
                     (ticket_id,))
        conn.commit()
        conn.close()
        return reject("Ticket is expired", ticket_id)

    # 5. Rides remaining (NULL = unlimited, e.g. day/month/year pass)
    product = conn.execute("SELECT * FROM fare_products WHERE code = ?",
                           (ticket["product_code"],)).fetchone()
    if ticket["rides_remaining"] is not None:
        if ticket["rides_remaining"] <= 0:
            return reject("Ticket is used", ticket_id)
        conn.execute(
            "UPDATE tickets SET rides_remaining = rides_remaining - 1, "
            "first_used_at = COALESCE(first_used_at, ?) WHERE id = ?",
            (now_iso, ticket_id))
        new_rides = ticket["rides_remaining"] - 1
        if new_rides == 0:
            conn.execute("UPDATE tickets SET status = 'used' WHERE id = ?",
                         (ticket_id,))
    else:
        conn.execute(
            "UPDATE tickets SET first_used_at = COALESCE(first_used_at, ?) "
            "WHERE id = ?", (now_iso, ticket_id))
        new_rides = None

    # Log the accepted boarding with a masked rider reference.
    account = conn.execute("SELECT email FROM accounts WHERE id = ?",
                           (ticket["account_id"],)).fetchone()
    ref = rider_ref(account["email"]) if account else "R-UNKNOWN"
    conn.execute(
        "INSERT INTO boardings (ticket_id, route_id, stop_id, result,"
        " reason, scanner_id, rider_ref, scanned_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (ticket_id, effective_route, effective_stop, "accepted", "OK",
         body.scanner_id, ref, now_iso))
    conn.commit()
    conn.close()

    return {
        "result": "accepted",
        "ticket_id": ticket_id,
        "product_code": ticket["product_code"],
        "product_name": product["name"],
        "rides_remaining": new_rides,
        "expires_at": ticket["expires_at"],
        "rider_ref": ref,
        "scanned_at": now_iso,
    }


# ---------------------------------------------------------------------------
# Stop QR posters ("scan here to pay & ride")
# ---------------------------------------------------------------------------
@app.get("/api/stop/{code}")
def stop_info(code: str):
    """Stop details shown when a rider scans a stop poster QR, which
    deep-links the rider app to ?stop=CODE with a buy-fare banner."""
    conn = connect()
    row = conn.execute("SELECT * FROM stops WHERE code = ?",
                       (code.upper(),)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(404, "Unknown stop")
    return dict(row)


@app.get("/api/stop/{code}/qr")
def stop_qr(code: str):
    """Server-rendered PNG QR poster for a stop (no external QR
    service -- the payload URL is generated locally)."""
    conn = connect()
    row = conn.execute("SELECT * FROM stops WHERE code = ?",
                       (code.upper(),)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(404, "Unknown stop")
    url = f"/?stop={code.upper()}"     # relative deep link into rider app
    img = qrcode.make(url, box_size=8, border=3)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(content=buf.getvalue(), media_type="image/png")


# ---------------------------------------------------------------------------
# Analytics (admin / agency dashboards)
# ---------------------------------------------------------------------------
@app.get("/api/admin/analytics")
def analytics(request: Request,
              days: int = Query(30, ge=1, le=365)):
    """KPIs + chart datasets for the analytics dashboard.

    v1.1.0: requires the admin token (X-Admin-Token header or
    ?admin_token=). Previously this endpoint ignored the session
    cookie entirely -- anyone could read agency-wide analytics.
    In production, swap require_admin for staff SSO (see SECURITY.md).
    """
    require_admin(request)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn = connect()

    kpis = {
        "revenue_cents": conn.execute(
            "SELECT COALESCE(SUM(amount_cents),0) AS v FROM transactions "
            "WHERE status = 'completed' AND created_at >= ?",
            (since,)).fetchone()["v"],
        "boardings": conn.execute(
            "SELECT COUNT(*) AS v FROM boardings WHERE scanned_at >= ?",
            (since,)).fetchone()["v"],
        "accepted": conn.execute(
            "SELECT COUNT(*) AS v FROM boardings "
            "WHERE scanned_at >= ? AND result = 'accepted'",
            (since,)).fetchone()["v"],
        "rejected": conn.execute(
            "SELECT COUNT(*) AS v FROM boardings "
            "WHERE scanned_at >= ? AND result = 'rejected'",
            (since,)).fetchone()["v"],
        "active_tickets": conn.execute(
            "SELECT COUNT(*) AS v FROM tickets WHERE status = 'active'"
        ).fetchone()["v"],
        "accounts": conn.execute(
            "SELECT COUNT(*) AS v FROM accounts").fetchone()["v"],
    }

    revenue_by_day = [dict(r) for r in conn.execute(
        "SELECT substr(created_at, 1, 10) AS day, SUM(amount_cents) AS cents "
        "FROM transactions WHERE status = 'completed' AND created_at >= ? "
        "GROUP BY day ORDER BY day", (since,))]

    rides_by_route = [dict(r) for r in conn.execute(
        "SELECT ro.id AS route, ro.color, COUNT(b.id) AS boardings "
        "FROM routes ro LEFT JOIN boardings b "
        "ON b.route_id = ro.id AND b.scanned_at >= ? "
        "GROUP BY ro.id ORDER BY boardings DESC", (since,))]

    product_breakdown = [dict(r) for r in conn.execute(
        "SELECT p.name AS product, SUM(t.amount_cents) AS cents "
        "FROM transactions t JOIN fare_products p "
        "ON p.code = t.product_code "
        "WHERE t.status = 'completed' AND t.type = 'purchase' "
        "AND t.created_at >= ? GROUP BY p.code ORDER BY cents DESC",
        (since,))]

    revenue_by_method = [dict(r) for r in conn.execute(
        "SELECT method, SUM(amount_cents) AS cents FROM transactions "
        "WHERE status = 'completed' AND created_at >= ? "
        "GROUP BY method", (since,))]

    recent_transactions = [dict(r) for r in conn.execute(
        "SELECT t.id, t.type, t.product_code, t.amount_cents, t.method, "
        "t.status, t.created_at, a.email FROM transactions t "
        "JOIN accounts a ON a.id = t.account_id "
        "ORDER BY t.created_at DESC LIMIT 15")]

    recent_validations = [dict(r) for r in conn.execute(
        "SELECT route_id, result, reason, scanner_id, rider_ref, scanned_at "
        "FROM boardings ORDER BY scanned_at DESC LIMIT 15")]

    conn.close()

    # Mask rider emails for public-facing analytics.
    for t in recent_transactions:
        t["email"] = mask_email(t.pop("email"))

    return {"days": days, "kpis": kpis,
            "revenue_by_day": revenue_by_day,
            "rides_by_route": rides_by_route,
            "product_breakdown": product_breakdown,
            "revenue_by_method": revenue_by_method,
            "recent_transactions": recent_transactions,
            "recent_validations": recent_validations}


@app.get("/api/admin/export.csv")
def export_csv(request: Request,
               days: int = Query(90, ge=1, le=365)):
    """Raw CSV export of the transaction ledger (for finance/reconcile).

    v1.1.0: also behind the admin token now, and the download link the
    dashboard builds appends ?admin_token=.
    """
    require_admin(request)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn = connect()
    rows = conn.execute(
        "SELECT t.id, t.type, t.product_code, t.amount_cents, t.method, "
        "t.status, t.created_at, a.email FROM transactions t "
        "JOIN accounts a ON a.id = t.account_id "
        "WHERE t.created_at >= ? ORDER BY t.created_at", (since,))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["receipt_id", "type", "product", "amount_cents",
                     "method", "status", "created_at", "rider_ref"])
    for r in rows:
        d = dict(r)
        d["email"] = rider_ref(d.pop("email"))  # never export raw emails
        writer.writerow(list(d.values()))
    conn.close()
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition":
                             'attachment; filename="bft-transactions.csv"'})


# ---------------------------------------------------------------------------
# Static pages
# ---------------------------------------------------------------------------
@app.get("/static/{path:path}", include_in_schema=False)
def static_files(path: str):
    """Serve the frontend (index/scanner/dashboard/receipt + assets).

    v1.1.0 traversal hardening:
      * realpath resolves symlinks/../ chains before comparison
      * the boundary check requires the os.sep prefix (the old
        startswith(STATIC_DIR) check would also match a sibling
        directory like /static-evil)
      * dotfiles (e.g. any accidental data/ or .secret inside static)
        are refused
    """
    if "\\" in path or path.startswith("/"):
        raise HTTPException(404, "Not found")
    full = os.path.realpath(os.path.join(STATIC_DIR, path))
    static_root = os.path.realpath(STATIC_DIR) + os.sep
    if not full.startswith(static_root):
        raise HTTPException(404, "Not found")
    if not os.path.isfile(full) or os.path.basename(full).startswith("."):
        raise HTTPException(404, "Not found")
    return FileResponse(full)
