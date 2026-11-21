"""
app/db.py -- Database layer for the BFT QR Fare Payment application.

VERSION: 1.1.0 (security hardening release)

CHANGELOG
---------
1.1.0 (refs: v1.0.0):
  * data/.secret (HMAC signing secret) is now created 0600 (owner
    read/write only) and pre-existing ≤0644 files are tightened on
    startup if the OS permits.

WHAT THIS MODULE DOES
---------------------
* Defines the SQLite schema for every table the app needs:
    accounts, routes, fare_products, tickets, transactions,
    boardings, stops, sessions.
* Ships the static BFT reference catalogs (routes, fare products,
  stops) that match Ben Franklin Transit's published 2025 fare
  structure.
* Owns the HMAC signing secret used to make QR payloads tamper-proof
  (data/.secret -- created once per installation, 64 hex chars).
* Seeds ~90 days of deterministic demo data so the analytics
  dashboard has something meaningful to chart on first run.

All timestamps are stored as ISO-8601 UTC strings (e.g.
"2025-04-01T12:34:56+00:00") so they sort correctly as text and are
portable across languages/tools.
"""

import hashlib
import hmac
import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "bft.db")
SECRET_PATH = os.path.join(DATA_DIR, ".secret")

os.makedirs(DATA_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
# NOTE ON SCHEMA EVOLUTION: if you change anything here, bump the version
# comment above and delete data/bft.db so init_db() re-creates it.
SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    wallet_cents  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routes (
    id    TEXT PRIMARY KEY,          -- e.g. "26", "BENTON"
    name  TEXT NOT NULL,
    color TEXT NOT NULL              -- hex color used on charts
);

CREATE TABLE IF NOT EXISTS fare_products (
    code              TEXT PRIMARY KEY,   -- SINGLE / DAY / RIDE10 / MONTH / YEAR
    name              TEXT NOT NULL,
    price_cents       INTEGER NOT NULL,
    reduced_price_cents INTEGER NOT NULL,
    validity_minutes  INTEGER NOT NULL,   -- how long the ticket stays valid
    rides             INTEGER,            -- NULL = unlimited rides while valid
    mobile_only       INTEGER NOT NULL DEFAULT 0,
    description       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id              TEXT PRIMARY KEY,         -- "tkt_<16 hex>"
    account_id      INTEGER NOT NULL REFERENCES accounts(id),
    product_code    TEXT NOT NULL REFERENCES fare_products(code),
    status          TEXT NOT NULL DEFAULT 'active',  -- active | used | expired
    rides_remaining INTEGER,                  -- NULL = unlimited (day pass)
    purchased_at    TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    first_used_at   TEXT,
    qr_payload      TEXT NOT NULL             -- "BFT1:<ticket_id>:<hmac16>"
);

CREATE TABLE IF NOT EXISTS transactions (
    id            TEXT PRIMARY KEY,      -- receipt number "BFT-YYYY-NNNNNN"
    account_id    INTEGER NOT NULL REFERENCES accounts(id),
    type          TEXT NOT NULL,         -- topup | purchase
    product_code  TEXT,                  -- NULL for topups
    amount_cents  INTEGER NOT NULL,
    method        TEXT NOT NULL,         -- wallet | card
    status        TEXT NOT NULL,         -- completed | failed
    description   TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS boardings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id   TEXT REFERENCES tickets(id),   -- NULL for rejected scans
    route_id    TEXT REFERENCES routes(id),    -- v1.1.0: NULL = unknown route
                                           -- reported by the scanner
    stop_id     TEXT REFERENCES stops(code),  -- NULL for rejected scans
    result      TEXT NOT NULL,                 -- accepted | rejected
    reason      TEXT NOT NULL,
    scanner_id  TEXT NOT NULL,
    rider_ref   TEXT NOT NULL,                 -- masked rider reference
    scanned_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stops (
    code TEXT PRIMARY KEY,   -- e.g. "TC-KEN"
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tickets_account ON tickets(account_id);
CREATE INDEX IF NOT EXISTS idx_txn_account     ON transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_boardings_time  ON boardings(scanned_at);
CREATE INDEX IF NOT EXISTS idx_txn_time        ON transactions(created_at);
"""


# ---------------------------------------------------------------------------
# Static BFT reference catalogs (Ben Franklin Transit, Tri-Cities WA)
# ---------------------------------------------------------------------------
# 15 routes covering Kennewick / Pasco / Richland / West Richland.
ROUTES = [
    ("26",    "Kennewick - Columbia Park",        "#00539b"),
    ("27",    "Kennewick - Clearwater",           "#00843d"),
    ("100",   "Tri-Cities Airport / Pasco",       "#ffb500"),
    ("110",   "Pasco - Downtown Loop",            "#c0392b"),
    ("120",   "Pasco - Road 68",                  "#6a3d9a"),
    ("150",   "Richland - Queensgate",            "#e07b00"),
    ("160",   "Richland - Horn Rapids",           "#00838f"),
    ("210",   "Kennewick - Richland Express",     "#00539b"),
    ("225",   "Pasco - Kennewick Express",        "#003a6e"),
    ("230",   "Richland - Pasco Express",         "#00843d"),
    ("240",   "West Richland - Badger Mountain",  "#7b1fa2"),
    ("250",   "Kennewick - Southridge",           "#ad1457"),
    ("270",   "Hanford 300 Area",                 "#5d4037"),
    ("500",   "Connell Commuter",                 "#455a64"),
    ("BENTON", "Benton City Commuter",            "#f57f17"),
]

# Fare products -- matches BFT's published 2025 fare structure.
# SINGLE $1.00 (reduced $0.50) | DAY PASS $3.00 (mobile only)
# 10-RIDE BOOK $8.00 | MONTHLY $10.00 | YEARLY $120.00 (mobile only)
FARE_PRODUCTS = [
    ("SINGLE",  "Single Ride",       100,   50,  120,    1,    0,
     "One ride on any BFT route. Valid 2 hours from first scan."),
    ("DAY",     "Day Pass",          300,  150, 1440,    None, 1,
     "Unlimited rides for 24 hours. Mobile app only."),
    ("RIDE10",  "10-Ride Book",      800,  400, 525600, 10,   0,
     "Ten rides, usable one at a time. Valid 12 months."),
    ("MONTH",   "Monthly Pass",     1000,  500, 43200,   None, 0,
     "Unlimited rides for 30 days."),
    ("YEAR",    "Yearly Pass",     12000, 6000, 525600,  None, 1,
     "Unlimited rides for 12 months. Mobile app only."),
]

# 8 major stops used by the scanner's "scan stop QR to buy" flow.
STOPS = [
    ("TC-KEN", "Tri-Cities Station - Kennewick"),
    ("TC-PAS", "Tri-Cities Station - Pasco"),
    ("TC-RIC", "Tri-Cities Station - Richland"),
    ("TC-QUE", "Queensgate Park & Ride"),
    ("STP-CCM", "Columbia Center Mall"),
    ("STP-CPP", "Columbia Park"),
    ("STP-VGS", "Village Green - Pasco"),
    ("STP-3RV", "Three Rivers Convention Center"),
]


# ---------------------------------------------------------------------------
# Signing secret (QR tamper-proofing)
# ---------------------------------------------------------------------------
def get_secret() -> bytes:
    """Return the per-installation HMAC signing secret.

    The secret is generated once (64 hex chars) and stored at
    data/.secret. It signs every QR payload as
    HMAC-SHA256(ticket_id)[:16 hex]. Losing it invalidates all
    previously issued QR codes; rotate it only when you also
    expire all outstanding tickets.
    """
    if os.path.exists(SECRET_PATH):
        # v1.1.0: tighten an over-permissive pre-existing file (no-op
        # where the OS/user does not allow it).
        try:
            os.chmod(SECRET_PATH, 0o600)
        except OSError:
            pass
        with open(SECRET_PATH, "r", encoding="utf-8") as f:
            return f.read().strip().encode()
    secret = os.urandom(32).hex().encode()
    # v1.1.0: create with 0600 -- the secret must never be world-readable.
    fd = os.open(SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(secret.decode())
    return secret


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------
def connect() -> sqlite3.Connection:
    """Open a SQLite connection with sane defaults.

    IMPORTANT: this returns the connection itself (not a generator).
    An earlier version yielded the connection, which made the object
    garbage-collected right after use and closed the DB mid-request
    (sqlite3.ProgrammingError: Cannot operate on a closed database).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(seed_demo: bool = True) -> None:
    """Create the schema and (optionally) seed demo data.

    Safe to call on every startup: CREATE TABLE IF NOT EXISTS means
    existing data is untouched.
    """
    conn = connect()
    conn.executescript(SCHEMA)
    # Static catalogs -- upsert so re-seeding refreshes names/prices.
    for rid, name, color in ROUTES:
        conn.execute(
            "INSERT OR REPLACE INTO routes (id, name, color) VALUES (?,?,?)",
            (rid, name, color),
        )
    for (code, name, price, reduced, validity, rides, mobile_only,
         description) in FARE_PRODUCTS:
        conn.execute(
            "INSERT OR REPLACE INTO fare_products "
            "(code, name, price_cents, reduced_price_cents, validity_minutes,"
            " rides, mobile_only, description) VALUES (?,?,?,?,?,?,?,?)",
            (code, name, price, reduced, validity, rides, mobile_only,
             description),
        )
    for code, name in STOPS:
        conn.execute(
            "INSERT OR REPLACE INTO stops (code, name) VALUES (?,?)",
            (code, name),
        )
    conn.commit()
    conn.close()

    if seed_demo and not _has_demo_data():
        _seed_demo()


def _has_demo_data() -> bool:
    """True once at least one demo transaction exists."""
    conn = connect()
    row = conn.execute("SELECT COUNT(*) AS n FROM transactions").fetchone()
    conn.close()
    return row["n"] > 0


# ---------------------------------------------------------------------------
# Demo data generator (deterministic, seed=42)
# ---------------------------------------------------------------------------
def _seed_demo() -> None:
    """Generate ~90 days of synthetic purchases and boardings.

    Product mix is weighted 55/25/8/10/2 (SINGLE/DAY/RIDE10/MONTH/YEAR)
    and purchases are weekday-weighted (more rides Mon-Fri). Each
    purchase produces 1+ boardings. Uses random.Random(42) so every
    fresh install gets identical analytics numbers.
    """
    rng = random.Random(42)
    now = datetime.now(timezone.utc)
    conn = connect()

    # 40 demo accounts with varying wallet balances.
    account_ids = []
    for i in range(40):
        email = f"rider{i+1}@example.com"
        created = now - timedelta(days=90, minutes=rng.randint(0, 10000))
        cur = conn.execute(
            "INSERT INTO accounts (email, wallet_cents, created_at) "
            "VALUES (?,?,?)",
            (email, rng.choice([0, 0, 500, 1000, 2000, 5000]), created.isoformat()),
        )
        account_ids.append((cur.lastrowid, email))

    products = {p[0]: p for p in FARE_PRODUCTS}
    weights = [55, 25, 8, 10, 2]
    product_codes = [p[0] for p in FARE_PRODUCTS]
    route_ids = [r[0] for r in ROUTES]
    stop_codes = [s[0] for s in STOPS]
    receipt_seq = 1

    # Walk backwards over 90 days.
    for day_offset in range(90, -1, -1):
        day = now - timedelta(days=day_offset)
        # Weekday weighting: 12-22 purchases on weekdays, 5-11 on weekends.
        is_weekend = day.weekday() >= 5
        n_purchases = rng.randint(5, 11) if is_weekend else rng.randint(12, 22)

        for _ in range(n_purchases):
            acct_id, email = rng.choice(account_ids)
            product_code = rng.choices(product_codes, weights=weights, k=1)[0]
            code, name, price, reduced, validity, rides, mobile_only, _desc = (
                products[product_code]
            )
            purchased_at = day.replace(
                hour=rng.randint(5, 21), minute=rng.randint(0, 59),
                second=rng.randint(0, 59), microsecond=0,
            )
            # ~20% of riders use reduced fare.
            amount = reduced if rng.random() < 0.2 else price
            method = "wallet" if rng.random() < 0.7 else "card"

            receipt = f"BFT-{purchased_at.year}-{receipt_seq:06d}"
            receipt_seq += 1
            conn.execute(
                "INSERT INTO transactions (id, account_id, type, product_code,"
                " amount_cents, method, status, description, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (receipt, acct_id, "purchase", product_code, amount, method,
                 "completed", f"{name}", purchased_at.isoformat()),
            )

            # Mint the ticket (same payload format as the live app).
            ticket_id = "tkt_" + os.urandom(8).hex()
            sig = hmac.new(get_secret(), ticket_id.encode(),
                           hashlib.sha256).hexdigest()[:16]
            expires_at = purchased_at + timedelta(minutes=validity)
            conn.execute(
                "INSERT INTO tickets (id, account_id, product_code, status,"
                " rides_remaining, purchased_at, expires_at, first_used_at,"
                " qr_payload) VALUES (?,?,?,?,?,?,?,?,?)",
                (ticket_id, acct_id, product_code, "used",
                 (rides - 1) if rides else None,
                 purchased_at.isoformat(), expires_at.isoformat(),
                 purchased_at.isoformat(), f"BFT1:{ticket_id}:{sig}"),
            )

            # 1+ boardings per purchase (day/month/year passes ride more).
            n_boardings = 1 if product_code == "SINGLE" else rng.randint(2, 6)
            for _ in range(n_boardings):
                boarded_at = purchased_at + timedelta(
                    minutes=rng.randint(1, min(90, validity)))
                if boarded_at > expires_at:
                    continue
                conn.execute(
                    "INSERT INTO boardings (ticket_id, route_id, stop_id,"
                    " result, reason, scanner_id, rider_ref, scanned_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (ticket_id, rng.choice(route_ids), rng.choice(stop_codes),
                     "accepted", "OK",
                     f"SCN-{rng.randint(100, 999)}",
                     "R-" + hashlib.sha1(email.encode()).hexdigest()[:8],
                     boarded_at.isoformat()),
                )

            # Occasional rejected scan (expired/reused tickets).
            if rng.random() < 0.05:
                conn.execute(
                    "INSERT INTO boardings (ticket_id, route_id, stop_id,"
                    " result, reason, scanner_id, rider_ref, scanned_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (None, rng.choice(route_ids), rng.choice(stop_codes),
                     "rejected", rng.choice(["Ticket is expired",
                                             "Ticket is used"]),
                     f"SCN-{rng.randint(100, 999)}", "R-UNKNOWN",
                     (purchased_at + timedelta(minutes=rng.randint(30, 200)))
                     .isoformat()),
                )

    conn.commit()
    conn.close()
