import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

DB_PATH = "payguard.db"


# =========================================================
# RISK / SCAM PATTERNS
# =========================================================

SUSPICIOUS_WORDS = [
    "lottery", "prize", "winner", "reward", "cashback", "refund",
    "kyc", "customer care", "support", "helpline", "lucky", "gift",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly",
    "rb.gy", "is.gd", "goo.gl", "shorturl.at"
}

RISKY_TLDS = (
    ".xyz", ".top", ".click", ".live", ".icu",
    ".tk", ".ml", ".cf", ".gq", ".work", ".shop"
)

LINK_WORDS = [
    "kyc", "verify", "update", "refund", "reward",
    "prize", "login", "secure", "otp", "claim", "lucky"
]

BRANDS = {
    "paytm": "paytm.com",
    "phonepe": "phonepe.com",
    "gpay": "google.com",
    "googlepay": "google.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
}


INDICATORS = [
    ("Large amount", "large amount"),
    ("Scam-word receiver name", "scam-related"),
    ("New receiver", "not paid this receiver"),
    ("Urgency pressure", "urgently"),
    ("OTP / PIN request", "otp/pin"),
    ("Round-number amount", "round-number"),
    ("Instant transfer", "instant transfers"),
    ("Suspicious link", "link:"),
    ("Suspicious SMS", "sms:"),
]


ADVICE = {
    "High": (
        "Do NOT pay yet. Verify the receiver through a trusted channel, "
        "never share your OTP/PIN, and report scams at cybercrime.gov.in "
        "or call 1930."
    ),

    "Medium": (
        "Pause and double-check the receiver's identity. "
        "Use a known phone number or trusted channel before paying."
    ),

    "Low": (
        "Looks lower risk from the details given, but always confirm "
        "the receiver and payment details before you pay."
    ),
}


# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:

        # Create table if it does not exist
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                amount REAL NOT NULL,
                receiver_name TEXT NOT NULL,
                payment_method TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                reasons TEXT NOT NULL,
                payment_link TEXT DEFAULT '',
                sms_message TEXT DEFAULT ''
            )
            """
        )

        # -------------------------------------------------
        # Database migration for existing payguard.db
        # -------------------------------------------------

        columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(transactions)"
            ).fetchall()
        ]

        # Add SMS column if old database doesn't have it
        if "sms_message" not in columns:
            conn.execute(
                """
                ALTER TABLE transactions
                ADD COLUMN sms_message TEXT DEFAULT ''
                """
            )


# =========================================================
# TRANSACTION RISK ANALYSIS
# =========================================================

def analyze(
    amount,
    name,
    method,
    new_receiver,
    urgent,
    asked_otp
):
    """
    Transparent rule-based transaction scoring.
    This is NOT machine learning.
    """

    score = 0
    reasons = []

    # -----------------------------------------------------
    # Amount
    # -----------------------------------------------------

    if amount >= 50000:
        score += 30
        reasons.append(
            "Very large amount (₹50,000 or more)."
        )

    elif amount >= 10000:
        score += 15
        reasons.append(
            "Large amount (₹10,000 or more)."
        )

    elif amount >= 5000:
        score += 8
        reasons.append(
            "Moderately large amount."
        )

    # -----------------------------------------------------
    # Round number
    # -----------------------------------------------------

    if amount >= 5000 and amount % 1000 == 0:
        score += 5
        reasons.append(
            "Large round-number amount, a common pattern in scams."
        )

    # -----------------------------------------------------
    # Receiver name
    # -----------------------------------------------------

    hits = [
        word
        for word in SUSPICIOUS_WORDS
        if word in name.lower()
    ]

    if hits:
        score += 25

        reasons.append(
            "Receiver name contains scam-related words: "
            + ", ".join(hits)
            + "."
        )

    # -----------------------------------------------------
    # New receiver
    # -----------------------------------------------------

    if new_receiver:
        score += 15

        reasons.append(
            "You have not paid this receiver before."
        )

    # -----------------------------------------------------
    # Urgency
    # -----------------------------------------------------

    if urgent:
        score += 20

        reasons.append(
            "You are being pressured to pay urgently."
        )

    # -----------------------------------------------------
    # OTP / PIN
    # -----------------------------------------------------

    if asked_otp:
        score += 40

        reasons.append(
            "Someone asked for your OTP/PIN. "
            "Legitimate receivers never do."
        )

    # -----------------------------------------------------
    # Payment method
    # -----------------------------------------------------

    if method.lower() in ("upi", "bank transfer") and amount >= 10000:
        score += 5

        reasons.append(
            "Instant transfers are hard to reverse."
        )

    return score, reasons


# =========================================================
# SMS / MESSAGE ANALYSIS
# =========================================================

def analyze_message(message):
    """
    Pattern-based SMS/message scam analysis.

    This function does not send the SMS anywhere
    and does not use machine learning.
    """

    message = message.strip()

    if not message:
        return 0, []

    score = 0
    reasons = []

    lower = message.lower()

    # -----------------------------------------------------
    # Urgency / pressure words
    # -----------------------------------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "last chance",
        "expire",
        "blocked",
        "suspended",
        "இப்போதே",
        "அவசரம்",
    ]

    urgency_hits = [
        word
        for word in urgency_words
        if word in lower
    ]

    if urgency_hits:
        score += 20

        reasons.append(
            "SMS: urgent or pressure language detected."
        )

    # -----------------------------------------------------
    # OTP / PIN / Password
    # -----------------------------------------------------

    security_words = [
        "otp",
        "pin",
        "password",
        "cvv",
        "verification code",
        "share otp",
        "send otp",
    ]

    security_hits = [
        word
        for word in security_words
        if word in lower
    ]

    if security_hits:
        score += 35

        reasons.append(
            "SMS: asks for OTP, PIN, password or "
            "other sensitive information."
        )

    # -----------------------------------------------------
    # Payment request
    # -----------------------------------------------------

    payment_words = [
        "pay",
        "payment",
        "transfer",
        "send money",
        "upi",
        "bank transfer",
        "₹",
        "rs.",
        "rupees",
    ]

    if any(word in lower for word in payment_words):
        score += 10

        reasons.append(
            "SMS: contains a payment or money-transfer request."
        )

    # -----------------------------------------------------
    # Scam-related words
    # -----------------------------------------------------

    scam_words = [
        "lottery",
        "winner",
        "prize",
        "reward",
        "cashback",
        "refund",
        "kyc",
        "verify",
        "claim",
        "gift",
        "customer care",
        "helpline",
    ]

    scam_hits = [
        word
        for word in scam_words
        if word in lower
    ]

    if scam_hits:
        score += 20

        reasons.append(
            "SMS: contains common scam-related words: "
            + ", ".join(scam_hits)
            + "."
        )

    # -----------------------------------------------------
    # Link inside SMS
    # -----------------------------------------------------

    if (
        "http://" in lower
        or "https://" in lower
        or "www." in lower
    ):
        score += 10

        reasons.append(
            "SMS: contains a web link. "
            "Verify the destination before opening it."
        )

    # -----------------------------------------------------
    # Threat / fear language
    # -----------------------------------------------------

    threat_words = [
        "account blocked",
        "account suspended",
        "legal action",
        "police",
        "arrest",
        "fine",
        "penalty",
    ]

    if any(word in lower for word in threat_words):
        score += 20

        reasons.append(
            "SMS: uses account-threat or fear-based language."
        )

    score = min(score, 100)

    if not reasons:
        reasons.append(
            "SMS: no obvious scam indicators found "
            "in the message."
        )

    return score, reasons


# =========================================================
# LINK ANALYSIS
# =========================================================

def analyze_link(link):
    """
    Pattern-based link check.

    The application does NOT visit the URL
    and does NOT use a live blacklist.
    """

    link = link.strip()

    if not link:
        return 0, []

    score = 0
    reasons = []

    lower = link.lower()

    # -----------------------------------------------------
    # UPI link
    # -----------------------------------------------------

    if lower.startswith("upi://"):

        payee = parse_qs(
            urlparse(link).query
        ).get("pa", [""])[0].lower()

        if any(
            word in payee
            for word in SUSPICIOUS_WORDS
        ):
            score += 25

            reasons.append(
                "Link: UPI payee ID contains "
                "scam-related words."
            )

        reasons.append(
            "Link: this is a UPI payment link. "
            "Check the payee name in your app before approving."
        )

        return score, reasons

    # -----------------------------------------------------
    # URL parsing
    # -----------------------------------------------------

    has_scheme = (
        re.match(
            r"^[a-z][a-z0-9+.-]*://",
            lower
        )
        is not None
    )

    parsed = urlparse(
        link if has_scheme else "https://" + link
    )

    host = (
        parsed.hostname or ""
    ).lower()

    if not host:
        return 10, [
            "Link: could not be read as a valid web address."
        ]

    # -----------------------------------------------------
    # HTTPS
    # -----------------------------------------------------

    if has_scheme and parsed.scheme != "https":
        score += 15

        reasons.append(
            "Link: does not use secure HTTPS."
        )

    # -----------------------------------------------------
    # Raw IP
    # -----------------------------------------------------

    if re.fullmatch(
        r"\d{1,3}(\.\d{1,3}){3}",
        host
    ):
        score += 30

        reasons.append(
            "Link: uses a raw IP address instead "
            "of a website name."
        )

    # -----------------------------------------------------
    # URL shortener
    # -----------------------------------------------------

    if host in SHORTENERS:
        score += 20

        reasons.append(
            "Link: shortened URL hides the real destination."
        )

    # -----------------------------------------------------
    # @ symbol
    # -----------------------------------------------------

    if "@" in link:
        score += 25

        reasons.append(
            "Link: contains '@', a trick used "
            "to disguise the real site."
        )

    # -----------------------------------------------------
    # Punycode
    # -----------------------------------------------------

    if "xn--" in host:
        score += 25

        reasons.append(
            "Link: look-alike (punycode) domain name."
        )

    # -----------------------------------------------------
    # Risky TLD
    # -----------------------------------------------------

    if host.endswith(RISKY_TLDS):
        score += 15

        reasons.append(
            "Link: uses a domain ending often seen "
            "in scam sites."
        )

    # -----------------------------------------------------
    # Many subdomains
    # -----------------------------------------------------

    if host.count(".") >= 4:
        score += 10

        reasons.append(
            "Link: has many subdomains, which can "
            "hide the real domain."
        )

    # -----------------------------------------------------
    # Scam words inside URL
    # -----------------------------------------------------

    hits = [
        word
        for word in LINK_WORDS
        if word in lower
    ]

    if hits:
        score += 20

        reasons.append(
            "Link: contains pressure/scam words: "
            + ", ".join(hits)
            + "."
        )

    # -----------------------------------------------------
    # Brand impersonation
    # -----------------------------------------------------

    for brand, official in BRANDS.items():

        if (
            brand in host
            and not (
                host == official
                or host.endswith("." + official)
            )
        ):
            score += 25

            reasons.append(
                f"Link: mentions '{brand}' but is not "
                f"the official {official} domain."
            )

            break

    # -----------------------------------------------------
    # No suspicious pattern
    # -----------------------------------------------------

    if not reasons:
        reasons.append(
            "Link: no suspicious patterns found. "
            "This does not prove the site is safe."
        )

    return score, reasons


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def index():
    return render_template("index.html")


# =========================================================
# ANALYZE API
# =========================================================

@app.route("/api/analyze", methods=["POST"])
def api_analyze():

    data = request.get_json(silent=True) or {}

    # -----------------------------------------------------
    # Amount
    # -----------------------------------------------------

    try:
        amount = float(data.get("amount"))

    except (TypeError, ValueError):
        return jsonify({
            "error": "Amount must be a number."
        }), 400

    if amount <= 0 or amount > 10_000_000:
        return jsonify({
            "error": "Amount must be between 0 and 10,000,000."
        }), 400

    # -----------------------------------------------------
    # Basic fields
    # -----------------------------------------------------

    name = str(
        data.get("receiver_name", "")
    ).strip()

    method = str(
        data.get("payment_method", "")
    ).strip()

    link = str(
        data.get("payment_link", "")
    ).strip()

    sms_message = str(
        data.get("sms_message", "")
    ).strip()

    # -----------------------------------------------------
    # Validation
    # -----------------------------------------------------

    if not name or len(name) > 100:
        return jsonify({
            "error": "Receiver name is required (max 100 characters)."
        }), 400

    if not method or len(method) > 30:
        return jsonify({
            "error": "Payment method is required."
        }), 400

    if len(link) > 500:
        return jsonify({
            "error": "Link is too long (max 500 characters)."
        }), 400

    if len(sms_message) > 3000:
        return jsonify({
            "error": "SMS message is too long (max 3000 characters)."
        }), 400

    # =====================================================
    # 1. TRANSACTION ANALYSIS
    # =====================================================

    score, reasons = analyze(
        amount,
        name,
        method,
        bool(data.get("new_receiver")),
        bool(data.get("urgent")),
        bool(data.get("asked_otp")),
    )

    # =====================================================
    # 2. SMS ANALYSIS
    # =====================================================

    sms_score, sms_reasons = analyze_message(
        sms_message
    )

    if sms_reasons:

        reasons = [
            r
            for r in reasons
            if not r.startswith("No suspicious")
        ]

        reasons.extend(sms_reasons)

        score = min(
            score + sms_score,
            100
        )

    # =====================================================
    # 3. LINK ANALYSIS
    # =====================================================

    link_score, link_reasons = analyze_link(link)

    if link_reasons:

        reasons = [
            r
            for r in reasons
            if not r.startswith("No suspicious")
        ]

        reasons.extend(link_reasons)

        score = min(
            score + link_score,
            100
        )

    # =====================================================
    # FINAL RISK CATEGORY
    # =====================================================

    score = min(score, 100)

    if score >= 60:
        category = "High"

    elif score >= 30:
        category = "Medium"

    else:
        category = "Low"

    # =====================================================
    # FALLBACK REASON
    # =====================================================

    if not reasons:

        reasons.append(
            "No suspicious indicators found "
            "in the details provided."
        )

    # =====================================================
    # SAVE TO DATABASE
    # =====================================================

    with get_db() as conn:

        cur = conn.execute(
            """
            INSERT INTO transactions (
                created_at,
                amount,
                receiver_name,
                payment_method,
                risk_score,
                risk_category,
                reasons,
                payment_link,
                sms_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M"
                ),
                amount,
                name,
                method,
                score,
                category,
                " | ".join(reasons),
                link,
                sms_message,
            ),
        )

        tx_id = cur.lastrowid

    # =====================================================
    # RESPONSE
    # =====================================================

    return jsonify({
        "id": tx_id,
        "risk_score": score,
        "risk_category": category,
        "reasons": reasons,
        "advice": ADVICE[category],
        "disclaimer": (
            "Rule-based estimate for demonstration. "
            "It cannot guarantee a payment, SMS, QR code "
            "or link is safe or fraudulent."
        ),
    })


# =========================================================
# HISTORY API
# =========================================================

@app.route("/api/history")
def api_history():

    with get_db() as conn:

        rows = conn.execute(
            """
            SELECT *
            FROM transactions
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

    return jsonify([
        dict(row)
        for row in rows
    ])


# =========================================================
# DASHBOARD STATS API
# =========================================================

@app.route("/api/stats")
def api_stats():

    with get_db() as conn:

        rows = conn.execute(
            """
            SELECT *
            FROM transactions
            ORDER BY id DESC
            """
        ).fetchall()

    counts = {
        "Low": 0,
        "Medium": 0,
        "High": 0
    }

    flagged = 0

    indicators = {
        label: 0
        for label, _ in INDICATORS
    }

    # -----------------------------------------------------
    # Process transactions
    # -----------------------------------------------------

    for row in rows:

        category = row["risk_category"]

        if category in counts:
            counts[category] += 1

        if category == "High":
            flagged += row["amount"]

        text = (
            row["reasons"] or ""
        ).lower()

        for label, key in INDICATORS:

            if key in text:
                indicators[label] += 1

    # -----------------------------------------------------
    # Average score
    # -----------------------------------------------------

    total = len(rows)

    if total:

        avg = round(
            sum(
                row["risk_score"]
                for row in rows
            ) / total,
            1
        )

    else:
        avg = 0

    # -----------------------------------------------------
    # Response
    # -----------------------------------------------------

    return jsonify({

        "total": total,

        "counts": counts,

        "average_score": avg,

        "flagged_amount": flagged,

        "timeline": [
            {
                "score": row["risk_score"],
                "category": row["risk_category"]
            }
            for row in reversed(
                rows[:20]
            )
        ],

        "indicators": sorted(
            (
                {
                    "label": label,
                    "count": count
                }
                for label, count
                in indicators.items()
                if count
            ),
            key=lambda item: -item["count"]
        ),

        "alerts": [
            dict(row)
            for row in rows
            if row["risk_category"] != "Low"
        ][:5],
    })


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

init_db()


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)