import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
DB_PATH = "payguard.db"

SUSPICIOUS_WORDS = [
    "lottery", "prize", "winner", "reward", "cashback", "refund",
    "kyc", "customer care", "support", "helpline", "lucky", "gift",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "goo.gl", "shorturl.at"}
RISKY_TLDS = (".xyz", ".top", ".click", ".live", ".icu", ".tk", ".ml", ".cf", ".gq", ".work", ".shop")
LINK_WORDS = ["kyc", "verify", "update", "refund", "reward", "prize", "login", "secure", "otp", "claim", "lucky"]
BRANDS = {
    "paytm": "paytm.com", "phonepe": "phonepe.com", "gpay": "google.com",
    "googlepay": "google.com", "sbi": "sbi.co.in", "hdfc": "hdfcbank.com",
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
]

ADVICE = {
    "High": "Do NOT pay yet. Verify the receiver through a trusted channel, never share your OTP/PIN, and report scams at cybercrime.gov.in or call 1930.",
    "Medium": "Pause and double-check the receiver's identity (call them on a known number) before paying.",
    "Low": "Looks lower risk from the details given, but always confirm the receiver name before you pay.",
}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                amount REAL NOT NULL,
                receiver_name TEXT NOT NULL,
                payment_method TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                reasons TEXT NOT NULL,
                payment_link TEXT DEFAULT ''
            )"""
        )


def analyze(amount, name, method, new_receiver, urgent, asked_otp):
    """Transparent rule-based scoring. NOT machine learning."""
    score = 0
    reasons = []

    if amount >= 50000:
        score += 30
        reasons.append("Very large amount (₹50,000 or more).")
    elif amount >= 10000:
        score += 15
        reasons.append("Large amount (₹10,000 or more).")
    elif amount >= 5000:
        score += 8
        reasons.append("Moderately large amount.")

    if amount >= 5000 and amount % 1000 == 0:
        score += 5
        reasons.append("Large round-number amount, a common pattern in scams.")

    hits = [w for w in SUSPICIOUS_WORDS if w in name.lower()]
    if hits:
        score += 25
        reasons.append("Receiver name contains scam-related words: " + ", ".join(hits) + ".")

    if new_receiver:
        score += 15
        reasons.append("You have not paid this receiver before.")

    if urgent:
        score += 20
        reasons.append("You are being pressured to pay urgently.")

    if asked_otp:
        score += 40
        reasons.append("Someone asked for your OTP/PIN. Legitimate receivers never do.")

    if method.lower() in ("upi", "bank transfer") and amount >= 10000:
        score += 5
        reasons.append("Instant transfers are hard to reverse.")

    score = min(score, 100)
    if score >= 60:
        category = "High"
    elif score >= 30:
        category = "Medium"
    else:
        category = "Low"

    if not reasons:
        reasons.append("No suspicious indicators found in the details provided.")
    return score, category, reasons


def analyze_link(link):
    """Pattern-based link check. Does NOT visit the link or use a blacklist."""
    link = link.strip()
    if not link:
        return 0, []
    score, reasons = 0, []
    lower = link.lower()

    if lower.startswith("upi://"):
        payee = parse_qs(urlparse(link).query).get("pa", [""])[0].lower()
        if any(w in payee for w in SUSPICIOUS_WORDS):
            score += 25
            reasons.append("Link: UPI payee ID contains scam-related words.")
        reasons.append("Link: this is a UPI payment link. Check the payee name in your app before approving.")
        return score, reasons

    has_scheme = re.match(r"^[a-z][a-z0-9+.-]*://", lower) is not None
    parsed = urlparse(link if has_scheme else "https://" + link)
    host = (parsed.hostname or "").lower()
    if not host:
        return 10, ["Link: could not be read as a valid web address."]

    if has_scheme and parsed.scheme != "https":
        score += 15
        reasons.append("Link: does not use secure HTTPS.")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 30
        reasons.append("Link: uses a raw IP address instead of a website name.")
    if host in SHORTENERS:
        score += 20
        reasons.append("Link: shortened URL hides the real destination.")
    if "@" in link:
        score += 25
        reasons.append("Link: contains '@', a trick used to disguise the real site.")
    if "xn--" in host:
        score += 25
        reasons.append("Link: look-alike (punycode) domain name.")
    if host.endswith(RISKY_TLDS):
        score += 15
        reasons.append("Link: uses a domain ending often seen in scam sites.")
    if host.count(".") >= 4:
        score += 10
        reasons.append("Link: has many subdomains, which can hide the real domain.")
    hits = [w for w in LINK_WORDS if w in lower]
    if hits:
        score += 20
        reasons.append("Link: contains pressure/scam words: " + ", ".join(hits) + ".")
    for brand, official in BRANDS.items():
        if brand in host and not (host == official or host.endswith("." + official)):
            score += 25
            reasons.append(f"Link: mentions '{brand}' but is not the official {official} domain.")
            break

    if not reasons:
        reasons.append("Link: no suspicious patterns found. This does not prove the site is safe.")
    return score, reasons


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}

    try:
        amount = float(data.get("amount"))
    except (TypeError, ValueError):
        return jsonify({"error": "Amount must be a number."}), 400
    if amount <= 0 or amount > 10_000_000:
        return jsonify({"error": "Amount must be between 0 and 10,000,000."}), 400

    name = str(data.get("receiver_name", "")).strip()
    method = str(data.get("payment_method", "")).strip()
    link = str(data.get("payment_link", "")).strip()
    if not name or len(name) > 100:
        return jsonify({"error": "Receiver name is required (max 100 characters)."}), 400
    if not method or len(method) > 30:
        return jsonify({"error": "Payment method is required."}), 400
    if len(link) > 500:
        return jsonify({"error": "Link is too long (max 500 characters)."}), 400

    score, category, reasons = analyze(
        amount, name, method,
        bool(data.get("new_receiver")),
        bool(data.get("urgent")),
        bool(data.get("asked_otp")),
    )

    link_score, link_reasons = analyze_link(link)
    if link_reasons:
        reasons = [r for r in reasons if not r.startswith("No suspicious")] + link_reasons
        score = min(score + link_score, 100)
        category = "High" if score >= 60 else "Medium" if score >= 30 else "Low"

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO transactions (created_at, amount, receiver_name, payment_method,"
            " risk_score, risk_category, reasons, payment_link) VALUES (?,?,?,?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M"), amount, name, method,
             score, category, " | ".join(reasons), link),
        )
        tx_id = cur.lastrowid

    return jsonify({
        "id": tx_id,
        "risk_score": score,
        "risk_category": category,
        "reasons": reasons,
        "advice": ADVICE[category],
        "disclaimer": "Rule-based estimate for demonstration. It cannot guarantee a payment or link is safe or fraudulent.",
    })


@app.route("/api/history")
def api_history():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM transactions ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats")
def api_stats():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM transactions ORDER BY id DESC").fetchall()

    counts = {"Low": 0, "Medium": 0, "High": 0}
    flagged = 0
    ind = {label: 0 for label, _ in INDICATORS}
    for r in rows:
        counts[r["risk_category"]] += 1
        if r["risk_category"] == "High":
            flagged += r["amount"]
        text = r["reasons"].lower()
        for label, key in INDICATORS:
            if key in text:
                ind[label] += 1

    total = len(rows)
    avg = round(sum(r["risk_score"] for r in rows) / total, 1) if total else 0
    return jsonify({
        "total": total,
        "counts": counts,
        "average_score": avg,
        "flagged_amount": flagged,
        "timeline": [{"score": r["risk_score"], "category": r["risk_category"]}
                     for r in reversed(rows[:20])],
        "indicators": sorted(
            ({"label": k, "count": v} for k, v in ind.items() if v),
            key=lambda x: -x["count"]),
        "alerts": [dict(r) for r in rows if r["risk_category"] != "Low"][:5],
    })


init_db()

if __name__ == "__main__":
    app.run(debug=True)