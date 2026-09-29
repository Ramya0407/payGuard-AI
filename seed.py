from datetime import datetime, timedelta
from app import analyze, get_db

# (amount, receiver, method, new_receiver, urgent, asked_otp)
samples = [
    (500, "Ravi Kumar", "Card", 0, 0, 0),
    (2500, "Anita Sharma", "UPI", 0, 0, 0),
    (15000, "Sunil Traders", "UPI", 1, 0, 0),
    (75000, "Prize Refund Support", "UPI", 1, 1, 0),
    (1200, "Coffee House", "QR Code", 0, 0, 0),
    (30000, "KYC Customer Care", "Bank Transfer", 1, 1, 1),
    (8000, "Meena Stores", "Wallet", 1, 0, 0),
    (50000, "Lucky Winner Reward", "UPI", 1, 1, 1),
    (900, "Auto Driver", "UPI", 0, 0, 0),
    (20000, "Vikram Rao", "Bank Transfer", 1, 1, 0),
]

with get_db() as conn:
    for i, (amt, name, method, new, urg, otp) in enumerate(samples):
        score, cat, reasons = analyze(amt, name, method, new, urg, otp)
        when = (datetime.now() - timedelta(hours=len(samples) - i)).strftime("%Y-%m-%d %H:%M")
        conn.execute(
            "INSERT INTO transactions (created_at, amount, receiver_name, payment_method,"
            " risk_score, risk_category, reasons) VALUES (?,?,?,?,?,?,?)",
            (when, amt, name, method, score, cat, " | ".join(reasons)),
        )
print("Added", len(samples), "sample transactions")