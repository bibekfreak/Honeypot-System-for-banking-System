import sqlite3
from pathlib import Path
from flask import Flask, render_template, jsonify

BASE_DIR = Path(__file__).resolve().parent.parent
DB_FILE = str(BASE_DIR / "data" / "honeypot.db")

app = Flask(__name__)

def q(sql, params=()):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/summary")
def api_summary():
    total_attacks = q("SELECT COUNT(*) AS c FROM attacks")[0]["c"]
    unique_ips = q("SELECT COUNT(DISTINCT source_ip) AS c FROM attacks")[0]["c"]
    blocked_ips = q("SELECT COUNT(*) AS c FROM blocked_ips")[0]["c"]
    return jsonify({
        "total_attacks": total_attacks,
        "unique_ips": unique_ips,
        "blocked_ips": blocked_ips
    })

@app.route("/api/attack_types")
def api_attack_types():
    return jsonify(q("""
        SELECT attack_type, COUNT(*) AS c
        FROM attacks
        GROUP BY attack_type
        ORDER BY c DESC
        LIMIT 10
    """))

@app.route("/api/top_attackers")
def api_top_attackers():
    return jsonify(q("""
        SELECT source_ip, COUNT(*) AS c
        FROM attacks
        GROUP BY source_ip
        ORDER BY c DESC
        LIMIT 10
    """))

@app.route("/api/recent_attacks")
def api_recent_attacks():
    return jsonify(q("""
        SELECT timestamp, source_ip, attack_type, service, port, severity, blocked, details
        FROM attacks
        ORDER BY id DESC
        LIMIT 25
    """))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
