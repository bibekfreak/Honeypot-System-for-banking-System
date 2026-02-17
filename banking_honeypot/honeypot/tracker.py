import json
import os
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime

from honeypot.logger import get_logger

logger = get_logger("Tracker")

class AttackTracker:
    def __init__(self, db_file: str, log_dir: str, rules: dict, config: dict):
        self.db_file = db_file
        self.log_dir = log_dir
        self.rules = rules
        self.config = config

        self._lock = threading.Lock()
        self.attempts = defaultdict(list)
        self.blocked_ips = set()
        self.port_scans = defaultdict(set)

        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(os.path.join(self.log_dir, "quarantine"), exist_ok=True)

        self.load_blocked_ips()

    def load_blocked_ips(self):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT ip FROM blocked_ips")
        self.blocked_ips = {row[0] for row in c.fetchall()}
        conn.close()
        logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs")

        # also dump json file for quick viewing
        self._dump_blocked_json()

    def _dump_blocked_json(self):
        path = os.path.join(self.log_dir, "blocked_ips.json")
        with self._lock:
            data = sorted(list(self.blocked_ips))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self.blocked_ips

    def record_attempt(self, ip: str, attack_type: str) -> bool:
        current_time = datetime.now().timestamp()
        rule = self.rules.get(attack_type, {})
        time_window = rule.get("time_window", self.config["TIME_WINDOW"])
        threshold = rule.get("threshold", self.config["BLOCK_THRESHOLD"])

        with self._lock:
            self.attempts[ip].append({"time": current_time, "type": attack_type})
            self.attempts[ip] = [
                a for a in self.attempts[ip] if current_time - a["time"] < time_window
            ]
            return len(self.attempts[ip]) >= threshold

    def block_ip(self, ip: str, reason: str, severity: str = "medium") -> bool:
        with self._lock:
            if ip in self.blocked_ips:
                return False
            self.blocked_ips.add(ip)
            attempts_count = len(self.attempts[ip])

        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute(
            """
            INSERT OR REPLACE INTO blocked_ips (ip, timestamp, reason, attempts)
            VALUES (?, ?, ?, ?)
            """,
            (ip, datetime.now().isoformat(), reason, attempts_count),
        )
        conn.commit()
        conn.close()

        self._dump_blocked_json()
        self.generate_alert(ip, reason, severity)

        logger.warning(f"BLOCKED IP: {ip} . Reason: {reason} . Severity: {severity}")
        return True

    def generate_alert(self, ip: str, reason: str, severity: str):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": ip,
            "reason": reason,
            "severity": severity,
            "action": "IP_BLOCKED",
        }

        alerts_file = os.path.join(self.log_dir, "alerts.jsonl")
        with open(alerts_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")

        logger.critical(f"ALERT [{severity.upper()}] . {reason} . Source: {ip}")

        


    
