import os
import sqlite3
from datetime import datetime

from honeypot.logger import get_logger

logger = get_logger("Report")

class ReportGenerator:
    @staticmethod
    def generate_summary(db_file: str, log_dir: str):
        conn = sqlite3.connect(db_file)
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM attacks")
        total_attacks = c.fetchone()[0]

        c.execute("SELECT COUNT(DISTINCT source_ip) FROM attacks")
        unique_ips = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM blocked_ips")
        blocked_count = c.fetchone()[0]

        c.execute(
            """
            SELECT attack_type, COUNT(*) as count
            FROM attacks
            GROUP BY attack_type
            ORDER BY count DESC
            """
        )
        attack_types = c.fetchall()

        c.execute(
            """
            SELECT source_ip, COUNT(*) as count
            FROM attacks
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
            """
        )
        top_attackers = c.fetchall()

        conn.close()

        report = f"""
========================================
HONEYPOT SECURITY REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
========================================

SUMMARY:
- Total Attack Attempts: {total_attacks}
- Unique Attacker IPs: {unique_ips}
- Blocked IP Addresses: {blocked_count}

ATTACK TYPES:
"""
        for attack_type, count in attack_types:
            report += f"- {attack_type}: {count}\n"

        report += "\nTOP ATTACKERS:\n"
        for ip, count in top_attackers:
            report += f"- {ip}: {count} attempts\n"

        report += "\n========================================\n"

        os.makedirs(log_dir, exist_ok=True)
        report_file = os.path.join(log_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)

        logger.info(f"Report generated . {report_file}")
        print(report)
