import os
import threading
import time
from pathlib import Path

import yaml

from honeypot.logger import setup_logging, get_logger
from honeypot.database import init_database
from honeypot.rules import load_rules
from honeypot.tracker import AttackTracker
from honeypot.report import ReportGenerator
from honeypot.services.ssh import SSHHoneypot
from honeypot.services.ftp import FTPHoneypot
from honeypot.services.http import HTTPHoneypot

def load_config():
    # defaults
    cfg = {
        "HONEYPOT_IP": "0.0.0.0",
        "SSH_PORT": 2222,
        "FTP_PORT": 2121,
        "HTTP_PORT": 8080,
        "LOG_DIR": "logs",
        "DATA_DIR": "data",
        "DB_FILE": "data/honeypot.db",
        "BLOCK_THRESHOLD": 5,
        "TIME_WINDOW": 60,
        "AUTO_BLOCK": True,
    }

    p = Path("config/config.yaml")
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            file_cfg = yaml.safe_load(f) or {}
        cfg.update(file_cfg)

    os.makedirs(cfg["LOG_DIR"], exist_ok=True)
    os.makedirs(cfg["DATA_DIR"], exist_ok=True)
    return cfg

def run():
    cfg = load_config()
    setup_logging(cfg["LOG_DIR"])
    logger = get_logger("Main")

    print(
        """
╔═══════════════════════════════════════════════════╗
║ Banking Honeypot Security System v1.0             ║
║ Rule-Based Threat Detection & Monitoring          ║
╚═══════════════════════════════════════════════════╝
"""
    )

    init_database(cfg["DB_FILE"])
    rules = load_rules("config/rules.yaml")

    tracker = AttackTracker(
        db_file=cfg["DB_FILE"],
        log_dir=cfg["LOG_DIR"],
        rules=rules,
        config=cfg,
    )

    ssh = SSHHoneypot(cfg["HONEYPOT_IP"], cfg["SSH_PORT"], cfg["DB_FILE"], tracker, cfg["LOG_DIR"])
    ftp = FTPHoneypot(cfg["HONEYPOT_IP"], cfg["FTP_PORT"], cfg["DB_FILE"], tracker, cfg["LOG_DIR"])
    http = HTTPHoneypot(cfg["HONEYPOT_IP"], cfg["HTTP_PORT"], cfg["DB_FILE"], tracker, cfg["LOG_DIR"], rules)

    threading.Thread(target=ssh.start, daemon=True).start()
    threading.Thread(target=ftp.start, daemon=True).start()
    threading.Thread(target=http.start, daemon=True).start()

    logger.info("All honeypot services started")
    print("\n[+] Honeypot system active")
    print(f"[+] SSH listening on port {cfg['SSH_PORT']}")
    print(f"[+] FTP listening on port {cfg['FTP_PORT']}")
    print(f"[+] HTTP listening on port {cfg['HTTP_PORT']}")
    print("\n[*] Press Ctrl+C to stop and generate report\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[!] Stopping honeypot system...")
        ReportGenerator.generate_summary(cfg["DB_FILE"], cfg["LOG_DIR"])
        print("[+] Report generated. Goodbye!")
