import sqlite3
from pathlib import Path

def ensure_parent(path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)

def connect(db_file: str):
    ensure_parent(db_file)
    return sqlite3.connect(db_file, check_same_thread=False)

def init_database(db_file: str):
    conn = connect(db_file)
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            attack_type TEXT,
            service TEXT,
            port INTEGER,
            severity TEXT,
            details TEXT,
            blocked BOOLEAN
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            timestamp TEXT,
            reason TEXT,
            attempts INTEGER
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS malware_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            filename TEXT,
            hash TEXT,
            size INTEGER,
            quarantine_path TEXT
        )
        """
    )

    conn.commit()
    conn.close()
