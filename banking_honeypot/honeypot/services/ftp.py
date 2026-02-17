import json
import socket
import sqlite3
from datetime import datetime
from threading import Thread

from honeypot.logger import get_logger

logger = get_logger("FTP")

class FTPHoneypot:
    def __init__(self, ip: str, port: int, db_file: str, tracker, log_dir: str):
        self.ip = ip
        self.port = port
        self.db_file = db_file
        self.tracker = tracker
        self.log_dir = log_dir
        self.banner = b"220 ProFTPD 1.3.5 Server ready.\r\n"

    def _log_attack_jsonl(self, event: dict):
        path = f"{self.log_dir}/attacks.jsonl"
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def log_attempt_db(self, source_ip: str, attack_type: str, details: dict):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO attacks (timestamp, source_ip, attack_type, service, port, severity, details, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(),
                source_ip,
                attack_type,
                "FTP",
                self.port,
                "medium",
                json.dumps(details),
                self.tracker.is_blocked(source_ip),
            ),
        )
        conn.commit()
        conn.close()

    def handle_client(self, client_socket: socket.socket, addr):
        source_ip = addr[0]
        if self.tracker.is_blocked(source_ip):
            client_socket.close()
            return

        client_socket.settimeout(10)

        username = "anonymous"

        try:
            client_socket.send(self.banner)

            while True:
                raw = client_socket.recv(1024)
                if not raw:
                    break

                data = raw.decode("utf-8", errors="ignore").strip()
                if not data:
                    break

                logger.info(f"FTP command from {source_ip} . {data}")

                parts = data.split(maxsplit=1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "USER":
                    username = arg or "anonymous"
                    client_socket.send(b"331 Password required\r\n")

                elif cmd == "PASS":
                    password = arg or ""

                    self.log_attempt_db(source_ip, "ftp_bruteforce", {"username": username, "password": password})
                    self._log_attack_jsonl({
                        "timestamp": datetime.now().isoformat(),
                        "source_ip": source_ip,
                        "attack_type": "ftp_bruteforce",
                        "service": "FTP",
                        "port": self.port,
                        "severity": "medium",
                        "details": {"username": username, "password": password},
                        "blocked": self.tracker.is_blocked(source_ip),
                    })

                    if self.tracker.record_attempt(source_ip, "ftp_bruteforce"):
                        self.tracker.block_ip(source_ip, "FTP Brute Force Attack", "medium")
                        break

                    client_socket.send(b"530 Login incorrect.\r\n")

                elif cmd in ("QUIT", "EXIT"):
                    client_socket.send(b"221 Goodbye.\r\n")
                    break

                else:
                    client_socket.send(b"502 Command not implemented.\r\n")

        except Exception as e:
            logger.error(f"FTP handler error . {e}")
        finally:
            client_socket.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.ip, self.port))
        server.listen(20)

        logger.info(f"FTP Honeypot listening on port {self.port}")

        while True:
            client, addr = server.accept()
            Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
