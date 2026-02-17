import json
import os
import socket
import sqlite3
from datetime import datetime
from threading import Thread

from honeypot.logger import get_logger

logger = get_logger("SSH")


class SSHHoneypot:
    def __init__(self, ip: str, port: int, db_file: str, tracker, log_dir: str):
        self.ip = ip
        self.port = port
        self.db_file = db_file
        self.tracker = tracker
        self.log_dir = log_dir
        self.banner = b"SSH-2.0-OpenSSH_7.4\r\n"

    def _log_attack_jsonl(self, event: dict):
        path = os.path.join(self.log_dir, "attacks.jsonl")
        os.makedirs(self.log_dir, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def log_attempt_db(self, source_ip: str, username: str, password: str, blocked: bool):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        details = json.dumps({"username": username, "password": password})
        c.execute(
            """
            INSERT INTO attacks (timestamp, source_ip, attack_type, service, port, severity, details, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(),
                source_ip,
                "ssh_bruteforce",
                "SSH",
                self.port,
                "high",
                details,
                blocked,
            ),
        )
        conn.commit()
        conn.close()

    def _recv_text(self, sock: socket.socket, max_bytes: int = 1024) -> str:
        """
        Safely receive some bytes and decode to text.
        Returns empty string on timeout or decode issues.
        """
        try:
            data = sock.recv(max_bytes)
            if not data:
                return ""
            return data.decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            return ""
        except Exception:
            return ""

    def handle_client(self, client_socket: socket.socket, addr):
        source_ip = addr[0]

        if self.tracker.is_blocked(source_ip):
            try:
                client_socket.sendall(b"Access denied\r\n")
            except Exception:
                pass
            finally:
                client_socket.close()
            return

        # Default timeout for the session
        client_socket.settimeout(5)

        try:
            # Send SSH banner
            client_socket.sendall(self.banner)

            # Read a client banner if present, but don't block on it
            old_timeout = client_socket.gettimeout()
            client_socket.settimeout(1.0)
            try:
                client_banner = client_socket.recv(1024)
            except socket.timeout:
                client_banner = b""
            except Exception:
                client_banner = b""
            finally:
                client_socket.settimeout(old_timeout)

            logger.info(f"SSH connection from {source_ip} . Banner: {client_banner[:60]}")

            attempts = 0
            while attempts < 3:
                # Prompt username/password (fake)
                client_socket.sendall(b"login: ")
                username = self._recv_text(client_socket)

                client_socket.sendall(b"password: ")
                password = self._recv_text(client_socket)

                # If nothing came back, treat it as disconnect and stop
                if not username and not password:
                    break

                attempts += 1

                # Threshold logic first
                threshold_hit = self.tracker.record_attempt(source_ip, "ssh_bruteforce")

                # Apply block if threshold hit
                if threshold_hit:
                    self.tracker.block_ip(source_ip, "SSH Brute Force Attack", "high")

                blocked_now = self.tracker.is_blocked(source_ip)

                # Log into DB (this is what your dashboard reads)
                self.log_attempt_db(source_ip, username, password, blocked_now)

                # Optional jsonl log (not required for your dashboard, but useful)
                self._log_attack_jsonl(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "source_ip": source_ip,
                        "attack_type": "ssh_bruteforce",
                        "service": "SSH",
                        "port": self.port,
                        "severity": "high",
                        "details": {"username": username},
                        "blocked": blocked_now,
                        "threshold_hit": threshold_hit,
                    }
                )

                # Respond
                client_socket.sendall(b"Access denied\r\n")

                if blocked_now:
                    break

        except Exception as e:
            logger.error(f"SSH handler error . {e}")
        finally:
            client_socket.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.ip, self.port))
        server.listen(20)

        logger.info(f"SSH Honeypot listening on port {self.port}")

        while True:
            client, addr = server.accept()
            Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
