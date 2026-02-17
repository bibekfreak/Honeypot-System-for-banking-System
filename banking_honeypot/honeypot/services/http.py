import hashlib
import json
import os
import socket
import sqlite3
import traceback
from datetime import datetime
from threading import Thread
from urllib.parse import unquote_plus, urlparse, parse_qs

from honeypot.logger import get_logger
from honeypot.rules import match_any

logger = get_logger("HTTP")


class HTTPHoneypot:
    def __init__(self, ip: str, port: int, db_file: str, tracker, log_dir: str, rules: dict):
        self.ip = ip
        self.port = port
        self.db_file = db_file
        self.tracker = tracker
        self.log_dir = log_dir
        self.rules = rules

        # Avoid blocking your own localhost while testing in browser
        self.safe_ips = {"127.0.0.1", "::1"}

    # ----------------------------
    # Logging
    # ----------------------------
    def _log_attack_jsonl(self, event: dict):
        path = os.path.join(self.log_dir, "attacks.jsonl")
        os.makedirs(self.log_dir, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def log_attack_db(self, source_ip: str, attack_type: str, details: str, severity: str):
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
                "HTTP",
                self.port,
                severity,
                details,
                self.tracker.is_blocked(source_ip),
            ),
        )
        conn.commit()
        conn.close()

    # ----------------------------
    # HTTP helpers (IMPORTANT)
    # ----------------------------
    def _http_response(self, status_code: int, reason: str, content_type: str, body: str, extra_headers=None) -> bytes:
        extra_headers = extra_headers or {}
        body_bytes = body.encode("utf-8", errors="ignore")

        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body_bytes)),
            "Connection": "close",
        }
        headers.update(extra_headers)

        header_blob = f"HTTP/1.1 {status_code} {reason}\r\n" + "".join(
            f"{k}: {v}\r\n" for k, v in headers.items()
        ) + "\r\n"

        return header_blob.encode("utf-8", errors="ignore") + body_bytes

    def _redirect(self, location: str, extra_headers=None) -> bytes:
        extra_headers = extra_headers or {}
        extra_headers["Location"] = location
        return self._http_response(302, "Found", "text/plain; charset=utf-8", "Redirecting...", extra_headers)

    def _parse_headers(self, request: str) -> dict:
        headers = {}
        parts = request.split("\r\n\r\n", 1)[0].split("\r\n")
        for line in parts[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers

    def _parse_request_line(self, request_line: str):
        # "GET /path?x=1 HTTP/1.1"
        bits = request_line.split()
        if len(bits) < 2:
            return "", "/", "HTTP/1.1"
        method = bits[0].upper()
        target = bits[1]
        version = bits[2] if len(bits) > 2 else "HTTP/1.1"
        return method, target, version

    def _get_body(self, request: str) -> str:
        return request.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in request else ""

    def _is_authed(self, headers: dict) -> bool:
        cookie = headers.get("cookie", "")
        # Simple cookie gate for demo purposes
        return "hp_auth=1" in cookie

    # ----------------------------
    # UI pages
    # ----------------------------
    def login_page(self) -> bytes:
        body = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NorthBridge Bank . Admin Portal</title>
  <style>
    :root{--bg1:#0b1220;--bg2:#0f1c35;--card:#0f172a;--card2:#111c33;--text:#e7eefc;--muted:#9fb0d0;--line:rgba(255,255,255,.10);--accent:#3b82f6;--accent2:#60a5fa;}
    *{box-sizing:border-box;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;}
    body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(1200px 800px at 20% 10%, #1b2a52 0%, transparent 55%),radial-gradient(900px 700px at 90% 30%, #133a63 0%, transparent 50%),linear-gradient(135deg,var(--bg1),var(--bg2));color:var(--text);padding:28px;}
    .shell{width:min(980px,92vw);display:grid;grid-template-columns:1.2fr 1fr;gap:18px;}
    @media (max-width: 860px){.shell{grid-template-columns:1fr;}}
    .hero{padding:28px;border:1px solid var(--line);border-radius:18px;background:linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));box-shadow:0 20px 60px rgba(0,0,0,.35);position:relative;overflow:hidden;}
    .hero:before{content:"";position:absolute;inset:-80px;opacity:.18;background:conic-gradient(from 220deg, transparent, var(--accent), transparent, var(--accent2), transparent);filter:blur(10px);}
    .hero-inner{position:relative;}
    .brand{display:flex;align-items:center;gap:12px;margin-bottom:18px;}
    .logo{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 10px 30px rgba(59,130,246,.35);}
    .logo svg{width:26px;height:26px;fill:white;opacity:.95;}
    .brand h1{font-size:18px;margin:0;letter-spacing:.4px;}
    .brand p{margin:2px 0 0 0;color:var(--muted);font-size:12px;}
    .hero h2{margin:14px 0 8px 0;font-size:28px;line-height:1.15;}
    .hero .sub{margin:0;color:var(--muted);max-width:52ch;font-size:14px;line-height:1.5;}
    .badges{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px;}
    .badge{border:1px solid var(--line);color:var(--muted);padding:8px 10px;border-radius:999px;font-size:12px;background:rgba(255,255,255,.02);}
    .card{padding:26px;border:1px solid var(--line);border-radius:18px;background:linear-gradient(180deg,var(--card),var(--card2));box-shadow:0 20px 60px rgba(0,0,0,.35);}
    .card h3{margin:0 0 6px 0;font-size:16px;letter-spacing:.3px;}
    .card .hint{margin:0 0 18px 0;color:var(--muted);font-size:12px;}
    label{display:block;margin:12px 0 6px 0;color:#cfe0ff;font-size:12px;}
    .field{width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.03);color:var(--text);outline:none;}
    .field:focus{border-color:rgba(96,165,250,.7);box-shadow:0 0 0 4px rgba(59,130,246,.18)}
    .row{display:flex;justify-content:space-between;align-items:center;margin-top:10px;}
    .chk{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;}
    .chk input{width:14px;height:14px;}
    .link{color:var(--accent2);text-decoration:none;font-size:12px;}
    .link:hover{text-decoration:underline;}
    .btn{width:100%;margin-top:16px;padding:12px 14px;border-radius:12px;border:0;background:linear-gradient(135deg,var(--accent),var(--accent2));color:white;font-weight:700;letter-spacing:.3px;cursor:pointer;}
    .btn:hover{filter:brightness(1.05)}
    .foot{margin-top:14px;color:var(--muted);font-size:11px;line-height:1.45;}
    .foot strong{color:#cfe0ff;font-weight:600;}
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div class="hero-inner">
        <div class="brand">
          <div class="logo" aria-hidden="true">
            <svg viewBox="0 0 24 24"><path d="M12 2 3 7v2h18V7L12 2zm8 9H4v9c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2v-9zM7 19H6v-6h1v6zm4 0H9v-6h2v6zm4 0h-2v-6h2v6zm3 0h-1v-6h1v6z"/></svg>
          </div>
          <div>
            <h1>NorthBridge Bank</h1>
            <p>Administration Console</p>
          </div>
        </div>

        <h2>Secure access for authorized staff</h2>
        <p class="sub">Sign in to manage users, review security events, and administer online banking systems. All activity is monitored for compliance and fraud prevention.</p>

        <div class="badges">
          <span class="badge">TLS Protected</span>
          <span class="badge">Role Based Controls</span>
          <span class="badge">Audit Logging</span>
          <span class="badge">Fraud Monitoring</span>
        </div>
      </div>
    </section>

    <section class="card">
      <h3>Sign in</h3>
      <p class="hint">Use your corporate credentials. MFA may be required.</p>

      <form action="/login" method="POST" autocomplete="off">
        <label for="username">Username</label>
        <input class="field" id="username" name="username" type="text" placeholder="e.g. nlimbu" required />

        <label for="password">Password</label>
        <input class="field" id="password" name="password" type="password" placeholder="••••••••" required />

        <div class="row">
          <label class="chk"><input type="checkbox" name="remember" />Remember device</label>
          <a class="link" href="/reset">Forgot password?</a>
        </div>

        <button class="btn" type="submit">Sign in</button>
      </form>

      <div class="foot">
        <strong>Notice.</strong> This system is restricted to authorized personnel only. Unauthorized access attempts are logged and may be investigated.
      </div>
    </section>
  </div>
</body>
</html>
        """.strip()

        return self._http_response(200, "OK", "text/html; charset=utf-8", body)

    def admin_dashboard(self, source_ip: str) -> bytes:
        body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NorthBridge Bank . Admin Dashboard</title>
  <style>
    :root{{--bg:#0b1220;--card:#0f172a;--text:#e7eefc;--muted:#9fb0d0;--line:rgba(255,255,255,.10);--accent:#60a5fa;}}
    *{{box-sizing:border-box;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;}}
    body{{margin:0;background:linear-gradient(135deg,#0b1220,#0f1c35);color:var(--text);}}
    .top{{display:flex;align-items:center;justify-content:space-between;padding:18px 22px;border-bottom:1px solid var(--line);}}
    .brand{{display:flex;gap:10px;align-items:center;}}
    .dot{{width:10px;height:10px;border-radius:999px;background:var(--accent);box-shadow:0 0 0 6px rgba(96,165,250,.14);}}
    .brand h1{{margin:0;font-size:14px;letter-spacing:.4px;}}
    .brand p{{margin:2px 0 0 0;font-size:12px;color:var(--muted);}}
    .btn{{color:var(--text);text-decoration:none;border:1px solid var(--line);padding:8px 10px;border-radius:10px;background:rgba(255,255,255,.03);font-size:12px;}}
    .wrap{{max-width:1100px;margin:0 auto;padding:22px;display:grid;grid-template-columns:260px 1fr;gap:16px;}}
    @media (max-width: 900px){{.wrap{{grid-template-columns:1fr;}}}}
    .nav{{border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.02);padding:14px;}}
    .nav a{{display:block;padding:10px 10px;border-radius:12px;color:var(--text);text-decoration:none;font-size:13px;}}
    .nav a:hover{{background:rgba(255,255,255,.04);}}
    .main{{display:grid;gap:16px;}}
    .grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;}}
    @media (max-width: 900px){{.grid{{grid-template-columns:1fr;}}}}
    .card{{border:1px solid var(--line);border-radius:16px;background:linear-gradient(180deg,#0f172a,#111c33);padding:14px;}}
    .card h2{{margin:0 0 8px 0;font-size:13px;letter-spacing:.3px;}}
    .kpi{{font-size:22px;font-weight:800;margin-top:6px;}}
    .muted{{color:var(--muted);font-size:12px;line-height:1.5;}}
    table{{width:100%;border-collapse:collapse;margin-top:10px;}}
    th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--line);font-size:12px;}}
    th{{color:#cfe0ff;font-weight:600;}}
    .pill{{display:inline-block;padding:4px 8px;border-radius:999px;background:rgba(96,165,250,.14);border:1px solid rgba(96,165,250,.28);font-size:11px;}}
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="dot"></div>
      <div>
        <h1>NorthBridge Bank . Admin Dashboard</h1>
        <p>Secure session . Activity monitored</p>
      </div>
    </div>
    <div style="display:flex;gap:10px;align-items:center">
      <span class="muted">Session IP: {source_ip}</span>
      <a class="btn" href="/logout">Log out</a>
    </div>
  </div>

  <div class="wrap">
    <nav class="nav">
      <a href="/admin/dashboard"><span class="pill">Dashboard</span></a>
      <a href="/admin/users">User Management</a>
      <a href="/admin/audit">Audit Logs</a>
      <a href="/admin/alerts">Security Alerts</a>
      <a href="/admin/settings">System Settings</a>
    </nav>

    <main class="main">
      <div class="grid">
        <div class="card">
          <h2>Authentication Events</h2>
          <div class="kpi">1,284</div>
          <div class="muted">Last 24 hours . Includes successful and failed sign-ins</div>
        </div>
        <div class="card">
          <h2>Flagged Sessions</h2>
          <div class="kpi">17</div>
          <div class="muted">Anomalous activity detected . Review security alerts</div>
        </div>
        <div class="card">
          <h2>Admin Actions</h2>
          <div class="kpi">402</div>
          <div class="muted">Configuration changes and approvals . Audit trail enabled</div>
        </div>
      </div>

      <div class="card">
        <h2>Recent Activity</h2>
        <div class="muted">Sample admin events . (Fake data for honeypot)</div>
        <table>
          <thead>
            <tr><th>Time</th><th>Actor</th><th>Action</th><th>Status</th></tr>
          </thead>
          <tbody>
            <tr><td>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</td><td>admin</td><td>Viewed user list</td><td><span class="pill">OK</span></td></tr>
            <tr><td>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</td><td>security_ops</td><td>Reviewed alerts</td><td><span class="pill">OK</span></td></tr>
            <tr><td>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</td><td>auditor</td><td>Exported audit report</td><td><span class="pill">OK</span></td></tr>
          </tbody>
        </table>
      </div>
    </main>
  </div>
</body>
</html>
        """.strip()

        return self._http_response(200, "OK", "text/html; charset=utf-8", body)

    def error_response(self, code: int) -> bytes:
        reason = "Forbidden" if code == 403 else "OK" if code == 200 else "Error"
        return self._http_response(code, reason, "text/plain; charset=utf-8", "Access Denied")

    def success_response(self) -> bytes:
        return self._http_response(200, "OK", "text/plain; charset=utf-8", "OK")

    # ----------------------------
    # Malware upload helpers
    # ----------------------------
    def quarantine_file(self, source_ip: str, filename: str, content: str):
        quarantine_dir = os.path.join(self.log_dir, "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)

        file_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
        quarantine_path = os.path.join(quarantine_dir, f"{file_hash}_{filename}")

        with open(quarantine_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)

        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO malware_samples (timestamp, source_ip, filename, hash, size, quarantine_path)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (datetime.now().isoformat(), source_ip, filename, file_hash, len(content), quarantine_path),
        )
        conn.commit()
        conn.close()

    def extract_filename(self, request: str):
        import re
        m = re.search(r'filename="([^"]+)"', request, re.IGNORECASE)
        return m.group(1) if m else None

    def is_malicious_file(self, filename: str) -> bool:
        ext = os.path.splitext(filename)[1].lower()
        exts = self.rules.get("malware_upload", {}).get("extensions", [])
        return ext in exts

    # ----------------------------
    # Attack handler (threshold based)
    # ----------------------------
    def _handle_detected_attack(self, source_ip: str, attack_type: str, details, severity: str, block_reason: str):
        threshold_hit = self.tracker.record_attempt(source_ip, attack_type)

        details_str = details if isinstance(details, str) else json.dumps(details)
        self.log_attack_db(source_ip, attack_type, details_str, severity)

        self._log_attack_jsonl({
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "attack_type": attack_type,
            "service": "HTTP",
            "port": self.port,
            "severity": severity,
            "details": details,
            "blocked": self.tracker.is_blocked(source_ip),
            "threshold_hit": threshold_hit,
        })

        if threshold_hit and source_ip not in self.safe_ips:
            self.tracker.block_ip(source_ip, block_reason, severity)
            return True

        return False

    # ----------------------------
    # Main socket handler
    # ----------------------------
    def handle_client(self, client_socket: socket.socket, addr):
        source_ip = addr[0]

        # If blocked, return 403 (no reset)
        if self.tracker.is_blocked(source_ip):
            try:
                client_socket.sendall(self.error_response(403))
            except Exception:
                pass
            finally:
                client_socket.close()
            return

        client_socket.settimeout(30)

        try:
            raw = client_socket.recv(8192).decode("utf-8", errors="ignore")
            if not raw:
                return

            decoded = unquote_plus(raw)

            request_line = raw.split("\r\n")[0] if "\r\n" in raw else raw[:80]
            method, target, _ = self._parse_request_line(request_line)

            headers = self._parse_headers(raw)
            authed = self._is_authed(headers)

            parsed = urlparse(target)
            path = parsed.path or "/"

            logger.info(f"HTTP request from {source_ip} . {unquote_plus(request_line)}")

            # Attack detection first (based on your YAML rules)
            sqli_rule = self.rules.get("sql_injection", {})
            trav_rule = self.rules.get("directory_traversal", {})
            malware_rule = self.rules.get("malware_upload", {})

            sqli_patterns = sqli_rule.get("patterns", [])
            trav_patterns = trav_rule.get("patterns", [])

            if sqli_patterns and match_any(sqli_patterns, decoded):
                severity = sqli_rule.get("severity", "critical")
                blocked_now = self._handle_detected_attack(source_ip, "sql_injection", unquote_plus(request_line), severity, "SQL Injection Attempt")
                response = self.error_response(403) if blocked_now else self.error_response(200)

            elif trav_patterns and match_any(trav_patterns, decoded):
                severity = trav_rule.get("severity", "high")
                blocked_now = self._handle_detected_attack(source_ip, "directory_traversal", unquote_plus(request_line), severity, "Directory Traversal Attack")
                response = self.error_response(403) if blocked_now else self.error_response(200)

            elif method == "POST" and path == "/upload":
                filename = self.extract_filename(raw)
                if filename and self.is_malicious_file(filename):
                    self.quarantine_file(source_ip, filename, raw)
                    severity = malware_rule.get("severity", "critical")
                    blocked_now = self._handle_detected_attack(source_ip, "malware_upload", {"filename": filename}, severity, "Malware Upload Attempt")
                    response = self.error_response(403) if blocked_now else self.error_response(200)
                else:
                    response = self.success_response()

            # ---- Fake app routes ----
            elif method == "GET" and path in ("/", "/login"):
                response = self.login_page()

            elif method == "POST" and path == "/login":
                body = unquote_plus(self._get_body(raw))
                params = parse_qs(body)

                username = (params.get("username", [""])[0] or "").strip()
                password = (params.get("password", [""])[0] or "").strip()

                # Log the login attempt (safe input capture)
                self._log_attack_jsonl({
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": source_ip,
                    "attack_type": "http_login_attempt",
                    "service": "HTTP",
                    "port": self.port,
                    "severity": "info",
                    "details": {"username": username, "password": password},
                    "blocked": self.tracker.is_blocked(source_ip),
                })

                # Pretend successful login and redirect to admin
                response = self._redirect(
                    "/admin/dashboard",
                    extra_headers={
                        "Set-Cookie": "hp_auth=1; Path=/; HttpOnly"
                    },
                )

            elif method == "GET" and path in ("/admin", "/admin/dashboard", "/admin/users", "/admin/audit", "/admin/alerts", "/admin/settings"):
                if not authed:
                    response = self._redirect("/login")
                else:
                    # Log admin navigation as “post compromise behavior”
                    self._log_attack_jsonl({
                        "timestamp": datetime.now().isoformat(),
                        "source_ip": source_ip,
                        "attack_type": "admin_navigation",
                        "service": "HTTP",
                        "port": self.port,
                        "severity": "info",
                        "details": {"path": path},
                        "blocked": self.tracker.is_blocked(source_ip),
                    })
                    response = self.admin_dashboard(source_ip)

            elif method == "GET" and path == "/logout":
                response = self._redirect(
                    "/login",
                    extra_headers={"Set-Cookie": "hp_auth=; Path=/; Max-Age=0"}
                )

            else:
                response = self.login_page()

            client_socket.sendall(response)

        except (socket.timeout, TimeoutError):
            # Normal: client connected but didn't send data in time (scanners, browsers, etc.)
            logger.info(f"HTTP client timed out before sending data . ip={source_ip}")
        except Exception as e:
            tb = traceback.format_exc()
            logger.error(f"HTTP handler error . {e}\n{tb}")

            # Crash-safe response so curl/browser doesn't show "connection was aborted"
            try:
                client_socket.sendall(
                    self._http_response(
                        500,
                        "Internal Server Error",
                        "text/plain; charset=utf-8",
                        "Internal Server Error",
                    )
                )
            except Exception:
                pass
        finally:
            client_socket.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.ip, self.port))
        server.listen(50)

        logger.info(f"HTTP Honeypot listening on port {self.port}")

        while True:
            client, addr = server.accept()
            Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
