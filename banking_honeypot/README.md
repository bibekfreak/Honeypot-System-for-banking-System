# Banking Honeypot (Educational Lab)

## What this is
A rule-based honeypot that emulates SSH, FTP, and HTTP services.
It detects brute force, SQL injection, directory traversal, and suspicious upload attempts.
It logs to SQLite and JSONL files, blocks IPs, and shows a dashboard.

## Run
### 1) Install deps
python -m venv .venv
# Windows:
.venv\Scripts\activate
# mac/linux:
source .venv/bin/activate

pip install -r requirements.txt

### 2) Start honeypot
python run.py

### 3) Start dashboard (optional)
python web/app.py

Open:
- Dashboard: http://127.0.0.1:5000
- HTTP Honeypot: http://127.0.0.1:8080

### Stop
Press Ctrl+C in the honeypot terminal. It generates a report in logs/.
