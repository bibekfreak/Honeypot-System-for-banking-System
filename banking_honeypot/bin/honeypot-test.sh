#!/usr/bin/env bash
set -e

TARGET="${1:-127.0.0.1}"
HTTP_PORT="${2:-8080}"

echo "[*] Testing HTTP normal page"
curl -s "http://${TARGET}:${HTTP_PORT}/" >/dev/null || true

echo "[*] Testing SQL injection pattern"
curl -s "http://${TARGET}:${HTTP_PORT}/login?user=admin'%20OR%20'1'='1" >/dev/null || true

echo "[*] Testing directory traversal"
curl -s "http://${TARGET}:${HTTP_PORT}/../../windows/system.ini" >/dev/null || true

echo "[*] Done. Check logs/alerts.jsonl and logs/honeypot.log"
