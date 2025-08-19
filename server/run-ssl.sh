#!/usr/bin/env bash
set -euo pipefail

# Repo root and module path
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="server.main:app"
RELOAD_DIR="$ROOT/server"

# TLS (optional)
CERT="$ROOT/server/certs/dev.pem"
KEY="$ROOT/server/certs/dev-key.pem"

HOST="0.0.0.0"
PORT="${PORT:-8000}"

# Use your LAN IP for PUBLIC_BASE_URL if available (macOS en0 fallback to localhost)
LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || echo localhost)"

export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

if [[ -f "$CERT" && -f "$KEY" ]]; then
  echo "🔐 Starting HTTPS: cert=$CERT key=$KEY"
  export PUBLIC_BASE_URL="https://$LAN_IP:$PORT"
  exec uvicorn "$APP" \
    --host "$HOST" --port "$PORT" --reload --reload-dir "$RELOAD_DIR" \
    --ssl-certfile "$CERT" --ssl-keyfile "$KEY"
else
  echo "⚠️  TLS cert/key not found."
  echo "    CERT expected at: $CERT"
  echo "    KEY  expected at: $KEY"
  echo "    Starting HTTP instead."
  export PUBLIC_BASE_URL="http://$LAN_IP:$PORT"
  exec uvicorn "$APP" \
    --host "$HOST" --port "$PORT" --reload --reload-dir "$RELOAD_DIR"
fi
