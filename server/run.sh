#!/usr/bin/env bash
set -euo pipefail

# PROJECT ROOT is parent of this script's dir
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

export STRONGHOLD_DB_PATH=data/stronghold.db
export DEV_ALLOW_INSECURE_COOKIE=1
export SESSION_SAMESITE=lax

# Make Python import from the project root (so "server.*" works)
export PYTHONPATH="${PYTHONPATH:-$ROOT_DIR}"

# Force HTTP localhost for QR links and general use
export PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-http://localhost:8000}"

# Make sure no TLS env is set (we're reverting to HTTP)
unset SSL_CERTFILE || true
unset SSL_KEYFILE  || true

echo "🌐 Starting HTTP (no TLS)"
echo "    PUBLIC_BASE_URL=$PUBLIC_BASE_URL"
echo "    URL: http://localhost:8000"
echo "    PYTHONPATH=$PYTHONPATH"
echo "    CWD=$PWD"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python

# Run uvicorn using the package path "server.main:app"
exec "$PY" -m uvicorn server.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --reload-dir "$ROOT_DIR"
