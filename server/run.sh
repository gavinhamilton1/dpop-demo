#!/usr/bin/env bash
set -euo pipefail


export DPOP_FUN_CONFIG=server/dpop-fun.dev.yaml


# PROJECT ROOT is parent of this script's dir
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python

# Run uvicorn using the package path "server.main:app"
exec "$PY" -m uvicorn server.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --reload-dir "$ROOT_DIR"
