#!/usr/bin/env bash
set -euo pipefail
export PYTHONUNBUFFERED=1
export STRONGHOLD_LOG_LEVEL=${STRONGHOLD_LOG_LEVEL:-INFO}
export DEV_ALLOW_INSECURE_COOKIE=${DEV_ALLOW_INSECURE_COOKIE:-1}
cd "$(dirname "$0")"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
