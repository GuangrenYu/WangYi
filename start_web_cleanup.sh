#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
source .venv/bin/activate
cleanup() {
  find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
  find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete 2>/dev/null || true
  rm -rf .pytest_cache 2>/dev/null || true
}
trap cleanup EXIT INT TERM
HOST="${HOST:-0.0.0.0}" PORT="${PORT:-8000}" python -m uvicorn cve_hunter.web_app:app --host "$HOST" --port "$PORT"
