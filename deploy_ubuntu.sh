#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${CVH_APP_DIR:-$HOME/cve-hunter}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PORT="${PORT:-8000}"

if [[ ! -f "$APP_DIR/requirements.txt" ]]; then
  echo "requirements.txt not found in $APP_DIR" >&2
  echo "Clone or extract the Ubuntu package into CVH_APP_DIR first." >&2
  exit 1
fi

cd "$APP_DIR"
"$PYTHON_BIN" -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
mkdir -p output/web_runs output/web_tasks output/web_uploads
if [[ ! -f .env ]]; then cp .env.example .env; fi
exec python -m uvicorn cve_hunter.web_app:app --host "${HOST:-0.0.0.0}" --port "$PORT"
