#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--docker" ]]; then
  exec docker compose -f docker-compose.web.yml up --build
fi
exec python -m uvicorn cve_hunter.web_app:app --host 127.0.0.1 --port "${PORT:-8000}"
