#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: bash scripts/restore_ubuntu.sh backup.tar.gz [/opt/cve-hunter]
ARCHIVE="${1:?Usage: $0 BACKUP.tar.gz [APP_DIR]}"
APP_DIR="${2:-$HOME/cve-hunter}"

if [[ ! -f "$ARCHIVE" ]]; then
  echo "Backup archive not found: $ARCHIVE" >&2
  exit 1
fi

if [[ -f "$ARCHIVE.sha256" ]]; then
  sha256sum -c "$ARCHIVE.sha256"
fi

mkdir -p "$APP_DIR"
tar -xzf "$ARCHIVE" -C "$APP_DIR"

cd "$APP_DIR"
if [[ ! -f requirements.txt ]]; then
  echo "requirements.txt not found after restore" >&2
  exit 1
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
mkdir -p output/web_runs output/web_tasks output/web_uploads data/cve/pcaps poc_kb/nvd

if [[ -f .env ]]; then
  chmod 600 .env
elif [[ -f .env.example ]]; then
  cp .env.example .env
  chmod 600 .env
  echo "Created $APP_DIR/.env from .env.example; fill in API keys before starting."
fi

# When the restore command was run through sudo, hand the tree back to the
# invoking user so the web process can write output and task snapshots.
if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  chown -R "$SUDO_USER:$(id -gn "$SUDO_USER")" "$APP_DIR"
fi

echo "Restore complete: $APP_DIR"
echo "Start with: cd $APP_DIR && source .venv/bin/activate && bash run_web.sh"
