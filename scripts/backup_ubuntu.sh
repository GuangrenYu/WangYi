#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: bash scripts/backup_ubuntu.sh [app_dir] [backup_dir]
APP_DIR="${1:-$(pwd)}"
BACKUP_DIR="${2:-$HOME/cve-hunter-backups}"

APP_DIR="$(cd "$APP_DIR" && pwd -P)"
mkdir -p "$BACKUP_DIR"
BACKUP_DIR="$(cd "$BACKUP_DIR" && pwd -P)"

if [[ ! -f "$APP_DIR/requirements.txt" ]]; then
  echo "requirements.txt not found in $APP_DIR" >&2
  exit 1
fi
if [[ "$BACKUP_DIR" == "$APP_DIR"/* || "$BACKUP_DIR" == "$APP_DIR" ]]; then
  echo "backup_dir must be outside app_dir to avoid archiving the backup itself" >&2
  exit 1
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
ARCHIVE="$BACKUP_DIR/cve-hunter-$STAMP.tar.gz"

echo "Creating $ARCHIVE"
tar -czf "$ARCHIVE" \
  --exclude='./.git' \
  --exclude='./.venv' \
  --exclude='./venv' \
  --exclude='./__pycache__' \
  --exclude='*/__pycache__' \
  --exclude='*.pyc' \
  --exclude='*.pyo' \
  --exclude='./.pytest_cache' \
  --exclude='*/.pytest_cache' \
  --exclude='./.mypy_cache' \
  --exclude='*/.mypy_cache' \
  -C "$APP_DIR" .

sha256sum "$ARCHIVE" | tee "$ARCHIVE.sha256"
chmod 600 "$ARCHIVE" "$ARCHIVE.sha256"
echo "Backup complete: $ARCHIVE"
du -h "$ARCHIVE"
