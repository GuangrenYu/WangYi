#!/usr/bin/env bash
set -euo pipefail

# Build a portable source bundle without Docker, caches, reports, or local data.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/dist}"
STAMP="$(date +%Y%m%d_%H%M%S)"
PACKAGE_DIR="$OUT_DIR/cve-hunter-ubuntu-$STAMP"
ARCHIVE="$OUT_DIR/cve-hunter-ubuntu-$STAMP.tar.gz"

rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"
cp "$ROOT_DIR/main.py" "$ROOT_DIR/requirements.txt" "$ROOT_DIR/README.md" "$ROOT_DIR/.env.example" "$PACKAGE_DIR/"
cp -R "$ROOT_DIR/cve_hunter" "$PACKAGE_DIR/cve_hunter"
mkdir -p "$PACKAGE_DIR/poc_kb"
cp -R "$ROOT_DIR/poc_kb/custom" "$PACKAGE_DIR/poc_kb/custom"
cp "$ROOT_DIR/run_web.sh" "$ROOT_DIR/deploy_ubuntu.sh" "$PACKAGE_DIR/"
find "$PACKAGE_DIR" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$PACKAGE_DIR" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

tar -czf "$ARCHIVE" -C "$OUT_DIR" "$(basename "$PACKAGE_DIR")"
rm -rf "$PACKAGE_DIR"
printf 'Created %s\n' "$ARCHIVE"
