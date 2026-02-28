#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v python3 >/dev/null 2>&1; then
  exec python3 "$ROOT_DIR/scripts/mailclient_tui.py"
fi

exec bash "$ROOT_DIR/scripts/tui_plain.sh"
