#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STYLE_FILE="web/styles.css"

if [[ ! -f "$STYLE_FILE" ]]; then
  echo "Missing $STYLE_FILE"
  exit 1
fi

required_selectors=(
  ".oobe-link-btn"
  ".oobe-control-rail"
  ".auth-task-selector"
  ".auth-task"
  ".auth-method-stack"
  ".auth-reset-stack"
  ".account-shell"
  ".account-security-grid"
  ".account-security-block"
  ".account-danger-block"
  ".security-badge"
  ".app-shell.is-setup-required .topbar"
  ".app-shell.is-setup-required #status-line"
)

missing=0
for selector in "${required_selectors[@]}"; do
  if ! rg -q --fixed-strings "$selector" "$STYLE_FILE"; then
    echo "UI selector contract violation: missing selector '$selector' in $STYLE_FILE"
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

echo "UI selector contract check passed."
