#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STYLE_FILE="web/styles.css"
TMP_FILTERED="$(mktemp)"
trap 'rm -f "$TMP_FILTERED"' EXIT
OTHER_FILES=(web/index.html web/oobe-mockup.html web/app.js web/oobe-mockup.js)

# Ignore legacy decorative palette swatches that are explicitly non-semantic.
awk '
  /LEGACY-PALETTE-ALLOWLIST START/ { skip=1; next }
  /LEGACY-PALETTE-ALLOWLIST END/ { skip=0; next }
  !skip { print FNR ":" $0 }
' "$STYLE_FILE" > "$TMP_FILTERED"

BANNED_HEX=(
  "#1f75c7"
  "#28b9ff"
  "#35d67a"
  "#0b8359"
  "#1ea1dd"
  "#244a9b"
  "#0a7b68"
)

failed=0
for hex in "${BANNED_HEX[@]}"; do
  if grep -Ein -i "${hex}" "$TMP_FILTERED" >/dev/null; then
    echo "Banned cool semantic color found in ${STYLE_FILE}: ${hex}"
    grep -Ein -i "${hex}" "$TMP_FILTERED" | sed "s|^|  |"
    failed=1
  fi
  for file in "${OTHER_FILES[@]}"; do
    if grep -Ein -i "${hex}" "$file" >/dev/null; then
      echo "Banned cool semantic color found in ${file}: ${hex}"
      grep -Ein -i "${hex}" "$file" | sed "s|^|  |"
      failed=1
    fi
  done
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "Warm palette audit passed."
