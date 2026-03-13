#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STYLE_FILE="web/styles.css"
FONT_FILES=(
  "web/styles.css"
  "web/app.js"
  "web/index.html"
  "web/oobe-mockup.html"
)
FONT_VIOLATION_PATTERN='(^|[^[:alnum:]_])(Inter|Georgia|Helvetica|Arial|ui-sans-serif|ui-monospace|SFMono-Regular|Menlo|Monaco|Consolas|sans-serif|serif)([^[:alnum:]_]|$)|Times New Roman|Segoe UI|Liberation Mono|Courier New'

if [[ ! -f "$STYLE_FILE" ]]; then
  echo "Missing $STYLE_FILE"
  exit 1
fi

failed=0

while IFS= read -r line; do
  num="${line%%:*}"
  text="${line#*:}"
  value="${text#*:}"
  value="${value%%;*}"
  compact="$(echo "$value" | tr -d '[:space:]')"
  if [[ "$compact" =~ [1-9] ]]; then
    echo "UI contract violation: border-radius must be 0 (${STYLE_FILE}:${num})"
    echo "  $text"
    failed=1
  fi
done < <(grep -Ein "border-radius[[:space:]]*:" "$STYLE_FILE" || true)

while IFS= read -r line; do
  num="${line%%:*}"
  text="${line#*:}"
  value="${text#*:}"
  value="${value%%;*}"
  compact="$(echo "$value" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
  if [[ "$compact" != "none" ]]; then
    echo "UI contract violation: box-shadow must be none (${STYLE_FILE}:${num})"
    echo "  $text"
    failed=1
  fi
done < <(grep -Ein "box-shadow[[:space:]]*:" "$STYLE_FILE" || true)

if grep -Ein "border(-top|-right|-bottom|-left)?[[:space:]]*:[^;]*[2-9][0-9]*px" "$STYLE_FILE" >/dev/null; then
  echo "UI contract violation: structural border width must stay at 1px"
  grep -Ein "border(-top|-right|-bottom|-left)?[[:space:]]*:[^;]*[2-9][0-9]*px" "$STYLE_FILE" | sed 's/^/  /'
  failed=1
fi

if grep -Ein "linear-gradient|radial-gradient|conic-gradient" "$STYLE_FILE" >/dev/null; then
  echo "UI contract violation: gradients are forbidden on primary surfaces"
  grep -Ein "linear-gradient|radial-gradient|conic-gradient" "$STYLE_FILE" | sed 's/^/  /'
  failed=1
fi

for file in "${FONT_FILES[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing $file"
    failed=1
    continue
  fi
  if grep -Ein "$FONT_VIOLATION_PATTERN" "$file" >/dev/null; then
    echo "UI contract violation: only IBM Plex Mono may be declared in $file"
    grep -Ein "$FONT_VIOLATION_PATTERN" "$file" | sed 's/^/  /'
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "UI contract audit passed."
