#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGETS=(web/app.js web/index.html)

failed=0
for file in "${TARGETS[@]}"; do
  if [[ ! -f "$file" ]]; then
    continue
  fi
  matches="$(perl -ne '
    if (/(^|[^A-Za-z0-9_\$.])(window\.)?(prompt|confirm|alert)\s*\(/) {
      print "$.:$_";
    }
  ' "$file")"
  filtered=""
  if [[ -n "$matches" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      code="${line#*:}"
      if [[ "$code" == *"allow-native-recovery-email-prompt"* ]]; then
        continue
      fi
      if [[ "$code" =~ ^[[:space:]]*(async[[:space:]]+)?(prompt|confirm|alert)[[:space:]]*\(\)[[:space:]]*\{ ]]; then
        continue
      fi
      filtered+="${line}"$'\n'
    done <<< "$matches"
  fi
  if [[ -n "$filtered" ]]; then
    echo "Native browser dialog usage is forbidden in $file"
    printf '%s' "$filtered" | sed '/^$/d' | sed 's/^/  /'
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "No native browser dialogs found."
