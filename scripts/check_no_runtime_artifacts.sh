#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

violations=()

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  violations+=(".env is tracked")
fi

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  violations+=("$path is tracked")
done < <(git ls-files 'data/*.db' 'data/*.db-shm' 'data/*.db-wal')

if [[ "${#violations[@]}" -gt 0 ]]; then
  printf 'Runtime secret/artifact tracking is not allowed:\n' >&2
  for item in "${violations[@]}"; do
    printf ' - %s\n' "$item" >&2
  done
  exit 1
fi

printf 'Runtime artifact tracking check passed.\n'
