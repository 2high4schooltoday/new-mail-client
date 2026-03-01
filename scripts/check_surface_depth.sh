#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HTML_FILE="web/index.html"

if [[ ! -f "$HTML_FILE" ]]; then
  echo "Missing $HTML_FILE"
  exit 1
fi

python3 - <<'PY'
from html.parser import HTMLParser

HTML_FILE = "web/index.html"
SURFACES = {
    "app-shell",
    "panel",
    "oobe-window",
    "oobe-modal-card",
    "compose-dialog",
}
MAX_ALLOWED = 2

class DepthAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.max_depth = 0
        self.max_tag = ""

    def handle_starttag(self, tag, attrs):
        attrs_map = {k: (v or "") for k, v in attrs}
        class_tokens = set(attrs_map.get("class", "").split())
        parent_hidden = self.stack[-1]["hidden"] if self.stack else False
        hidden = parent_hidden or ("hidden" in class_tokens) or attrs_map.get("aria-hidden", "").lower() == "true"

        parent_depth = self.stack[-1]["depth"] if self.stack else 0
        is_surface = (not hidden) and bool(class_tokens & SURFACES)
        depth = parent_depth + 1 if is_surface else parent_depth

        if depth > self.max_depth:
            self.max_depth = depth
            ident = attrs_map.get("id", "")
            cls = attrs_map.get("class", "")
            self.max_tag = f"<{tag} id='{ident}' class='{cls}'>"

        self.stack.append({"hidden": hidden, "depth": depth})

    def handle_endtag(self, tag):
        if self.stack:
            self.stack.pop()

parser = DepthAudit()
with open(HTML_FILE, "r", encoding="utf-8") as f:
    parser.feed(f.read())

if parser.max_depth > MAX_ALLOWED:
    print(f"Surface depth audit failed: max depth {parser.max_depth} exceeds {MAX_ALLOWED}")
    if parser.max_tag:
        print(f"  Deepest visible surface node: {parser.max_tag}")
    raise SystemExit(1)

print(f"Surface depth audit passed (max depth {parser.max_depth}/{MAX_ALLOWED}).")
PY
