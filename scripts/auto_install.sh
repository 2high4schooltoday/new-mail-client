#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_EXAMPLE="$ROOT_DIR/.env.example"
OUT_ENV="$ROOT_DIR/.env"
DEFAULT_REPO_URL="${MAILCLIENT_REPO_URL:-https://github.com/2high4schooltoday/new-mail-client.git}"
DEFAULT_REPO_REF="${MAILCLIENT_REPO_REF:-main}"
APT_UPDATED=0

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err() { printf '[ERR ] %s\n' "$*" >&2; }

on_install_error() {
  local code="$1" line="$2" cmd="$3"
  err "Installer failed at line ${line}: ${cmd}"
  err "Run manually for diagnostics: bash -x \"$0\""
  exit "$code"
}
trap 'on_install_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

if [[ $# -ne 0 ]]; then
  err "This installer is interactive and does not accept arguments. Run: ./scripts/auto_install.sh"
  exit 1
fi

have_cmd() { command -v "$1" >/dev/null 2>&1; }

run_as_root() {
  if [[ "${EUID:-1}" -ne 0 ]]; then
    if ! have_cmd sudo; then
      err "sudo is required for this operation"
      exit 1
    fi
    sudo "$@"
    return
  fi
  "$@"
}

trim() {
  local s="$1"
  # shellcheck disable=SC2001
  s="$(echo "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  printf '%s' "$s"
}

lower() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

prompt_input() {
  local prompt="$1" default="${2:-}" val
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " val
    if [[ -z "$(trim "$val")" ]]; then
      printf '%s' "$default"
      return
    fi
    printf '%s' "$(trim "$val")"
    return
  fi
  while true; do
    read -r -p "$prompt: " val
    val="$(trim "$val")"
    if [[ -n "$val" ]]; then
      printf '%s' "$val"
      return
    fi
  done
}

prompt_yes_no() {
  local prompt="$1" default_yes="$2" ans
  local hint="[y/N]"
  if [[ "$default_yes" == "1" ]]; then
    hint="[Y/n]"
  fi
  while true; do
    read -r -p "$prompt $hint " ans
    ans="$(lower "$(trim "$ans")")"
    if [[ -z "$ans" ]]; then
      [[ "$default_yes" == "1" ]] && return 0
      return 1
    fi
    case "$ans" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
    esac
  done
}

install_apt_packages() {
  if ! have_cmd apt-get; then
    return 1
  fi
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    run_as_root apt-get update
    APT_UPDATED=1
  fi
  run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

ensure_repo_checkout_or_bootstrap() {
  if [[ -f "$ENV_EXAMPLE" && -f "$ROOT_DIR/go.mod" && -f "$ROOT_DIR/cmd/server/main.go" ]]; then
    return
  fi

  warn "App source files were not found next to this script."
  warn "Switching to standalone bootstrap mode (fetch from GitHub)."

  local uname_sys repo_url repo_ref checkout_base checkout_dir target
  uname_sys="$(lower "$(uname -s)")"
  if [[ "$uname_sys" != "linux" ]]; then
    err "Standalone bootstrap currently supports Linux servers only."
    exit 1
  fi

  repo_url="$(prompt_input "GitHub repository URL" "$DEFAULT_REPO_URL")"
  repo_ref="$(prompt_input "Git ref (branch/tag/commit)" "$DEFAULT_REPO_REF")"
  checkout_base="$(prompt_input "Installer workspace directory" "/opt/mailclient-installer")"
  checkout_dir="${checkout_base%/}/src"

  if ! have_cmd git; then
    if prompt_yes_no "git is missing. Install git automatically?" 1; then
      install_apt_packages git ca-certificates curl
    else
      err "git is required to download source files."
      exit 1
    fi
  fi

  run_as_root mkdir -p "$checkout_base"
  if [[ -d "$checkout_dir/.git" ]]; then
    run_as_root git -C "$checkout_dir" fetch --tags --prune origin
  else
    run_as_root rm -rf "$checkout_dir"
    run_as_root git clone "$repo_url" "$checkout_dir"
  fi
  run_as_root git -C "$checkout_dir" checkout "$repo_ref"
  run_as_root git -C "$checkout_dir" pull --ff-only origin "$repo_ref" || true

  target="$checkout_dir/scripts/auto_install.sh"
  if [[ ! -f "$target" ]]; then
    err "Downloaded repository does not contain scripts/auto_install.sh"
    exit 1
  fi

  log "Re-launching installer from: $checkout_dir"
  run_as_root env MAILCLIENT_REPO_URL="$repo_url" MAILCLIENT_REPO_REF="$repo_ref" bash "$target"
  exit 0
}

port_open() {
  local host="$1" port="$2"
  if have_cmd nc; then
    nc -z -w 1 "$host" "$port" >/dev/null 2>&1
    return $?
  fi
  (echo >"/dev/tcp/$host/$port") >/dev/null 2>&1
  return $?
}

set_env_var() {
  local file="$1" key="$2" value="$3"
  local tmp
  tmp="${file}.tmp.$$"

  if grep -q "^${key}=" "$file" 2>/dev/null; then
    awk -v k="$key" -v v="$value" '
      BEGIN { done = 0 }
      {
        if ($0 ~ "^" k "=") {
          print k "=" v
          done = 1
        } else {
          print $0
        }
      }
      END {
        if (!done) print k "=" v
      }
    ' "$file" >"$tmp"
  else
    cat "$file" >"$tmp"
    printf '%s=%s\n' "$key" "$value" >>"$tmp"
  fi
  mv "$tmp" "$file"
}

extract_kv_line() {
  local file="$1" key="$2"
  local line
  line="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null | tail -n 1 || true)"
  line="${line#*=}"
  trim "$line"
}

extract_table_from_query() {
  local q="$1"
  awk '
    {
      for (i = 1; i <= NF; i++) {
        t = tolower($i)
        gsub(/[;,]/, "", t)
        if (t == "from" && i + 1 <= NF) {
          v = $(i+1)
          gsub(/[;,]/, "", v)
          print v
          exit
        }
      }
    }
  ' <<<"$q"
}

extract_email_col_from_query() {
  local q="$1"
  local m
  m="$(echo "$q" | grep -Eo "[A-Za-z0-9_.\"\`]+[[:space:]]*=[[:space:]]*'?%[A-Za-z]+'?" | head -n 1 || true)"
  if [[ -n "$m" ]]; then
    echo "$m" | sed -E "s/[[:space:]]*=[[:space:]]*.*$//"
  fi
}

extract_password_col_from_query() {
  local q="$1"
  local select_part alias_hit token
  select_part="$(echo "$q" | sed -E 's/^[[:space:]]*[Ss][Ee][Ll][Ee][Cc][Tt][[:space:]]+//; s/[[:space:]]+[Ff][Rr][Oo][Mm][[:space:]].*$//')"

  alias_hit="$(echo "$select_part" | sed -nE "s/.*([A-Za-z0-9_.\"\`]+)[[:space:]]+[Aa][Ss][[:space:]]+password.*/\1/p" | head -n 1 || true)"
  if [[ -n "$alias_hit" ]]; then
    echo "$alias_hit"
    return
  fi

  while IFS= read -r token; do
    token="$(trim "$token")"
    if [[ -z "$token" ]]; then
      continue
    fi
    if echo "$(lower "$token")" | grep -q "password"; then
      echo "$token" | awk '{print $1}'
      return
    fi
    if echo "$(lower "$token")" | grep -q "pass"; then
      echo "$token" | awk '{print $1}'
      return
    fi
  done < <(echo "$select_part" | tr ',' '\n')
}

extract_maildir_col_from_query() {
  local q="$1"
  local select_part alias_hit token l
  select_part="$(echo "$q" | sed -E 's/^[[:space:]]*[Ss][Ee][Ll][Ee][Cc][Tt][[:space:]]+//; s/[[:space:]]+[Ff][Rr][Oo][Mm][[:space:]].*$//')"

  alias_hit="$(echo "$select_part" | sed -nE "s/.*([A-Za-z0-9_.\"\`]+)[[:space:]]+[Aa][Ss][[:space:]]+(maildir|mail|home).*/\1/p" | head -n 1 || true)"
  if [[ -n "$alias_hit" ]]; then
    echo "$alias_hit"
    return
  fi

  while IFS= read -r token; do
    token="$(trim "$token")"
    l="$(lower "$token")"
    if echo "$l" | grep -Eq "maildir|\bhome\b|\bmail\b"; then
      echo "$token" | awk '{print $1}'
      return
    fi
  done < <(echo "$select_part" | tr ',' '\n')
}

extract_active_col_from_query() {
  local q="$1"
  local maybe
  maybe="$(echo "$q" | grep -Eo "[A-Za-z0-9_.\"\`]+[[:space:]]*=[[:space:]]*(1|true|'[YyTt]'|'active'|[Aa][Cc][Tt][Ii][Vv][Ee])" | head -n 1 || true)"
  if [[ -n "$maybe" ]]; then
    echo "$maybe" | sed -E "s/[[:space:]]*=[[:space:]]*.*$//"
  fi
}

parse_connect_kv() {
  local connect="$1" key="$2"
  local tok k v
  local IFS=' '
  for tok in $connect; do
    k="${tok%%=*}"
    v="${tok#*=}"
    if [[ "$k" == "$key" ]]; then
      printf '%s' "$v"
      return
    fi
  done
}

build_dsn() {
  local driver="$1" connect="$2"
  local host port user pass db ssl
  host="$(parse_connect_kv "$connect" host)"
  port="$(parse_connect_kv "$connect" port)"
  user="$(parse_connect_kv "$connect" user)"
  pass="$(parse_connect_kv "$connect" password)"
  db="$(parse_connect_kv "$connect" dbname)"
  ssl="$(parse_connect_kv "$connect" sslmode)"

  if [[ "$driver" == "mysql" ]]; then
    [[ -z "$host" ]] && host="127.0.0.1"
    [[ -z "$port" ]] && port="3306"
    if [[ -z "$db" || -z "$user" ]]; then
      printf ''
      return
    fi
    if [[ "$host" == /* ]]; then
      printf '%s' "${user}:${pass}@unix(${host})/${db}?parseTime=true"
    else
      printf '%s' "${user}:${pass}@tcp(${host}:${port})/${db}?parseTime=true"
    fi
    return
  fi

  if [[ "$driver" == "pgx" ]]; then
    [[ -z "$host" ]] && host="127.0.0.1"
    [[ -z "$port" ]] && port="5432"
    [[ -z "$ssl" ]] && ssl="disable"
    if [[ -z "$db" || -z "$user" ]]; then
      printf ''
      return
    fi
    printf '%s' "postgres://${user}:${pass}@${host}:${port}/${db}?sslmode=${ssl}"
    return
  fi

  printf ''
}

detect_sql_conf_file() {
  if [[ -n "${DOVECOT_SQL_CONF:-}" && -f "${DOVECOT_SQL_CONF}" ]]; then
    printf '%s' "$DOVECOT_SQL_CONF"
    return
  fi

  local candidates out p
  candidates=""

  if have_cmd doveconf; then
    out="$(doveconf -n 2>/dev/null || true)"
    if [[ -z "$out" && ${EUID:-1} -ne 0 ]] && have_cmd sudo; then
      out="$(sudo -n doveconf -n 2>/dev/null || true)"
    fi
    if [[ -n "$out" ]]; then
      while IFS= read -r p; do
        p="$(trim "$p")"
        [[ -z "$p" ]] && continue
        candidates+="$p\n"
      done < <(printf '%s\n' "$out" | sed -nE 's/^[[:space:]]*args[[:space:]]*=[[:space:]]*(.*dovecot-sql[^[:space:]]*).*/\1/p')
    fi
  fi

  candidates+="/etc/dovecot/dovecot-sql.conf.ext\n"
  candidates+="/usr/local/etc/dovecot/dovecot-sql.conf.ext\n"

  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if [[ -f "$p" ]]; then
      printf '%s' "$p"
      return
    fi
  done <<<"$(printf "%b" "$candidates")"

  printf ''
}

detect_dovecot_auth_mode() {
  local out=""
  if have_cmd doveconf; then
    out="$(doveconf -n 2>/dev/null || true)"
    if [[ -z "$out" && ${EUID:-1} -ne 0 ]] && have_cmd sudo; then
      out="$(sudo -n doveconf -n 2>/dev/null || true)"
    fi
  fi

  if [[ -n "$out" ]] && echo "$out" | grep -Eiq 'driver[[:space:]]*=[[:space:]]*pam'; then
    printf 'pam'
    return
  fi

  if grep -RqsE 'auth-system\.conf\.ext|driver[[:space:]]*=[[:space:]]*pam' /etc/dovecot /usr/local/etc/dovecot 2>/dev/null; then
    printf 'pam'
    return
  fi

  printf 'sql'
}

detect_imap_port() {
  if port_open 127.0.0.1 993; then
    echo 993
    return
  fi
  if port_open 127.0.0.1 143; then
    echo 143
    return
  fi
  echo 993
}

detect_smtp_port() {
  if port_open 127.0.0.1 587; then
    echo 587
    return
  fi
  if port_open 127.0.0.1 465; then
    echo 465
    return
  fi
  if port_open 127.0.0.1 25; then
    echo 25
    return
  fi
  echo 587
}

detect_web_servers() {
  local found=()
  if [[ -d /etc/nginx ]] || have_cmd nginx; then
    found+=("nginx")
  fi
  if [[ -d /etc/apache2 ]] || have_cmd apache2 || have_cmd apache2ctl; then
    found+=("apache2")
  fi
  printf '%s\n' "${found[@]}"
}

detect_primary_ip() {
  local ip
  if have_cmd hostname; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    ip="$(trim "${ip:-}")"
    if [[ -n "$ip" ]]; then
      printf '%s' "$ip"
      return
    fi
  fi
  if have_cmd ip; then
    ip="$(ip route get 1.1.1.1 2>/dev/null | sed -nE 's/.* src ([^ ]+).*/\1/p' | head -n1 || true)"
    ip="$(trim "${ip:-}")"
    if [[ -n "$ip" ]]; then
      printf '%s' "$ip"
      return
    fi
  fi
  printf '<server-ip>'
}

verify_direct_access() {
  local listen_addr="$1"
  local check_url
  if [[ "$listen_addr" =~ ^:([0-9]+)$ ]]; then
    check_url="http://127.0.0.1:${BASH_REMATCH[1]}/health/live"
  elif [[ "$listen_addr" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
    check_url="http://127.0.0.1:${BASH_REMATCH[1]}/health/live"
  elif [[ "$listen_addr" =~ ^0\.0\.0\.0:([0-9]+)$ ]]; then
    check_url="http://127.0.0.1:${BASH_REMATCH[1]}/health/live"
  else
    check_url="http://127.0.0.1:8080/health/live"
  fi
  curl -fsS --max-time 5 "$check_url" >/dev/null
}

verify_proxy_access() {
  local server="$1" tls_enabled="$2"
  if [[ "$tls_enabled" == "1" ]]; then
    curl -kfsS --max-time 8 --resolve "${server}:443:127.0.0.1" "https://${server}/health/live" >/dev/null
    return
  fi
  curl -fsS --max-time 8 -H "Host: ${server}" "http://127.0.0.1/health/live" >/dev/null
}

apply_ufw_rules() {
  local mode="$1"
  local rc=0
  if ! have_cmd ufw; then
    return
  fi
  if ! run_as_root ufw status >/dev/null 2>&1; then
    warn "ufw exists but could not be queried; skipping firewall automation."
    return
  fi
  if [[ "$mode" == "proxy" ]]; then
    if prompt_yes_no "Open firewall ports 80/tcp and 443/tcp via ufw?" 1; then
      if ! run_as_root ufw allow 80/tcp >/dev/null 2>&1; then
        warn "Failed to apply ufw rule 80/tcp. Continue manually: sudo ufw allow 80/tcp"
        rc=1
      fi
      if ! run_as_root ufw allow 443/tcp >/dev/null 2>&1; then
        warn "Failed to apply ufw rule 443/tcp. Continue manually: sudo ufw allow 443/tcp"
        rc=1
      fi
      if [[ "$rc" -eq 0 ]]; then
        log "Applied ufw rules: 80/tcp, 443/tcp"
      else
        warn "ufw automation incomplete; installer will continue."
      fi
    fi
    return
  fi
  if prompt_yes_no "Open firewall port 8080/tcp via ufw for direct access?" 1; then
    if run_as_root ufw allow 8080/tcp >/dev/null 2>&1; then
      log "Applied ufw rule: 8080/tcp"
    else
      warn "Failed to apply ufw rule 8080/tcp. Continue manually: sudo ufw allow 8080/tcp"
      warn "ufw automation incomplete; installer will continue."
    fi
  fi
}

print_cloud_firewall_checklist() {
  local mode="$1"
  cat <<EOF

Cloud firewall / security-group checklist:
  - Ensure DNS points to this server public IP.
  - Ensure inbound rules allow required ports.
EOF
  if [[ "$mode" == "proxy" ]]; then
    cat <<EOF
  - Required inbound: TCP 80 and TCP 443.
EOF
  else
    cat <<EOF
  - Required inbound: TCP 8080.
EOF
  fi
  cat <<EOF
  - Verify no provider-level ACL/NACL blocks these ports.

EOF
}

ensure_service_dependencies() {
  local os_id="$1"
  local missing=()
  local install_pkgs=()

  if ! have_cmd go; then
    missing+=("go")
    install_pkgs+=("golang-go")
  fi
  if ! have_cmd gcc; then
    missing+=("gcc")
    install_pkgs+=("build-essential")
  fi
  if ! have_cmd git; then
    missing+=("git")
    install_pkgs+=("git")
  fi
  if ! have_cmd pkg-config; then
    missing+=("pkg-config")
    install_pkgs+=("pkg-config")
  fi
  if ! have_cmd curl; then
    missing+=("curl")
    install_pkgs+=("curl")
  fi

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return
  fi

  warn "Missing build/runtime dependencies: ${missing[*]}"
  if [[ "$os_id" == "ubuntu" || "$os_id" == "debian" ]]; then
    if prompt_yes_no "Install missing dependencies automatically with apt?" 1; then
      install_apt_packages "${install_pkgs[@]}"
      return
    fi
  fi

  err "Required dependencies are missing: ${missing[*]}"
  exit 1
}

render_nginx_conf() {
  local server_name="$1" upstream="$2" tls_enabled="$3" cert_file="$4" key_file="$5"
  if [[ "$tls_enabled" == "1" ]]; then
    cat <<EOF
server {
    listen 80;
    server_name ${server_name};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${server_name};
    client_max_body_size 30m;

    ssl_certificate ${cert_file};
    ssl_certificate_key ${key_file};

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://${upstream};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    return
  fi

  cat <<EOF
server {
    listen 80;
    server_name ${server_name};
    client_max_body_size 30m;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://${upstream};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
}

render_apache_conf() {
  local server_name="$1" upstream="$2" tls_enabled="$3" cert_file="$4" key_file="$5"
  cat <<EOF
<VirtualHost *:80>
    ServerName ${server_name}

    ProxyPreserveHost On
    ProxyRequests Off
    AllowEncodedSlashes NoDecode

    RequestHeader set X-Forwarded-Proto expr=%{REQUEST_SCHEME}
    ProxyPass / http://${upstream}/ nocanon
    ProxyPassReverse / http://${upstream}/

    LimitRequestBody 31457280
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
</VirtualHost>
EOF

  if [[ "$tls_enabled" == "1" ]]; then
    cat <<EOF

<VirtualHost *:443>
    ServerName ${server_name}

    SSLEngine on
    SSLCertificateFile ${cert_file}
    SSLCertificateKeyFile ${key_file}

    ProxyPreserveHost On
    ProxyRequests Off
    AllowEncodedSlashes NoDecode

    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass / http://${upstream}/ nocanon
    ProxyPassReverse / http://${upstream}/

    LimitRequestBody 31457280
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
</VirtualHost>
EOF
  fi
}

setup_nginx_proxy() {
  local server_name="$1" upstream="$2" tls_enabled="$3" cert_file="$4" key_file="$5"
  local conf="/etc/nginx/sites-available/mailclient.conf"
  local enabled="/etc/nginx/sites-enabled/mailclient.conf"
  local tmp
  tmp="$(mktemp)"
  render_nginx_conf "$server_name" "$upstream" "$tls_enabled" "$cert_file" "$key_file" >"$tmp"

  "${PREFIX[@]}" mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
  "${PREFIX[@]}" install -m 0644 "$tmp" "$conf"
  "${PREFIX[@]}" ln -sfn "$conf" "$enabled"
  rm -f "$tmp"

  if [[ ! -L "$enabled" ]]; then
    err "Nginx site enablement failed: ${enabled} symlink missing"
    exit 1
  fi

  "${PREFIX[@]}" nginx -t
  "${PREFIX[@]}" systemctl enable --now nginx
  "${PREFIX[@]}" systemctl reload nginx
}

setup_apache_proxy() {
  local server_name="$1" upstream="$2" tls_enabled="$3" cert_file="$4" key_file="$5"
  local conf="/etc/apache2/sites-available/mailclient.conf"
  local tmp
  tmp="$(mktemp)"
  render_apache_conf "$server_name" "$upstream" "$tls_enabled" "$cert_file" "$key_file" >"$tmp"

  "${PREFIX[@]}" install -m 0644 "$tmp" "$conf"
  rm -f "$tmp"

  "${PREFIX[@]}" a2enmod proxy proxy_http headers >/dev/null
  if [[ "$tls_enabled" == "1" ]]; then
    "${PREFIX[@]}" a2enmod ssl >/dev/null
  fi
  "${PREFIX[@]}" a2ensite mailclient.conf >/dev/null
  if [[ ! -L /etc/apache2/sites-enabled/mailclient.conf && ! -f /etc/apache2/sites-enabled/mailclient.conf ]]; then
    err "Apache2 site enablement failed: /etc/apache2/sites-enabled/mailclient.conf missing"
    exit 1
  fi
  "${PREFIX[@]}" apache2ctl configtest
  "${PREFIX[@]}" systemctl enable --now apache2
  "${PREFIX[@]}" systemctl reload apache2
}

detect_default_domain() {
  local out
  if [[ -f /etc/mailname ]]; then
    out="$(trim "$(cat /etc/mailname 2>/dev/null || true)")"
    if [[ "$out" == *.* && "$out" != "localhost" ]]; then
      printf '%s' "$out"
      return
    fi
  fi

  if have_cmd hostname; then
    out="$(hostname -f 2>/dev/null || true)"
    out="$(trim "$out")"
    if [[ "$out" == *.* && "$out" != "localhost" ]]; then
      printf '%s' "$out"
      return
    fi
  fi

  printf 'example.com'
}

generate_secret() {
  if have_cmd openssl; then
    openssl rand -hex 32
    return
  fi
  if [[ -r /dev/urandom ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    return
  fi
  date +%s | sha256sum | awk '{print $1}'
}

ensure_repo_checkout_or_bootstrap

if [[ ! -f "$ENV_EXAMPLE" ]]; then
  err ".env.example not found at $ENV_EXAMPLE"
  exit 1
fi

OS_ID="unknown"
OS_VER="unknown"
UNAME_ARCH="$(uname -m)"
UNAME_SYS="$(lower "$(uname -s)")"
if [[ -f /etc/os-release ]]; then
  # shellcheck source=/etc/os-release
  . /etc/os-release
  OS_ID="$(lower "${ID:-unknown}")"
  OS_VER="${VERSION_ID:-unknown}"
else
  OS_ID="$UNAME_SYS"
fi

GOARCH=""
case "$UNAME_ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *)
    err "Unsupported CPU architecture: $UNAME_ARCH (supported: x86_64, aarch64/arm64)"
    exit 1
    ;;
esac

if [[ "$UNAME_SYS" != "linux" ]]; then
  warn "Detected non-Linux host: $UNAME_SYS. Service installation is Ubuntu/Linux only; .env generation still works."
fi
if [[ "$OS_ID" != "ubuntu" ]]; then
  warn "Detected OS: $OS_ID $OS_VER. This script is validated for Ubuntu Server; continuing in best-effort mode."
fi

log "Despatch interactive installer"
log "Detected platform: ${OS_ID} ${OS_VER}, arch ${UNAME_ARCH} (${GOARCH})"

if ! prompt_yes_no "Continue with installation?" 1; then
  err "Aborted"
  exit 1
fi

BASE_DOMAIN_DEFAULT="$(detect_default_domain)"
LISTEN_ADDR_DEFAULT=":8080"
INSTALL_SERVICE=1
PROXY_SETUP=0
PROXY_SERVER=""
PROXY_SERVER_NAME=""
PROXY_TLS=0
PROXY_CERT=""
PROXY_KEY=""
DEPLOY_MODE="direct"

BASE_DOMAIN="$(prompt_input "Primary mail domain (used by first-run web setup)" "$BASE_DOMAIN_DEFAULT")"
LISTEN_ADDR="$(prompt_input "HTTP listen address" "$LISTEN_ADDR_DEFAULT")"
if [[ "$UNAME_SYS" != "linux" ]]; then
  INSTALL_SERVICE=0
  warn "Service installation disabled on non-Linux hosts."
elif ! prompt_yes_no "Install and start systemd service automatically?" 1; then
  INSTALL_SERVICE=0
fi

if [[ "$INSTALL_SERVICE" -eq 1 ]]; then
  mapfile -t WEB_SERVERS < <(detect_web_servers)
  if [[ "${#WEB_SERVERS[@]}" -gt 0 ]]; then
    if prompt_yes_no "Detected installed reverse proxy ($(IFS=,; echo "${WEB_SERVERS[*]}")). Configure it automatically?" 1; then
      PROXY_SETUP=1
      DEPLOY_MODE="proxy"
      if [[ "${#WEB_SERVERS[@]}" -eq 1 ]]; then
        PROXY_SERVER="${WEB_SERVERS[0]}"
      else
        while true; do
          choice="$(lower "$(prompt_input "Choose proxy server: nginx or apache2" "${WEB_SERVERS[0]}")")"
          if [[ "$choice" == "nginx" || "$choice" == "apache2" ]]; then
            PROXY_SERVER="$choice"
            break
          fi
          warn "Choose either nginx or apache2."
        done
      fi
      PROXY_SERVER_NAME="$(prompt_input "Public server name for reverse proxy" "$BASE_DOMAIN")"
      if prompt_yes_no "Enable TLS in reverse proxy config now (requires existing cert files)?" 0; then
        PROXY_TLS=1
        PROXY_CERT="$(prompt_input "TLS certificate file" "/etc/letsencrypt/live/${PROXY_SERVER_NAME}/fullchain.pem")"
        PROXY_KEY="$(prompt_input "TLS private key file" "/etc/letsencrypt/live/${PROXY_SERVER_NAME}/privkey.pem")"
      fi
      if [[ "$LISTEN_ADDR" == ":8080" ]]; then
        LISTEN_ADDR="127.0.0.1:8080"
        log "Adjusted app listen address to ${LISTEN_ADDR} because reverse proxy is enabled."
      fi
    fi
  fi
fi

SQL_CONF="$(detect_sql_conf_file)"
DOVECOT_AUTH_MODE_DETECTED="$(detect_dovecot_auth_mode)"
DOVECOT_AUTH_MODE="$(lower "$(prompt_input "Dovecot auth backend mode (pam or sql)" "$DOVECOT_AUTH_MODE_DETECTED")")"
if [[ "$DOVECOT_AUTH_MODE" != "pam" && "$DOVECOT_AUTH_MODE" != "sql" ]]; then
  warn "Invalid auth backend mode: $DOVECOT_AUTH_MODE. Falling back to detected mode: $DOVECOT_AUTH_MODE_DETECTED"
  DOVECOT_AUTH_MODE="$DOVECOT_AUTH_MODE_DETECTED"
fi
DOVECOT_DRIVER_RAW=""
DOVECOT_DRIVER=""
DOVECOT_CONNECT=""
DOVECOT_PASSWORD_QUERY=""
DOVECOT_USER_QUERY=""
DOVECOT_TABLE="users"
DOVECOT_EMAIL_COL="email"
DOVECOT_PASS_COL="password_hash"
DOVECOT_ACTIVE_COL=""
DOVECOT_MAILDIR_COL=""
DOVECOT_DSN=""

if [[ "$DOVECOT_AUTH_MODE" == "sql" && -n "$SQL_CONF" ]]; then
  DOVECOT_DRIVER_RAW="$(extract_kv_line "$SQL_CONF" driver)"
  DOVECOT_CONNECT="$(extract_kv_line "$SQL_CONF" connect)"
  DOVECOT_PASSWORD_QUERY="$(extract_kv_line "$SQL_CONF" password_query)"
  DOVECOT_USER_QUERY="$(extract_kv_line "$SQL_CONF" user_query)"

  case "$(lower "$DOVECOT_DRIVER_RAW")" in
    mysql) DOVECOT_DRIVER="mysql" ;;
    pgsql|postgres|postgresql|pgx) DOVECOT_DRIVER="pgx" ;;
    *) DOVECOT_DRIVER="" ;;
  esac

  if [[ -n "$DOVECOT_PASSWORD_QUERY" ]]; then
    t="$(extract_table_from_query "$DOVECOT_PASSWORD_QUERY")"
    [[ -n "$t" ]] && DOVECOT_TABLE="$t"
    c="$(extract_email_col_from_query "$DOVECOT_PASSWORD_QUERY")"
    [[ -n "$c" ]] && DOVECOT_EMAIL_COL="$c"
    c="$(extract_password_col_from_query "$DOVECOT_PASSWORD_QUERY")"
    [[ -n "$c" ]] && DOVECOT_PASS_COL="$c"
    c="$(extract_active_col_from_query "$DOVECOT_PASSWORD_QUERY")"
    [[ -n "$c" ]] && DOVECOT_ACTIVE_COL="$c"
  fi

  if [[ -n "$DOVECOT_USER_QUERY" ]]; then
    c="$(extract_maildir_col_from_query "$DOVECOT_USER_QUERY")"
    [[ -n "$c" ]] && DOVECOT_MAILDIR_COL="$c"
    t="$(extract_table_from_query "$DOVECOT_USER_QUERY")"
    [[ -n "$t" ]] && DOVECOT_TABLE="$t"
    c="$(extract_email_col_from_query "$DOVECOT_USER_QUERY")"
    [[ -n "$c" ]] && DOVECOT_EMAIL_COL="$c"
  fi

  if [[ -n "$DOVECOT_DRIVER" && -n "$DOVECOT_CONNECT" ]]; then
    DOVECOT_DSN="$(build_dsn "$DOVECOT_DRIVER" "$DOVECOT_CONNECT")"
  fi
fi

if [[ "$DOVECOT_AUTH_MODE" == "sql" ]]; then
  if [[ -z "$DOVECOT_DRIVER" || -z "$DOVECOT_DSN" ]]; then
    warn "Could not fully auto-detect Dovecot SQL writable credentials."
    if prompt_yes_no "Enter Dovecot SQL settings manually now?" 0; then
      DOVECOT_DRIVER="$(prompt_input "Dovecot auth DB driver (mysql or pgx)" "mysql")"
      DOVECOT_DRIVER="$(lower "$DOVECOT_DRIVER")"
      DOVECOT_DSN="$(prompt_input "Dovecot auth DB DSN")"
      DOVECOT_TABLE="$(prompt_input "Dovecot auth table" "$DOVECOT_TABLE")"
      DOVECOT_EMAIL_COL="$(prompt_input "Email/login column" "$DOVECOT_EMAIL_COL")"
      DOVECOT_PASS_COL="$(prompt_input "Password hash column" "$DOVECOT_PASS_COL")"
      DOVECOT_ACTIVE_COL="$(prompt_input "Active/enabled column (blank if none)" "$DOVECOT_ACTIVE_COL")"
      DOVECOT_MAILDIR_COL="$(prompt_input "Maildir column (blank if none)" "$DOVECOT_MAILDIR_COL")"
    else
      warn "Dovecot SQL provisioning will remain disabled until configured in .env"
    fi
  fi
else
  DOVECOT_DRIVER=""
  DOVECOT_DSN=""
  DOVECOT_ACTIVE_COL=""
  DOVECOT_MAILDIR_COL=""
  log "PAM auth mode selected. Dovecot SQL provisioning is disabled."
fi

IMAP_PORT="$(detect_imap_port)"
SMTP_PORT="$(detect_smtp_port)"
IMAP_TLS="true"
IMAP_STARTTLS="false"
if [[ "$IMAP_PORT" == "143" ]]; then
  IMAP_TLS="false"
  IMAP_STARTTLS="true"
fi
SMTP_TLS="false"
SMTP_STARTTLS="true"
if [[ "$SMTP_PORT" == "465" ]]; then
  SMTP_TLS="true"
  SMTP_STARTTLS="false"
fi
if [[ "$SMTP_PORT" == "25" ]]; then
  SMTP_STARTTLS="false"
fi

SESSION_KEY="$(generate_secret)"
APP_DB_PATH="./data/app.db"
if [[ "$INSTALL_SERVICE" -eq 1 ]]; then
  APP_DB_PATH="/var/lib/mailclient/app.db"
fi

cp "$ENV_EXAMPLE" "$OUT_ENV"
set_env_var "$OUT_ENV" "BASE_DOMAIN" "$BASE_DOMAIN"
set_env_var "$OUT_ENV" "LISTEN_ADDR" "$LISTEN_ADDR"
set_env_var "$OUT_ENV" "APP_DB_PATH" "$APP_DB_PATH"
set_env_var "$OUT_ENV" "SESSION_ENCRYPT_KEY" "$SESSION_KEY"
set_env_var "$OUT_ENV" "COOKIE_SECURE" "true"
set_env_var "$OUT_ENV" "DEPLOY_MODE" "$DEPLOY_MODE"
set_env_var "$OUT_ENV" "DOVECOT_AUTH_MODE" "$DOVECOT_AUTH_MODE"
if [[ "$PROXY_SETUP" -eq 1 ]]; then
  set_env_var "$OUT_ENV" "TRUST_PROXY" "true"
fi

set_env_var "$OUT_ENV" "IMAP_HOST" "127.0.0.1"
set_env_var "$OUT_ENV" "IMAP_PORT" "$IMAP_PORT"
set_env_var "$OUT_ENV" "IMAP_TLS" "$IMAP_TLS"
set_env_var "$OUT_ENV" "IMAP_STARTTLS" "$IMAP_STARTTLS"
set_env_var "$OUT_ENV" "SMTP_HOST" "127.0.0.1"
set_env_var "$OUT_ENV" "SMTP_PORT" "$SMTP_PORT"
set_env_var "$OUT_ENV" "SMTP_TLS" "$SMTP_TLS"
set_env_var "$OUT_ENV" "SMTP_STARTTLS" "$SMTP_STARTTLS"

set_env_var "$OUT_ENV" "BOOTSTRAP_ADMIN_EMAIL" ""
set_env_var "$OUT_ENV" "BOOTSTRAP_ADMIN_PASSWORD" ""

if [[ -n "$DOVECOT_DRIVER" ]]; then
  set_env_var "$OUT_ENV" "DOVECOT_AUTH_DB_DRIVER" "$DOVECOT_DRIVER"
fi
if [[ -n "$DOVECOT_DSN" ]]; then
  set_env_var "$OUT_ENV" "DOVECOT_AUTH_DB_DSN" "$DOVECOT_DSN"
fi
set_env_var "$OUT_ENV" "DOVECOT_AUTH_TABLE" "$DOVECOT_TABLE"
set_env_var "$OUT_ENV" "DOVECOT_AUTH_EMAIL_COL" "$DOVECOT_EMAIL_COL"
set_env_var "$OUT_ENV" "DOVECOT_AUTH_PASS_COL" "$DOVECOT_PASS_COL"
set_env_var "$OUT_ENV" "DOVECOT_AUTH_ACTIVE_COL" "$DOVECOT_ACTIVE_COL"
set_env_var "$OUT_ENV" "DOVECOT_AUTH_MAILDIR_COL" "$DOVECOT_MAILDIR_COL"

log "Generated $OUT_ENV"
log "Detected IMAP 127.0.0.1:$IMAP_PORT and SMTP 127.0.0.1:$SMTP_PORT"
log "Deployment mode: $DEPLOY_MODE"
log "Dovecot auth mode: $DOVECOT_AUTH_MODE"
if [[ -n "$SQL_CONF" ]]; then
  log "Detected Dovecot SQL file: $SQL_CONF"
fi

if [[ "$INSTALL_SERVICE" -eq 0 ]]; then
  cat <<NEXT

Run locally:
  cd "$ROOT_DIR"
  go run ./cmd/server

Open:
  http://localhost:8080

The first web visit will launch OOBE where you set admin email/password.
Default admin email in OOBE is webmaster@${BASE_DOMAIN}.
NEXT
  exit 0
fi

ensure_service_dependencies "$OS_ID"
if ! have_cmd go; then
  err "Go toolchain is still unavailable after dependency checks."
  exit 1
fi

if [[ "$OS_ID" != "ubuntu" ]]; then
  warn "Proceeding with best-effort service install on non-Ubuntu Linux"
fi

if ! have_cmd systemctl; then
  err "systemd is required for automatic service install."
  exit 1
fi

PREFIX=()
if [[ "${EUID:-1}" -ne 0 ]]; then
  if ! have_cmd sudo; then
    err "sudo is required when running installer as non-root"
    exit 1
  fi
  PREFIX=(sudo)
fi

log "Building mailclient binary for linux/${GOARCH}"
(
  cd "$ROOT_DIR"
  GOOS=linux GOARCH="$GOARCH" go build -o "$ROOT_DIR/mailclient" ./cmd/server
)

"${PREFIX[@]}" mkdir -p /opt/mailclient /var/lib/mailclient
if ! id -u mailclient >/dev/null 2>&1; then
  "${PREFIX[@]}" useradd --system --home /var/lib/mailclient --shell /usr/sbin/nologin mailclient
fi

"${PREFIX[@]}" install -m 0755 "$ROOT_DIR/mailclient" /opt/mailclient/mailclient
"${PREFIX[@]}" install -m 0644 "$OUT_ENV" /opt/mailclient/.env
"${PREFIX[@]}" rm -rf /opt/mailclient/web /opt/mailclient/migrations
"${PREFIX[@]}" cp -R "$ROOT_DIR/web" /opt/mailclient/web
"${PREFIX[@]}" cp -R "$ROOT_DIR/migrations" /opt/mailclient/migrations
"${PREFIX[@]}" install -m 0644 "$ROOT_DIR/deploy/mailclient.service" /etc/systemd/system/mailclient.service
"${PREFIX[@]}" chown -R mailclient:mailclient /opt/mailclient /var/lib/mailclient

"${PREFIX[@]}" systemctl daemon-reload
"${PREFIX[@]}" systemctl enable --now mailclient

log "Service installed and started: mailclient"

apply_ufw_rules "$DEPLOY_MODE"
print_cloud_firewall_checklist "$DEPLOY_MODE"

if [[ "$PROXY_SETUP" -eq 1 ]]; then
  log "Configuring ${PROXY_SERVER} reverse proxy"
  APP_UPSTREAM="$LISTEN_ADDR"
  if [[ "$PROXY_SERVER" == "nginx" ]]; then
    setup_nginx_proxy "$PROXY_SERVER_NAME" "$APP_UPSTREAM" "$PROXY_TLS" "$PROXY_CERT" "$PROXY_KEY"
  else
    setup_apache_proxy "$PROXY_SERVER_NAME" "$APP_UPSTREAM" "$PROXY_TLS" "$PROXY_CERT" "$PROXY_KEY"
  fi
  log "Reverse proxy configured: ${PROXY_SERVER} (${PROXY_SERVER_NAME})"
  if [[ "$PROXY_SERVER" == "nginx" ]]; then
    log "Reverse proxy config path: /etc/nginx/sites-available/mailclient.conf"
  else
    log "Reverse proxy config path: /etc/apache2/sites-available/mailclient.conf"
  fi
fi

if ! "${PREFIX[@]}" systemctl is-active --quiet mailclient; then
  err "mailclient service is not active after install."
  err "Run: systemctl status mailclient --no-pager"
  exit 1
fi

if ! verify_direct_access "$LISTEN_ADDR"; then
  err "Local app health check failed on ${LISTEN_ADDR}."
  err "Run: /opt/mailclient/mailclient (or check /opt/mailclient/.env and service logs)"
  err "Run: journalctl -u mailclient -n 100 --no-pager"
  exit 1
fi

if [[ "$DEPLOY_MODE" == "proxy" ]]; then
  if ! verify_proxy_access "$PROXY_SERVER_NAME" "$PROXY_TLS"; then
    err "Reverse proxy health check failed for ${PROXY_SERVER_NAME}."
    err "Component likely failing: proxy routing or vhost mismatch."
    if [[ "$PROXY_SERVER" == "nginx" ]]; then
      err "Run: nginx -t && systemctl status nginx --no-pager"
    else
      err "Run: apache2ctl configtest && systemctl status apache2 --no-pager"
    fi
    err "Run: bash $ROOT_DIR/scripts/diagnose_access.sh"
    exit 1
  fi
fi

SERVER_IP="$(detect_primary_ip)"
cat <<DONE

Open in browser:
DONE
if [[ "$DEPLOY_MODE" == "proxy" ]]; then
  if [[ "$PROXY_TLS" == "1" ]]; then
    cat <<DONE
  https://${PROXY_SERVER_NAME}
DONE
  else
    cat <<DONE
  http://${PROXY_SERVER_NAME}
DONE
  fi
else
  cat <<DONE
  http://${SERVER_IP}:8080
DONE
fi
cat <<DONE

First-run OOBE is web-only and will ask for:
  - domain (pre-filled: ${BASE_DOMAIN})
  - admin email (default: webmaster@${BASE_DOMAIN})
  - admin password
DONE

if prompt_yes_no "Run Internet accessibility diagnostics now?" 1; then
  bash "$ROOT_DIR/scripts/diagnose_access.sh" || true
fi
