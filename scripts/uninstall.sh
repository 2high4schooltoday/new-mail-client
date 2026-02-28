#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err() { printf '[ERR ] %s\n' "$*" >&2; }

if [[ $# -ne 0 ]]; then
  err "This uninstaller is interactive and does not accept arguments. Run: ./scripts/uninstall.sh"
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

lower() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

trim() {
  local s="$1"
  # shellcheck disable=SC2001
  s="$(echo "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  printf '%s' "$s"
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

timestamp() {
  date +%Y%m%d-%H%M%S
}

backup_path() {
  local path="$1"
  local dst="/var/backups/mailclient/$(basename "$path").$(timestamp)"
  run_as_root mkdir -p /var/backups/mailclient
  if [[ -d "$path" ]]; then
    run_as_root cp -a "$path" "$dst"
  else
    run_as_root cp -a "$path" "$dst"
  fi
  log "Backup created: $dst"
}

safe_systemctl() {
  local action="$1" unit="$2"
  if have_cmd systemctl; then
    run_as_root systemctl "$action" "$unit" >/dev/null 2>&1 || true
  fi
}

cleanup_nginx_proxy() {
  local conf="/etc/nginx/sites-available/mailclient.conf"
  local enabled="/etc/nginx/sites-enabled/mailclient.conf"

  if [[ ! -f "$conf" && ! -L "$enabled" ]]; then
    warn "Nginx mailclient site config not found; skipping."
    return
  fi

  run_as_root rm -f "$enabled" "$conf"
  if have_cmd nginx; then
    run_as_root nginx -t
    safe_systemctl reload nginx
  fi
  log "Removed mailclient nginx site config."
}

cleanup_apache_proxy() {
  local conf="/etc/apache2/sites-available/mailclient.conf"
  if [[ ! -f "$conf" ]]; then
    warn "Apache2 mailclient site config not found; skipping."
    return
  fi

  if have_cmd a2dissite; then
    run_as_root a2dissite mailclient.conf >/dev/null 2>&1 || true
  fi
  run_as_root rm -f "$conf"
  if have_cmd apache2ctl; then
    run_as_root apache2ctl configtest
    safe_systemctl reload apache2
  fi
  log "Removed mailclient apache2 site config."
}

remove_path_if_exists() {
  local p="$1"
  if [[ -e "$p" ]]; then
    run_as_root rm -rf "$p"
    log "Removed: $p"
  else
    warn "Not found: $p"
  fi
}

remove_mailclient_user() {
  if id -u mailclient >/dev/null 2>&1; then
    run_as_root userdel mailclient >/dev/null 2>&1 || true
    log "Removed system user: mailclient"
  else
    warn "System user mailclient not found; skipping."
  fi
}

log "Despatch interactive uninstaller"
warn "This removes only Despatch-managed artifacts."
warn "It does NOT remove Postfix, Dovecot, Nginx, Apache2, databases, or TLS packages."

if ! prompt_yes_no "Continue with uninstall?" 0; then
  err "Aborted"
  exit 1
fi

if [[ -f /opt/mailclient/.env ]] && prompt_yes_no "Backup /opt/mailclient/.env before removal?" 1; then
  backup_path /opt/mailclient/.env
fi

if [[ -d /var/lib/mailclient ]] && prompt_yes_no "Backup /var/lib/mailclient before removal?" 1; then
  backup_path /var/lib/mailclient
fi

log "Removing service files..."
if have_cmd systemctl; then
  safe_systemctl stop mailclient
  safe_systemctl disable mailclient
  if [[ -f /etc/systemd/system/mailclient.service ]]; then
    run_as_root rm -f /etc/systemd/system/mailclient.service
  fi
  run_as_root systemctl daemon-reload
else
  warn "systemctl not found; skipping systemd removal."
fi

if prompt_yes_no "Remove installed app files from /opt/mailclient ?" 1; then
  remove_path_if_exists /opt/mailclient
fi

if prompt_yes_no "Remove app data from /var/lib/mailclient ?" 1; then
  remove_path_if_exists /var/lib/mailclient
fi

if prompt_yes_no "Remove system user 'mailclient'?" 1; then
  remove_mailclient_user
fi

if prompt_yes_no "Remove mailclient reverse-proxy site config from Nginx (if present)?" 1; then
  cleanup_nginx_proxy
fi

if prompt_yes_no "Remove mailclient reverse-proxy site config from Apache2 (if present)?" 1; then
  cleanup_apache_proxy
fi

if [[ -d /opt/mailclient-installer ]] && prompt_yes_no "Remove standalone installer checkout /opt/mailclient-installer ?" 0; then
  remove_path_if_exists /opt/mailclient-installer
fi

cat <<DONE

Uninstall complete.

Not touched:
  - Postfix services/config
  - Dovecot services/config
  - Nginx/Apache2 packages (only optional mailclient site entries)
  - Dovecot auth database
  - TLS/certbot packages and certificates

DONE
