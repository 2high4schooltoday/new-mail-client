#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="/opt/mailclient/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  ENV_FILE="$ROOT_DIR/.env"
fi

have_cmd() { command -v "$1" >/dev/null 2>&1; }
trim() {
  local s="$1"
  s="$(echo "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  printf '%s' "$s"
}

get_env() {
  local key="$1" default="${2:-}" line
  if [[ -f "$ENV_FILE" ]]; then
    line="$(grep -E "^${key}=" "$ENV_FILE" | tail -n1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s' "${line#*=}"
      return
    fi
  fi
  printf '%s' "$default"
}

first_error=""
record_fail() {
  local code="$1" reason="$2"
  if [[ -z "$first_error" ]]; then
    first_error="${code}:${reason}"
  fi
  printf '[FAIL] %s\n' "$reason"
}

record_ok() {
  printf '[ OK ] %s\n' "$1"
}

DEPLOY_MODE="$(trim "$(get_env DEPLOY_MODE "")")"
LISTEN_ADDR="$(trim "$(get_env LISTEN_ADDR ":8080")")"
BASE_DOMAIN="$(trim "$(get_env BASE_DOMAIN "")")"
if [[ -z "$DEPLOY_MODE" ]]; then
  if [[ "$LISTEN_ADDR" == 127.0.0.1:* ]]; then
    DEPLOY_MODE="proxy"
  else
    DEPLOY_MODE="direct"
  fi
fi

PROXY_SERVER=""
if [[ -f /etc/nginx/sites-available/mailclient.conf || -L /etc/nginx/sites-enabled/mailclient.conf ]]; then
  PROXY_SERVER="nginx"
elif [[ -f /etc/apache2/sites-available/mailclient.conf || -L /etc/apache2/sites-enabled/mailclient.conf ]]; then
  PROXY_SERVER="apache2"
fi

printf '=== Despatch Internet Access Diagnosis ===\n'
printf 'env_file=%s\n' "$ENV_FILE"
printf 'deploy_mode=%s\n' "$DEPLOY_MODE"
printf 'listen_addr=%s\n' "$LISTEN_ADDR"
if [[ -n "$BASE_DOMAIN" ]]; then
  printf 'base_domain=%s\n' "$BASE_DOMAIN"
fi
if [[ -n "$PROXY_SERVER" ]]; then
  printf 'proxy_server=%s\n' "$PROXY_SERVER"
fi
printf '\n'

if have_cmd systemctl; then
  if systemctl is-active --quiet mailclient; then
    record_ok "mailclient service is active"
  else
    record_fail 10 "APP_DOWN: mailclient service is inactive"
  fi
else
  printf '[WARN] systemctl not found; service state cannot be verified.\n'
fi

LOCAL_HEALTH="http://127.0.0.1:8080/health/live"
if [[ "$LISTEN_ADDR" =~ ^:([0-9]+)$ ]]; then
  LOCAL_HEALTH="http://127.0.0.1:${BASH_REMATCH[1]}/health/live"
elif [[ "$LISTEN_ADDR" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
  LOCAL_HEALTH="http://127.0.0.1:${BASH_REMATCH[1]}/health/live"
elif [[ "$LISTEN_ADDR" =~ ^0\.0\.0\.0:([0-9]+)$ ]]; then
  LOCAL_HEALTH="http://127.0.0.1:${BASH_REMATCH[1]}/health/live"
fi

if have_cmd curl && curl -fsS --max-time 6 "$LOCAL_HEALTH" >/dev/null; then
  record_ok "local app health check passed (${LOCAL_HEALTH})"
else
  record_fail 10 "APP_DOWN: local app health check failed (${LOCAL_HEALTH})"
fi

READY_URL="${LOCAL_HEALTH%/health/live}/health/ready"
if have_cmd curl; then
  ready_json="$(curl -fsS --max-time 8 "$READY_URL" || true)"
  if [[ -n "${ready_json:-}" ]]; then
    if echo "$ready_json" | grep -q '"imap"[[:space:]]*:[[:space:]]*{[^}]*"ok"[[:space:]]*:[[:space:]]*false'; then
      printf '[WARN] mail readiness: IMAP probe failed in /health/ready\n'
      printf '       Check IMAP_HOST/IMAP_PORT/IMAP_TLS/IMAP_STARTTLS and cert verification settings.\n'
    fi
    if echo "$ready_json" | grep -q '"smtp"[[:space:]]*:[[:space:]]*{[^}]*"ok"[[:space:]]*:[[:space:]]*false'; then
      printf '[WARN] mail readiness: SMTP probe failed in /health/ready\n'
      printf '       Check SMTP_HOST/SMTP_PORT/SMTP_TLS/SMTP_STARTTLS and cert verification settings.\n'
    fi
  fi
fi

if [[ "$DEPLOY_MODE" == "proxy" ]]; then
  if [[ -z "$PROXY_SERVER" ]]; then
    record_fail 20 "PROXY_DOWN: mailclient proxy config not found for nginx/apache2"
  fi

  if [[ "$PROXY_SERVER" == "nginx" ]]; then
    if have_cmd systemctl && systemctl is-active --quiet nginx; then
      record_ok "nginx service is active"
    else
      record_fail 20 "PROXY_DOWN: nginx service inactive"
    fi
  elif [[ "$PROXY_SERVER" == "apache2" ]]; then
    if have_cmd systemctl && systemctl is-active --quiet apache2; then
      record_ok "apache2 service is active"
    else
      record_fail 20 "PROXY_DOWN: apache2 service inactive"
    fi
  fi

  if have_cmd curl && [[ -n "$BASE_DOMAIN" ]]; then
    if curl -kfsS --max-time 6 --resolve "${BASE_DOMAIN}:443:127.0.0.1" "https://${BASE_DOMAIN}/health/live" >/dev/null \
      || curl -fsS --max-time 6 -H "Host: ${BASE_DOMAIN}" "http://127.0.0.1/health/live" >/dev/null; then
      record_ok "proxy route health check passed for ${BASE_DOMAIN}"
    else
      record_fail 21 "PROXY_MISROUTE: proxy does not route ${BASE_DOMAIN} to app health endpoint"
    fi
  else
    printf '[WARN] curl or BASE_DOMAIN missing; proxy route check skipped.\n'
  fi
fi

printf '\n--- Listening ports ---\n'
if have_cmd ss; then
  ss -ltnp | awk 'NR==1 || /:80 |:443 |:8080 |:25 |:143 |:465 |:587 |:993 /'
elif have_cmd netstat; then
  netstat -ltnp 2>/dev/null | awk 'NR==1 || /:80 |:443 |:8080 |:25 |:143 |:465 |:587 |:993 /'
else
  printf '[WARN] ss/netstat not available.\n'
fi

printf '\n--- Firewall (ufw) ---\n'
if have_cmd ufw; then
  ufw status || true
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    if [[ "$DEPLOY_MODE" == "proxy" ]]; then
      if ufw status 2>/dev/null | grep -Eq '(^|[[:space:]])80(/tcp)?[[:space:]].*ALLOW' \
        && ufw status 2>/dev/null | grep -Eq '(^|[[:space:]])443(/tcp)?[[:space:]].*ALLOW'; then
        record_ok "ufw allows 80/tcp and 443/tcp"
      else
        record_fail 30 "PORT_BLOCKED: ufw active but missing ALLOW for 80/443"
      fi
    else
      if ufw status 2>/dev/null | grep -Eq '(^|[[:space:]])8080(/tcp)?[[:space:]].*ALLOW'; then
        record_ok "ufw allows 8080/tcp"
      else
        record_fail 30 "PORT_BLOCKED: ufw active but missing ALLOW for 8080"
      fi
    fi
  fi
else
  printf '[INFO] ufw not installed.\n'
fi

printf '\n--- DNS ---\n'
if [[ -n "$BASE_DOMAIN" ]]; then
  resolved=""
  if have_cmd dig; then
    resolved="$(dig +short A "$BASE_DOMAIN" | head -n1 || true)"
  elif have_cmd getent; then
    resolved="$(getent ahostsv4 "$BASE_DOMAIN" | awk '{print $1}' | head -n1 || true)"
  fi
  resolved="$(trim "$resolved")"
  if [[ -n "$resolved" ]]; then
    printf '[INFO] %s resolves to %s\n' "$BASE_DOMAIN" "$resolved"
    public_ip=""
    if have_cmd curl; then
      public_ip="$(curl -fsS --max-time 4 https://api.ipify.org || true)"
      public_ip="$(trim "$public_ip")"
    fi
    if [[ -n "$public_ip" ]]; then
      printf '[INFO] this host public IP appears to be %s\n' "$public_ip"
      if [[ "$resolved" != "$public_ip" ]]; then
        record_fail 40 "DNS_MISMATCH: ${BASE_DOMAIN} does not resolve to this host public IP"
      else
        record_ok "DNS appears aligned with this host public IP"
      fi
    fi
  else
    printf '[WARN] could not resolve %s (dig/getent unavailable or no DNS record)\n' "$BASE_DOMAIN"
  fi
else
  printf '[WARN] BASE_DOMAIN not set; DNS check skipped.\n'
fi

printf '\n=== Result ===\n'
if [[ -z "$first_error" ]]; then
  printf '[ OK ] Healthy: Internet access path looks good.\n'
  exit 0
fi

code="${first_error%%:*}"
reason="${first_error#*:}"
printf '[FAIL] first_error=%s (%s)\n' "$code" "$reason"
case "$code" in
  10) printf 'Next: check app logs -> journalctl -u mailclient -n 100 --no-pager\n' ;;
  20) printf 'Next: check proxy service status/config test.\n' ;;
  21) printf 'Next: verify proxy server_name/vhost routes to 127.0.0.1:8080.\n' ;;
  30) printf 'Next: open required firewall ports (ufw/security groups).\n' ;;
  40) printf 'Next: update DNS A record to this server public IP.\n' ;;
esac
exit "$code"
