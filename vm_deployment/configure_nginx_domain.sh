#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-nexus.nxlink.com}"
IP_ADDR="${IP_ADDR:-192.168.11.118}"

# Repo docker-compose exposes the frontend container on host port 8000.
# The frontend Nginx proxies /api/* to the backend container.
UPSTREAM_URL="${UPSTREAM_URL:-http://127.0.0.1:8000}"

CONFIG_NAME="nexus-domain"
CONFIG_PATH="/etc/nginx/sites-available/${CONFIG_NAME}"
ENABLED_PATH="/etc/nginx/sites-enabled/${CONFIG_NAME}"

WEBROOT="/var/www/html"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
EMAIL="${EMAIL:-netops@team.nxlink.com}"

MANUAL_CERT="/etc/nginx/ssl/nxlink-com.pem"
MANUAL_KEY="/etc/nginx/ssl/nxlink-com.key"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${YELLOW}[INFO] $*${NC}"; }
ok() { echo -e "${GREEN}[OK] $*${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $*${NC}"; }
error() { echo -e "${RED}[ERROR] $*${NC}"; }

require_commands() {
  local missing=()
  for cmd in bash sudo systemctl nginx curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if ((${#missing[@]} > 0)); then
    error "Missing required command(s): ${missing[*]}"
    exit 1
  fi
}

write_proxy_block() {
  cat <<BLOCK
    proxy_connect_timeout 300s;
    proxy_send_timeout 300s;
    proxy_read_timeout 300s;
    send_timeout 300s;

    location / {
        proxy_pass ${UPSTREAM_URL};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }
BLOCK
}

generate_http_config() {
  sudo tee "$CONFIG_PATH" >/dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} ${IP_ADDR};

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
        try_files \$uri =404;
    }

$(write_proxy_block)
}
EOF
}

generate_https_config() {
  local cert_path="$1"
  local key_path="$2"

  sudo tee "$CONFIG_PATH" >/dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} ${IP_ADDR};

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
        try_files \$uri =404;
    }

    location / {
        # Preserve method/body (avoid POST->GET causing 405s).
        return 308 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     ${cert_path};
    ssl_certificate_key ${key_path};
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
        try_files \$uri =404;
    }

$(write_proxy_block)
}
EOF
}

attempt_certbot() {
  info "Requesting Let's Encrypt certificate for ${DOMAIN}..."
  if sudo certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" --non-interactive --agree-tos --email "$EMAIL" >/tmp/certbot.log 2>&1; then
    ok "Certificate issued. Logs: /tmp/certbot.log"
    return 0
  fi
  warn "Certificate issuance failed (see /tmp/certbot.log). Ensure DNS A record points to this server."
  return 1
}

configure_firewall() {
  if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
    info "Opening HTTP/HTTPS ports in ufw..."
    sudo ufw allow 80/tcp comment "HTTP - NEXUS" >/dev/null 2>&1 || true
    sudo ufw allow 443/tcp comment "HTTPS - NEXUS" >/dev/null 2>&1 || true
    ok "Firewall rules updated (ports 80 and 443)."
  fi
}

print_header() {
  echo "=========================================="
  echo "Nginx Domain Configuration"
  echo "Domain: ${DOMAIN}"
  echo "Upstream: ${UPSTREAM_URL}"
  echo "=========================================="
  echo ""
}

print_header
require_commands

if [ "$EUID" -eq 0 ]; then
  error "Do not run as root; this script uses sudo when needed."
  exit 1
fi

sudo mkdir -p "$WEBROOT"

CERT_PATH=""
KEY_PATH=""
MANUAL_USED=false

if [[ -f "$MANUAL_CERT" && -f "$MANUAL_KEY" ]]; then
  CERT_PATH="$MANUAL_CERT"
  KEY_PATH="$MANUAL_KEY"
  MANUAL_USED=true
  ok "Using manual certificate from /etc/nginx/ssl."
elif [[ -d "$CERT_DIR" ]]; then
  CERT_PATH="${CERT_DIR}/fullchain.pem"
  KEY_PATH="${CERT_DIR}/privkey.pem"
  ok "Using existing Let's Encrypt certificate."
else
  warn "No certificate found yet. Starting with HTTP-only proxy."
fi

if [[ -n "$CERT_PATH" && -n "$KEY_PATH" ]]; then
  info "Generating HTTPS nginx configuration..."
  generate_https_config "$CERT_PATH" "$KEY_PATH"
else
  info "Generating HTTP nginx configuration..."
  generate_http_config
fi

info "Enabling site configuration..."
sudo ln -sf "$CONFIG_PATH" "$ENABLED_PATH"
sudo rm -f /etc/nginx/sites-enabled/default >/dev/null 2>&1 || true

info "Testing nginx configuration..."
sudo nginx -t
ok "nginx configuration is valid."

info "Reloading nginx..."
sudo systemctl reload nginx

if [[ "$MANUAL_USED" == false && -z "$CERT_PATH" ]]; then
  if ! command -v certbot >/dev/null 2>&1; then
    warn "Certbot not found; installing..."
    sudo apt update
    sudo apt install -y certbot python3-certbot-nginx >/dev/null
    ok "Certbot installed."
  fi

  if attempt_certbot; then
    CERT_PATH="${CERT_DIR}/fullchain.pem"
    KEY_PATH="${CERT_DIR}/privkey.pem"
    info "Switching nginx to HTTPS..."
    generate_https_config "$CERT_PATH" "$KEY_PATH"
    sudo nginx -t
    sudo systemctl reload nginx
    ok "HTTPS configuration active."
  else
    warn "Continuing with HTTP only. Run this script again after DNS propagation."
  fi
else
  if command -v certbot >/dev/null 2>&1; then
    info "Renewing certificate (if due)..."
    sudo certbot renew --webroot -w "$WEBROOT" --quiet >/tmp/certbot-renew.log 2>&1 || warn "Certificate renewal log: /tmp/certbot-renew.log"
  fi
fi

configure_firewall

echo ""
echo "=========================================="
echo "Configuration Complete!"
echo "=========================================="
echo ""

if [[ -n "$CERT_PATH" ]]; then
  ok "Reachable via https://${DOMAIN}"
else
  warn "HTTPS not configured yet."
  echo "http://${DOMAIN}"
  echo "http://${IP_ADDR}"
fi

echo ""
info "Upstream health check:"
curl -fsS "${UPSTREAM_URL}/api/health" | head -c 200 || warn "Upstream not reachable at ${UPSTREAM_URL} (start docker compose?)"

echo ""
info "If docker isn't running yet, start it from the repo root:"
echo "  cd ~/nexus && docker compose up -d --build"
