#!/usr/bin/env bash
# =============================================================================
# setup_dev.sh — One-time DEV environment bootstrap on the VM
# =============================================================================
# Creates a SEPARATE clone of the repo at ~/noc-configmaker-dev/ tracking
# the same 'main' branch as production.
#
# Both directories track main — the difference is WHEN you pull:
#   1. Push to main on GitHub
#   2. Pull into ~/noc-configmaker-dev/ first → test
#   3. When happy, pull into ~/noc-configmaker/ → production updated
#
# Architecture:
#   ~/noc-configmaker/      → PRODUCTION  (main, port 8000)
#   ~/noc-configmaker-dev/  → DEVELOPMENT (main, port 8100)
#
# USAGE (on the VM):
#   bash ~/noc-configmaker/vm_deployment/setup_dev.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${YELLOW}[INFO] $*${NC}"; }
ok()   { echo -e "${GREEN}[OK]   $*${NC}"; }
err()  { echo -e "${RED}[ERR]  $*${NC}"; }

REPO_URL="https://github.com/NX-Whamza/noc-configmaker.git"
DEV_DIR="$HOME/noc-configmaker-dev"

generate_version_env() {
  info "Generating app version metadata..."
  python3 "$DEV_DIR/vm_deployment/generate_version_env.py" --output "$DEV_DIR/.version.env" >/dev/null
  set -a
  . "$DEV_DIR/.version.env"
  set +a
  ok "App version: ${NEXUS_APP_VERSION:-unknown}"
}

echo "=========================================="
echo "NOC Config Maker – DEV Environment Setup"
echo "=========================================="
echo ""
echo "  Production:  ~/noc-configmaker      (main, :8000)"
echo "  Development: ~/noc-configmaker-dev   (main, :8100)"
echo ""

# ── 1. Clone (or update) the dev copy ──
if [ -d "$DEV_DIR/.git" ]; then
  ok "Dev clone already exists at $DEV_DIR"
  cd "$DEV_DIR"
  info "Pulling latest main..."
  git pull origin main --ff-only
else
  info "Cloning repo to $DEV_DIR..."
  git clone "$REPO_URL" "$DEV_DIR"
  cd "$DEV_DIR"
fi
ok "Dev clone at $DEV_DIR (commit: $(git rev-parse --short HEAD))"

# ── 2. Create secure_data dir (dev has its own, isolated from prod) ──
mkdir -p "$DEV_DIR/secure_data"
chmod 700 "$DEV_DIR/secure_data"
ok "secure_data/ created (isolated from production)"

# ── 3. Create .env for the dev clone ──
if [ ! -f "$DEV_DIR/.env" ]; then
  if [ -f "$DEV_DIR/ENV_DEV_TEMPLATE.txt" ]; then
    cp "$DEV_DIR/ENV_DEV_TEMPLATE.txt" "$DEV_DIR/.env"
    chmod 600 "$DEV_DIR/.env"
    ok "Created .env from template (FRONTEND_PORT=8100, NOC_ENVIRONMENT=dev)"
    echo ""
    echo -e "${RED}  ╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}  ║  ACTION REQUIRED: Fill in all CHANGE_ME values in .env  ║${NC}"
    echo -e "${RED}  ║  Real credentials are NOT stored in the template.       ║${NC}"
    echo -e "${RED}  ║  Copy values from the production .env or 1Password.     ║${NC}"
    echo -e "${RED}  ╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    info "  Edit now: nano $DEV_DIR/.env"
    info "  Then re-run this script or: cd $DEV_DIR && docker compose up -d --build"
  else
    err "ENV_DEV_TEMPLATE.txt not found in dev clone!"
    exit 1
  fi
else
  ok ".env already exists in dev clone"
fi

# ── 4. Configure host nginx for dev domain ──
info "Setting up nginx for dev-noc-configmaker.nxlink.com → :8100..."
bash "$DEV_DIR/vm_deployment/configure_nginx_dev_domain.sh"

# ── 5. Build and start dev stack ──
info "Building and starting the dev Docker stack..."
cd "$DEV_DIR"
generate_version_env
docker compose up -d --build

echo ""
echo "=========================================="
ok "DEV environment is live!"
echo "=========================================="
echo ""
echo "  DEV URL:     https://dev-noc-configmaker.nxlink.com"
echo "  DEV dir:     $DEV_DIR"
echo "  DEV data:    $DEV_DIR/secure_data/  (isolated from prod)"
echo ""
echo "  PROD URL:    https://noc-configmaker.nxlink.com"
echo "  PROD dir:    ~/noc-configmaker"
echo "  PROD data:   ~/noc-configmaker/secure_data/"
echo ""
echo "  Update dev:  cd $DEV_DIR && bash vm_deployment/update_dev.sh"
echo "  Update prod: cd ~/noc-configmaker && bash vm_deployment/update_prod.sh"
echo "  Dev logs:    cd $DEV_DIR && docker compose logs -f"
echo "  Stop dev:    cd $DEV_DIR && docker compose down"
echo ""
