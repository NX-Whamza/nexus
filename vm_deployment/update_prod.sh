#!/usr/bin/env bash
# =============================================================================
# update_prod.sh — Pull latest main and rebuild PRODUCTION
# =============================================================================
# Run this ONLY after testing on dev (dev-nexus.nxlink.com).
#
# USAGE (on the VM):
#   cd ~/nexus && bash vm_deployment/update_prod.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${YELLOW}[INFO] $*${NC}"; }
ok()   { echo -e "${GREEN}[OK]   $*${NC}"; }
err()  { echo -e "${RED}[ERR]  $*${NC}"; }

PROD_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROD_DIR"

generate_version_env() {
  info "Generating app version metadata..."
  python3 "$PROD_DIR/vm_deployment/generate_version_env.py" --output "$PROD_DIR/.version.env" >/dev/null
  set -a
  . "$PROD_DIR/.version.env"
  set +a
  ok "App version: ${NEXUS_APP_VERSION:-unknown}"
}

echo "=========================================="
echo "NEXUS – PRODUCTION Update"
echo "Dir: $PROD_DIR"
echo "=========================================="
echo ""

# ── Safety: compare with dev to make sure you tested first ──
DEV_DIR="$HOME/nexus-dev"
if [ -d "$DEV_DIR/.git" ]; then
  DEV_COMMIT=$(cd "$DEV_DIR" && git rev-parse HEAD)
  REMOTE_COMMIT=$(git ls-remote origin main | cut -f1)
  
  if [ "$DEV_COMMIT" != "$REMOTE_COMMIT" ]; then
    echo -e "${YELLOW}[WARN] Dev clone is at a different commit than origin/main.${NC}"
    echo "  Dev:    $(cd "$DEV_DIR" && git rev-parse --short HEAD)"
    echo "  Remote: $(echo "$REMOTE_COMMIT" | cut -c1-7)"
    echo ""
    read -p "Continue updating prod anyway? (y/N) " -r
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
      echo "Aborted. Update dev first: cd $DEV_DIR && bash vm_deployment/update_dev.sh"
      exit 0
    fi
  else
    ok "Dev clone matches origin/main — safe to proceed"
  fi
fi

# ── 1. Pull latest main ──
BEFORE=$(git rev-parse --short HEAD)
info "Pulling latest from origin/main..."
git pull origin main --ff-only
AFTER=$(git rev-parse --short HEAD)

if [ "$BEFORE" = "$AFTER" ]; then
  ok "Already up to date ($AFTER)"
else
  ok "Updated: $BEFORE → $AFTER"
fi

# ── 2. Rebuild production containers ──
generate_version_env
info "Rebuilding production containers..."
docker compose up -d --build
ok "Production stack rebuilt"
docker compose ps

# ── 3. Health check ──
echo ""
info "Waiting for production health (up to 90s)..."
HEALTH_URL="http://127.0.0.1:8000/api/health"
HEALTH_OK=0
for _ in $(seq 1 18); do
  if curl -fsS "$HEALTH_URL" | head -c 200; then
    HEALTH_OK=1
    break
  fi
  sleep 5
done

echo ""
if [ "$HEALTH_OK" -eq 1 ]; then
  ok "PRODUCTION is healthy at https://nexus.nxlink.com"
  info "Backend health payload:"
  curl -fsS "$HEALTH_URL" | head -c 1200
  echo ""
else
  err "Health check failed after 90s. Check logs:"
  echo "  docker compose logs -f backend frontend"
fi

echo ""
echo "=========================================="
ok "Production update complete ($(git rev-parse --short HEAD))"
echo "=========================================="
