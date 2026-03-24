#!/usr/bin/env bash
# =============================================================================
# update_dev.sh — Pull latest main into dev clone and rebuild
# =============================================================================
# Production (~/noc-configmaker) is NEVER touched.
# Run this to test new changes before promoting to prod.
#
# USAGE (on the VM):
#   cd ~/noc-configmaker-dev && bash vm_deployment/update_dev.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${YELLOW}[INFO] $*${NC}"; }
ok()   { echo -e "${GREEN}[OK]   $*${NC}"; }

DEV_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEV_DIR"

generate_version_env() {
  info "Generating app version metadata..."
  python3 "$DEV_DIR/vm_deployment/generate_version_env.py" --output "$DEV_DIR/.version.env" >/dev/null
  set -a
  . "$DEV_DIR/.version.env"
  set +a
  ok "App version: ${NEXUS_APP_VERSION:-unknown}"
}

echo "=========================================="
echo "NOC Config Maker – DEV Update"
echo "Dir: $DEV_DIR"
echo "=========================================="
echo ""

# ── 1. Pull latest main ──
info "Pulling latest from origin/main..."
git pull origin main --ff-only
ok "Code updated to $(git rev-parse --short HEAD)"

# ── 2. Rebuild and restart dev containers ──
generate_version_env
info "Rebuilding dev containers..."
docker compose up -d --build
ok "Dev stack rebuilt and restarted"

# ── 3. Health check ──
echo ""
info "Waiting 10s for containers to start..."
sleep 10

DEV_PORT=$(grep -E '^FRONTEND_PORT=' "$DEV_DIR/.env" 2>/dev/null | cut -d= -f2 || echo "8100")
DEV_PORT="${DEV_PORT:-8100}"

info "Health check (port $DEV_PORT):"
if curl -fsS "http://127.0.0.1:${DEV_PORT}/api/health" | head -c 200; then
  echo ""
  ok "DEV is healthy at https://dev-noc-configmaker.nxlink.com"
else
  echo ""
  echo -e "${RED}[WARN] Health check failed — check logs:${NC}"
  echo "  cd $DEV_DIR && docker compose logs -f"
fi

echo ""
echo "=========================================="
echo "Production status (untouched):"
if [ -d "$HOME/noc-configmaker/.git" ]; then
  echo "  Commit: $(cd "$HOME/noc-configmaker" && git rev-parse --short HEAD)"
  echo "  (run 'bash vm_deployment/update_prod.sh' from ~/noc-configmaker to update prod)"
else
  echo "  ~/noc-configmaker not found"
fi
echo "=========================================="
