#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────
# update_env_gitlab.sh — Patch .env with GitLab compliance vars
#
# Run ON THE VM:
#   cd ~/nexus && bash update_env_gitlab.sh
#
# What it does:
#   1. Checks if .env exists (creates from ENV_TEMPLATE.txt if needed)
#   2. Adds/updates ALL GitLab compliance vars
#   3. Backs up the original as .env.bak.<timestamp>
#   4. Rebuilds Docker containers to pick up the new vars
#   5. Verifies compliance is pulling from GitLab
# ───────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")" || cd ~/nexus

ENV_FILE=".env"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP=".env.bak.${TIMESTAMP}"

echo "=== GitLab Compliance .env Updater ==="
echo "  Directory: $(pwd)"
echo "  Time:      $(date)"
echo ""

# ── Step 1: Ensure .env exists ────────────────────────────────────
if [ ! -f "$ENV_FILE" ]; then
    echo "⚠  No .env file found."
    if [ -f "ENV_TEMPLATE.txt" ]; then
        echo "   Creating from ENV_TEMPLATE.txt..."
        cp ENV_TEMPLATE.txt "$ENV_FILE"
    else
        echo "   Creating empty .env..."
        touch "$ENV_FILE"
    fi
fi

# ── Step 2: Backup ────────────────────────────────────────────────
cp "$ENV_FILE" "$BACKUP"
echo "✓  Backed up to $BACKUP"

# ── Step 3: Prompt for token if not already set ───────────────────
CURRENT_TOKEN=$(grep -oP '(?<=^GITLAB_COMPLIANCE_TOKEN=).*' "$ENV_FILE" 2>/dev/null || echo "")

if [ -z "$CURRENT_TOKEN" ] || [ "$CURRENT_TOKEN" = "CHANGE_ME" ]; then
    echo ""
    echo "─── GitLab Token Required ───"
    echo "  Go to: https://tested.nxlink.com/-/user_settings/personal_access_tokens"
    echo "  Create a token with: read_repository, read_api scopes"
    echo ""
    read -rp "  Paste your GitLab Personal Access Token: " NEW_TOKEN
    if [ -z "$NEW_TOKEN" ]; then
        echo "✗  No token provided. Aborting."
        exit 1
    fi
else
    NEW_TOKEN="$CURRENT_TOKEN"
    echo "✓  Existing token found: ***${NEW_TOKEN: -4}"
fi

# ── Step 4: Define the vars we need ───────────────────────────────
declare -A GITLAB_VARS=(
    ["GITLAB_COMPLIANCE_TOKEN"]="$NEW_TOKEN"
    ["GITLAB_COMPLIANCE_PROJECT_ID"]="75"
    ["GITLAB_COMPLIANCE_HOST"]="tested.nxlink.com"
    ["GITLAB_COMPLIANCE_REPO_PATH"]="netforge/compliance"
    ["GITLAB_COMPLIANCE_REF"]="main"
    ["GITLAB_COMPLIANCE_TTL"]="900"
    ["GITLAB_COMPLIANCE_SCRIPT_PATH"]="TX-ARv2.rsc"
)

# ── Step 5: Upsert each var into .env ─────────────────────────────
echo ""
echo "─── Updating .env ───"
for KEY in "${!GITLAB_VARS[@]}"; do
    VALUE="${GITLAB_VARS[$KEY]}"
    # Mask token in output
    if [ "$KEY" = "GITLAB_COMPLIANCE_TOKEN" ]; then
        DISPLAY="***${VALUE: -4}"
    else
        DISPLAY="$VALUE"
    fi

    if grep -q "^${KEY}=" "$ENV_FILE" 2>/dev/null; then
        # Update existing line (handles commented or uncommented)
        sed -i "s|^${KEY}=.*|${KEY}=${VALUE}|" "$ENV_FILE"
        echo "  ✓ Updated  $KEY = $DISPLAY"
    elif grep -q "^#.*${KEY}=" "$ENV_FILE" 2>/dev/null; then
        # Uncomment and set
        sed -i "s|^#.*${KEY}=.*|${KEY}=${VALUE}|" "$ENV_FILE"
        echo "  ✓ Enabled   $KEY = $DISPLAY"
    else
        # Append
        echo "${KEY}=${VALUE}" >> "$ENV_FILE"
        echo "  ✓ Added     $KEY = $DISPLAY"
    fi
done

# ── Step 6: Verify .env looks correct ─────────────────────────────
echo ""
echo "─── .env GitLab section ───"
grep "GITLAB_COMPLIANCE" "$ENV_FILE" | while IFS= read -r line; do
    KEY=$(echo "$line" | cut -d= -f1)
    if [ "$KEY" = "GITLAB_COMPLIANCE_TOKEN" ]; then
        VAL=$(echo "$line" | cut -d= -f2-)
        echo "  $KEY=***${VAL: -4}"
    else
        echo "  $line"
    fi
done

# ── Step 7: Pull latest code + rebuild Docker ────────────────────
echo ""
echo "─── Pulling latest code ───"
git pull origin main

echo ""
echo "─── Rebuilding Docker containers ───"
docker compose up -d --build

echo ""
echo "─── Waiting for backend to be healthy (30s) ───"
sleep 30

# ── Step 8: Verify compliance status ─────────────────────────────
echo ""
echo "─── Verifying compliance endpoints ───"

echo "  Backend (port 5000):"
RESULT=$(curl -s http://localhost:5000/api/compliance-status 2>/dev/null || echo '{"error":"unreachable"}')
echo "    $RESULT" | python3 -m json.tool 2>/dev/null || echo "    $RESULT"

echo ""
echo "  IDO Backend (port 18081):"
RESULT2=$(curl -s http://localhost:18081/api/ido/compliance/status 2>/dev/null || echo '{"error":"unreachable"}')
echo "    $RESULT2" | python3 -m json.tool 2>/dev/null || echo "    $RESULT2"

# ── Step 9: Force a fresh fetch to confirm GitLab connectivity ────
echo ""
echo "─── Forcing fresh compliance fetch ───"
curl -s -X POST http://localhost:5000/api/reload-compliance 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "(reload failed)"
curl -s -X POST http://localhost:18081/api/ido/compliance/refresh 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "(ido reload failed)"

# Re-check status after refresh
sleep 2
echo ""
echo "─── Final status check ───"
FINAL=$(curl -s http://localhost:5000/api/compliance-status 2>/dev/null || echo '{}')
SOURCE=$(echo "$FINAL" | python3 -c "import sys,json;print(json.load(sys.stdin).get('active_source','unknown'))" 2>/dev/null || echo "unknown")
CONFIGURED=$(echo "$FINAL" | python3 -c "import sys,json;print(json.load(sys.stdin).get('gitlab_configured',False))" 2>/dev/null || echo "unknown")
AVAILABLE=$(echo "$FINAL" | python3 -c "import sys,json;print(json.load(sys.stdin).get('gitlab_available',False))" 2>/dev/null || echo "unknown")

echo "  gitlab_configured: $CONFIGURED"
echo "  gitlab_available:  $AVAILABLE"
echo "  active_source:     $SOURCE"

echo ""
if [ "$SOURCE" = "gitlab" ]; then
    echo "============================================"
    echo "  ✓ SUCCESS: Compliance pulling from GitLab"
    echo "============================================"
else
    echo "============================================"
    echo "  ✗ WARNING: Still using hardcoded fallback"
    echo "    Check token validity and network access"
    echo "============================================"
fi
echo ""
echo "Done. Token last-used on GitLab should now show 'just now'."
