# UAT/Dev URL Deployment Runbook (Same VM)

## Goal
Run a separate UAT/dev stack on the same VM as production for safe testing and demos.

## Target URLs
- Prod: `https://nexus.nxlink.com`
- UAT/Dev (proposed): `https://nexus-dev.nxlink.com`

## Prerequisites
- DNS A record for `nexus-dev.nxlink.com` -> VM public IP.
- TLS cert available for dev hostname.
- Access to VM shell with Docker + Docker Compose.

## Isolation Model
- Keep prod and dev in separate compose projects.
- Use separate env files.
- Use different published ports for dev backend/frontend.
- Route by hostname in Nginx.

## Recommended VM Layout
- Prod compose project: `nexus`
- Dev compose project: `nexus-dev`
- Dev backend port example: `8001`
- Dev frontend port example: `8081` (if needed internally)

## Step 1: Create Dev Env File
Create `.env.dev` with dev-specific values:
- App env marker (`APP_ENV=dev` if supported)
- GitLab token and compliance URL
- Any non-prod credentials
- Distinct service/port values where applicable

Do not store secrets in git.

## Step 2: Bring Up Dev Stack
Example command:
```powershell
docker compose --env-file .env.dev -p nexus-dev up -d --build
```

## Step 3: Add Nginx Host Routing
Add a server block for the dev hostname and proxy to dev frontend/backend container ports.

Example mapping:
- `nexus.nxlink.com` -> existing prod upstream
- `nexus-dev.nxlink.com` -> dev upstream

## Step 4: Enable TLS
- Issue/attach cert for `nexus-dev.nxlink.com`.
- Reload Nginx.

## Step 5: Verify
1. Open dev URL and confirm banner clearly says `TESTING`/`DO NOT USE IN PRODUCTION`.
2. Run a sample generation and confirm expected output.
3. Verify compliance fetch works with dev env token.
4. Confirm prod behavior is unchanged.

## Optional Hardening
- Add HTTP basic auth on dev URL.
- Restrict dev URL by source IP (office/VPN ranges).
- Hide dev from public indexing.

## Operations Workflow
- Deploy new changes to dev first.
- Validate with test cases.
- Promote to prod only after pass criteria.

## Rollback
- If dev has issues:
```powershell
docker compose --env-file .env.dev -p nexus-dev down
```
- Revert Nginx dev block if required.

## Pass Criteria Before Using Dev with Team
- Dev URL resolves and serves valid TLS.
- Core tabs load: Home, MikroTik Config, Aviat Backhaul, FTTH, Command Vault.
- Config generation runs end-to-end.
- Compliance section is present and current.
- No impact to prod URL uptime.
