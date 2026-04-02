NOC Config Maker - VM Deployment

QUICK START:
1. SSH: ssh <user>@<vm-ip>
2. Update code: cd ~/noc-configmaker && git pull
3. Start or rebuild: docker compose up -d --build
4. Verify health: curl -fsS http://127.0.0.1:8000/api/health
5. Configure public domain: bash vm_deployment/configure_nginx_domain.sh
6. Access:
   - Local VM: http://127.0.0.1:8000/app
   - Public domain: https://noc-configmaker.nxlink.com

NOTES:
- Production uses Docker Compose, not a systemd backend service.
- Host nginx should proxy to the Docker frontend on port 8000.

