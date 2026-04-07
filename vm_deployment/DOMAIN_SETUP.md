# Domain Setup Guide: nexus.nxlink.com

Production runs through Docker Compose:
- Docker frontend listens on `127.0.0.1:8000`
- The backend stays internal to the Compose network
- Host nginx should proxy browser traffic to `127.0.0.1:8000`

## Quick Setup

Run these commands on the VM:

```bash
ssh <user>@<vm-ip>
cd ~/nexus
docker compose up -d --build
bash vm_deployment/configure_nginx_domain.sh
```

## What The Script Does

1. Creates or updates the host nginx site for `nexus.nxlink.com`
2. Proxies host nginx to the Docker frontend on port `8000`
3. Obtains or reuses TLS certificates when available
4. Enables HTTP to HTTPS redirect when certificates are configured
5. Opens ports `80` and `443` when `ufw` is active

## Verification

Check the Docker stack:

```bash
cd ~/nexus
docker compose ps
curl -fsS http://127.0.0.1:8000/api/health
```

Check nginx:

```bash
sudo nginx -t
sudo systemctl status nginx
```

Then open:

- `https://nexus.nxlink.com`

## Troubleshooting

If you see the default nginx page:
- Re-run `bash vm_deployment/configure_nginx_domain.sh`
- Run `sudo nginx -t && sudo systemctl reload nginx`

If the app is not responding:
- Run `cd ~/nexus && docker compose ps`
- Run `cd ~/nexus && docker compose logs --tail=200 backend frontend`
- Verify the local health endpoint: `curl -fsS http://127.0.0.1:8000/api/health`

If TLS setup fails:
- Verify DNS points to the correct public IP for the VM
- Re-run the domain setup script after DNS propagation completes

If you get connection errors:
- Run `sudo ufw status`
- Open ports if needed: `sudo ufw allow 80/tcp && sudo ufw allow 443/tcp`

## Manual Nginx Reload

```bash
sudo nano /etc/nginx/sites-available/nexus-domain
sudo nginx -t && sudo systemctl reload nginx
```

## Certificate Renewal

```bash
sudo certbot renew --dry-run
```
