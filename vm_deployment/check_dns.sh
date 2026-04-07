#!/bin/bash
# Check DNS configuration for nexus.nxlink.com

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "=========================================="
echo "DNS Check for nexus.nxlink.com"
echo "=========================================="
echo ""

# Get VM's public IP
echo -e "${YELLOW}VM's IP addresses:${NC}"
hostname -I
echo ""

# Check what DNS resolves to
echo -e "${YELLOW}Checking DNS resolution:${NC}"
echo "From public DNS servers:"
dig +short nexus.nxlink.com @8.8.8.8 || nslookup nexus.nxlink.com 8.8.8.8
echo ""

echo "From Cloudflare DNS:"
dig +short nexus.nxlink.com @1.1.1.1 || nslookup nexus.nxlink.com 1.1.1.1
echo ""

# Check if it resolves to this VM
VM_IP=$(hostname -I | awk '{print $1}')
DNS_IP=$(dig +short nexus.nxlink.com @8.8.8.8 | head -1)

if [ -z "$DNS_IP" ]; then
    echo -e "${RED}✗${NC} DNS record not found or not propagated yet"
    echo ""
    echo -e "${YELLOW}You need to add an A record at your DNS provider:${NC}"
    echo "  Host: nexus"
    echo "  Type: A"
    echo "  Value: 192.168.11.118 (or your VM's public IP)"
    echo ""
    echo "If 192.168.11.118 is a private IP, you need your VM's PUBLIC IP instead."
elif [ "$DNS_IP" = "$VM_IP" ] || [ "$DNS_IP" = "192.168.11.118" ]; then
    echo -e "${GREEN}✓${NC} DNS is pointing to this VM ($DNS_IP)"
else
    echo -e "${YELLOW}⚠${NC} DNS resolves to: $DNS_IP"
    echo -e "${YELLOW}⚠${NC} But this VM's IP is: $VM_IP"
    echo "They don't match - check your DNS configuration."
fi

echo ""
echo "=========================================="
