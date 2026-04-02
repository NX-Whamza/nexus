#!/bin/bash
# Quick extract script - Run this in ~/vm_deployment directory

echo "=========================================="
echo "Extracting NOC Config Maker Files"
echo "=========================================="
echo ""

# Check current directory
CURRENT_DIR=$(pwd)
echo "Current directory: $CURRENT_DIR"
echo ""

# Get the exact filename (avoid wildcard issues)
ARCHIVE_FILE=$(ls -1 noc-configmaker-vm-*.tar.gz 2>/dev/null | head -n 1)

if [ -z "$ARCHIVE_FILE" ]; then
    echo "❌ No archive file found in current directory!"
    echo ""
    echo "Files in current directory:"
    ls -lh
    echo ""
    echo "Looking for archive in home directory..."
    ARCHIVE_FILE=$(ls -1 ~/noc-configmaker-vm-*.tar.gz 2>/dev/null | head -n 1)
    
    if [ -z "$ARCHIVE_FILE" ]; then
        echo "❌ Archive not found in home directory either!"
        echo ""
        echo "Please find the archive file:"
        echo "  find ~ -name 'noc-configmaker-vm-*.tar.gz' -type f"
        exit 1
    else
        echo "✓ Found archive in home: $ARCHIVE_FILE"
        echo "Extracting to current directory ($CURRENT_DIR)..."
        tar -xzvf "$ARCHIVE_FILE"
    fi
else
    echo "✓ Found archive: $ARCHIVE_FILE"
    echo "File size: $(ls -lh "$ARCHIVE_FILE" | awk '{print $5}')"
    echo "Extracting to current directory..."
    echo ""
    tar -xzvf "$ARCHIVE_FILE"
fi

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Extraction complete!"
    echo ""
    echo "Files extracted. Next steps:"
    echo "  cd ~/noc-configmaker"
    echo "  docker compose up -d --build"
    echo "  bash vm_deployment/configure_nginx_domain.sh"
    echo ""
else
    echo ""
    echo "❌ Extraction failed! Check the errors above."
    exit 1
fi
