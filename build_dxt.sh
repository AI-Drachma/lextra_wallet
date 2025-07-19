#!/bin/bash
# Build nova_wallet.dxt with proper dependencies

echo "=( Building nova_wallet.dxt..."

# Remove old dxt file
rm -f nova_wallet.dxt

# Create the dxt file (which is just a zip)
zip -r nova_wallet.dxt . -x "*.git*" "*.venv*" "temp/*" "*.pyc" "__pycache__/*" ".pytest_cache/*" "tests/*" "*.cbor" "build_dxt.sh"

echo " Built nova_wallet.dxt successfully!"
echo "=æ File size: $(du -h nova_wallet.dxt | cut -f1)"

# Verify MCP is included
echo "= Verifying MCP packages are included:"
unzip -l nova_wallet.dxt | grep -c "mcp/" || echo "L MCP packages not found!"