#!/usr/bin/env bash
# Installs all runtime dependencies into the vendor/ folder.
# Run this from the project root:
#   ./scripts/vendor_install.sh
#
# The vendor/ directory is added to sys.path at runtime by
# src/netrecon/_vendor_bootstrap.py, so the app works without a
# virtual environment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENDOR_DIR="$PROJECT_ROOT/vendor"

echo "==> Cleaning existing vendor/ directory..."
rm -rf "$VENDOR_DIR"

echo "==> Installing dependencies into vendor/..."
pip install \
    --target="$VENDOR_DIR" \
    typer \
    rich \
    scapy \
    dnspython \
    httpx \
    python-whois \
    cryptography \
    PySide6

echo ""
echo "==> Done. Installed to: $VENDOR_DIR"
echo "    $(ls -1 "$VENDOR_DIR" | wc -l | tr -d ' ') items in vendor/"
