#!/bin/bash
# Minimal offline uninstaller for Snoop-Blocker Clone
# Run as root. Leaves nothing behind except the original source tree.

set -euo pipefail

INSTALL_DIR=/opt/snoop-blocker
SERVICE_NAME=snoop-blocker.service

if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "[*] Stopping and disabling service"
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

echo "[*] Removing unit"
rm -f /etc/systemd/system/"$SERVICE_NAME"
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

echo "[*] Removing install directory"
rm -rf "$INSTALL_DIR"

echo "[*] Checking for orphaned processes"
if pgrep -f "/opt/snoop-blocker/clone.py" >/dev/null 2>&1; then
  echo "[!] Found leftover process — killing"
pkill -f "/opt/snoop-blocker/clone.py" || true
else
  echo "[+] No orphaned snoop-blocker processes"
fi

echo "[+] Uninstall complete"
echo "    Source tree (this directory) is untouched"
echo "    Policy and binary removed from $INSTALL_DIR"
