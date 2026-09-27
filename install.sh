#!/bin/bash
# Minimal offline installer for Snoop-Blocker Clone
# Run as root. Keeps clones identical.

set -euo pipefail

INSTALL_DIR=/opt/snoop-blocker
SERVICE_NAME=snoop-blocker.service

if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "[*] Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -f clone.py policy.json "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/clone.py"
chmod 644 "$INSTALL_DIR/policy.json"

echo "[*] Installing systemd unit"
cp -f snoop-blocker.service /etc/systemd/system/"$SERVICE_NAME"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo "[*] Starting"
systemctl restart "$SERVICE_NAME"
sleep 1
systemctl --no-pager -l status "$SERVICE_NAME" || true

echo "[+] Done. Logs: journalctl -u $SERVICE_NAME -f"
echo "    Policy:  $INSTALL_DIR/policy.json"
echo "    Mode:    $(python3 -c "import json; print(json.load(open('$INSTALL_DIR/policy.json'))['disrupt_mode'])")"
