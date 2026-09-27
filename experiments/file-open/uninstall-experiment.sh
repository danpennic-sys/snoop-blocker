#!/bin/bash
# Independent uninstaller for File-Open Entryway Experiment (v0.7)
# Leaves locked baseline completely untouched.

set -euo pipefail

EXP_DIR=/opt/snoop-blocker-file-open
SANDBOX=/tmp/snoop-blocker-sandbox
UNIT=snoop-blocker-file-open.service

if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "[*] Stopping experiment service"
systemctl stop "$UNIT" 2>/dev/null || true
systemctl disable "$UNIT" 2>/dev/null || true
rm -f /etc/systemd/system/"$UNIT"
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed "$UNIT" 2>/dev/null || true

echo "[*] Removing experiment directory"
rm -rf "$EXP_DIR"

echo "[*] Removing sandbox"
rm -rf "$SANDBOX"

echo "[*] Checking for orphaned experiment processes"
if pgrep -f "file_open_watch.py" >/dev/null 2>&1; then
  echo "[!] Orphan found — killing"
  pkill -f "file_open_watch.py" || true
else
  echo "[+] No orphaned experiment processes"
fi

# Clean experiment logs
rm -f /tmp/snoop-blocker-file-open.log /tmp/snoop-blocker-file-open.state

echo "[+] Experiment uninstall complete"
echo "    Locked baseline (v0.6.1) was not modified"
