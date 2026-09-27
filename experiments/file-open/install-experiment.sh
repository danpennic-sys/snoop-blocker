#!/bin/bash
# Independent installer for File-Open Entryway Experiment (v0.7)
# Does NOT touch the locked v0.6.1 baseline service.

set -euo pipefail

EXP_DIR=/opt/snoop-blocker-file-open
SANDBOX=/tmp/snoop-blocker-sandbox
UNIT=snoop-blocker-file-open.service
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "[*] Installing experiment to $EXP_DIR"
mkdir -p "$EXP_DIR"
cp -f "$SRC_DIR/file_open_watch.py" "$EXP_DIR/"
chmod 755 "$EXP_DIR/file_open_watch.py"

# Optional local policy copy (experiment still prefers baseline /opt/snoop-blocker/policy.json)
if [[ -f /opt/snoop-blocker/policy.json ]]; then
  echo "[*] Baseline policy detected at /opt/snoop-blocker/policy.json (will be used)"
else
  echo "[*] No baseline policy found — experiment will use defaults"
fi

echo "[*] Creating sandbox target $SANDBOX"
mkdir -p "$SANDBOX"
echo "sandbox fixture $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$SANDBOX/fixture.txt"
chmod 755 "$SANDBOX"
chmod 644 "$SANDBOX/fixture.txt"

echo "[*] Installing experiment unit"
cat > /etc/systemd/system/"$UNIT" << EOF
[Unit]
Description=Snoop-Blocker File-Open Entryway Experiment (v0.7)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $EXP_DIR/file_open_watch.py
WorkingDirectory=$EXP_DIR
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ReadWritePaths=/tmp $EXP_DIR
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snoop-blocker-file-open

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$UNIT"
systemctl restart "$UNIT"
sleep 1
systemctl --no-pager -l status "$UNIT" || true

echo "[+] Experiment installed"
echo "    Binary:  $EXP_DIR/file_open_watch.py"
echo "    Sandbox: $SANDBOX"
echo "    Logs:    journalctl -u $UNIT -f"
echo "    Mode:    observation-only (log)"
