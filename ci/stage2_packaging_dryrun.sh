#!/bin/bash
# Stage 2 — Packaging dry-run only
# Isolated temp root. Never touches live /opt/snoop-blocker or real systemd.
# Fail closed if any write escapes the temp root.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPROOT="$(mktemp -d /tmp/snoop-blocker-stage2.XXXXXX)"
LIVE_OPT="/opt/snoop-blocker"
LIVE_UNIT="/etc/systemd/system/snoop-blocker.service"

cleanup() {
  rm -rf "$TMPROOT"
}
trap cleanup EXIT

echo "Snoop-Blocker Stage 2 packaging dry-run"
echo "ROOT=$ROOT"
echo "TMPROOT=$TMPROOT"

LIVE_OPT_BEFORE=""
LIVE_UNIT_BEFORE=""
if [[ -d "$LIVE_OPT" ]]; then
  LIVE_OPT_BEFORE="$(find "$LIVE_OPT" -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum | awk '{print $1}')"
  echo "  live /opt/snoop-blocker snapshot: $LIVE_OPT_BEFORE"
else
  echo "  live /opt/snoop-blocker: absent (ok)"
fi
if [[ -f "$LIVE_UNIT" ]]; then
  LIVE_UNIT_BEFORE="$(sha256sum "$LIVE_UNIT" | awk '{print $1}')"
  echo "  live unit snapshot: $LIVE_UNIT_BEFORE"
else
  echo "  live unit: absent (ok)"
fi

if [[ "$TMPROOT" == "$LIVE_OPT"* ]] || [[ "$TMPROOT" == /opt/* ]]; then
  echo "[FAIL] TMPROOT collides with live paths"
  exit 1
fi

echo "== Dry-run install =="
mkdir -p "$TMPROOT/opt/snoop-blocker"
mkdir -p "$TMPROOT/etc/systemd/system"

cp -f "$ROOT/clone.py" "$ROOT/policy.json" "$TMPROOT/opt/snoop-blocker/"
chmod 755 "$TMPROOT/opt/snoop-blocker/clone.py"
chmod 644 "$TMPROOT/opt/snoop-blocker/policy.json"

cp -f "$ROOT/snoop-blocker.service" "$TMPROOT/etc/systemd/system/snoop-blocker.service"

echo "  [OK] files copied into TMPROOT"

echo "== Verify layout =="
fail=0

require_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    echo "  [OK] present: ${f#$TMPROOT}"
  else
    echo "  [FAIL] missing: ${f#$TMPROOT}"
    fail=1
  fi
}

require_file "$TMPROOT/opt/snoop-blocker/clone.py"
require_file "$TMPROOT/opt/snoop-blocker/policy.json"
require_file "$TMPROOT/etc/systemd/system/snoop-blocker.service"

CL_MODE=$(stat -c '%a' "$TMPROOT/opt/snoop-blocker/clone.py" 2>/dev/null || stat -f '%OLp' "$TMPROOT/opt/snoop-blocker/clone.py")
PO_MODE=$(stat -c '%a' "$TMPROOT/opt/snoop-blocker/policy.json" 2>/dev/null || stat -f '%OLp' "$TMPROOT/opt/snoop-blocker/policy.json")
if [[ "$CL_MODE" == "755" ]]; then
  echo "  [OK] clone.py mode 755"
else
  echo "  [FAIL] clone.py mode want 755 got $CL_MODE"
  fail=1
fi
if [[ "$PO_MODE" == "644" ]]; then
  echo "  [OK] policy.json mode 644"
else
  echo "  [FAIL] policy.json mode want 644 got $PO_MODE"
  fail=1
fi

python3 -c "
import json, sys
p=json.load(open('$TMPROOT/opt/snoop-blocker/policy.json'))
assert p.get('disrupt_mode') in ('log','freeze','kill'), p.get('disrupt_mode')
print('  [OK] policy.json valid disrupt_mode=' + p['disrupt_mode'])
"

UNIT="$TMPROOT/etc/systemd/system/snoop-blocker.service"
if grep -q 'ExecStart=/usr/bin/python3 /opt/snoop-blocker/clone.py' "$UNIT"; then
  echo "  [OK] unit ExecStart points at /opt/snoop-blocker/clone.py"
else
  echo "  [FAIL] unit ExecStart incorrect"
  fail=1
fi
if grep -q 'WorkingDirectory=/opt/snoop-blocker' "$UNIT"; then
  echo "  [OK] unit WorkingDirectory=/opt/snoop-blocker"
else
  echo "  [FAIL] unit WorkingDirectory incorrect"
  fail=1
fi

echo "== Dry-run uninstall =="
rm -rf "$TMPROOT/opt/snoop-blocker"
rm -f "$TMPROOT/etc/systemd/system/snoop-blocker.service"

if [[ ! -e "$TMPROOT/opt/snoop-blocker" ]]; then
  echo "  [OK] temp install dir removed"
else
  echo "  [FAIL] temp install dir still present"
  fail=1
fi
if [[ ! -e "$TMPROOT/etc/systemd/system/snoop-blocker.service" ]]; then
  echo "  [OK] temp unit removed"
else
  echo "  [FAIL] temp unit still present"
  fail=1
fi

echo "== Live boundary check =="
if [[ -n "$LIVE_OPT_BEFORE" ]]; then
  LIVE_OPT_AFTER="$(find "$LIVE_OPT" -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum | awk '{print $1}')"
  if [[ "$LIVE_OPT_BEFORE" == "$LIVE_OPT_AFTER" ]]; then
    echo "  [OK] live /opt/snoop-blocker unchanged"
  else
    echo "  [FAIL] live /opt/snoop-blocker was modified"
    fail=1
  fi
else
  if [[ -d "$LIVE_OPT" ]]; then
    echo "  [FAIL] live /opt/snoop-blocker appeared during dry-run"
    fail=1
  else
    echo "  [OK] live /opt/snoop-blocker still absent"
  fi
fi

if [[ -n "$LIVE_UNIT_BEFORE" ]]; then
  LIVE_UNIT_AFTER="$(sha256sum "$LIVE_UNIT" | awk '{print $1}')"
  if [[ "$LIVE_UNIT_BEFORE" == "$LIVE_UNIT_AFTER" ]]; then
    echo "  [OK] live unit unchanged"
  else
    echo "  [FAIL] live unit was modified"
    fail=1
  fi
else
  if [[ -f "$LIVE_UNIT" ]]; then
    echo "  [FAIL] live unit appeared during dry-run"
    fail=1
  else
    echo "  [OK] live unit still absent"
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo ""
  echo "STAGE 2 FAILED"
  exit 1
fi

echo ""
echo "ALL STAGE 2 PACKAGING DRY-RUN CHECKS PASSED"
exit 0
