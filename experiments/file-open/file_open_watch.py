#!/usr/bin/env python3
"""
Snoop-Blocker File-Open Entryway Experiment (v0.7)
Isolated module. Observation-only by default.
Does NOT modify the locked v0.6.1 baseline.

- Reads existing external policy.json (no private rules)
- Default action: log only
- No process disruption connected
- Independent lifecycle
"""

import os
import sys
import time
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

BASELINE_POLICY = Path("/opt/snoop-blocker/policy.json")
LOCAL_POLICY = Path(__file__).resolve().parent / "policy.json"
LOG_FILE = Path("/tmp/snoop-blocker-file-open.log")
STATE_FILE = Path("/tmp/snoop-blocker-file-open.state")

SANDBOX_DIR = Path("/tmp/snoop-blocker-sandbox")
DEFAULT_WATCH_PATHS = [
    str(SANDBOX_DIR),
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root",
]

CHECK_INTERVAL = 1.5
DEFAULT_ACTION = "log"

def load_policy():
    """Read external policy. Never invent private rules."""
    for candidate in (BASELINE_POLICY, LOCAL_POLICY):
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text())
                return data, str(candidate)
            except Exception:
                continue
    return {}, "none"

def log(msg: str, level: str = "INFO"):
    ts = datetime.now(timezone.utc).isoformat()
    line = f"{ts} [{level}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    h = hashlib.sha256()
    if LOG_FILE.exists():
        h.update(LOG_FILE.read_bytes())
    STATE_FILE.write_text(h.hexdigest())

def snapshot_opens(watch_paths):
    observed = set()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        fd_dir = Path(f"/proc/{pid}/fd")
        try:
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                    if not target.startswith("/"):
                        continue
                    for wp in watch_paths:
                        if target == wp or target.startswith(wp.rstrip("/") + "/"):
                            observed.add((pid, target))
                            break
                except (FileNotFoundError, PermissionError, OSError):
                    continue
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            continue
    return observed

def main():
    policy, policy_src = load_policy()
    interval = float(policy.get("check_interval", CHECK_INTERVAL))
    action = DEFAULT_ACTION

    watch_paths = policy.get("file_open_watch_paths", DEFAULT_WATCH_PATHS)
    if not isinstance(watch_paths, list):
        watch_paths = DEFAULT_WATCH_PATHS

    log("=== File-Open Entryway Experiment v0.7 started ===")
    log(f"PID: {os.getpid()}")
    log(f"Policy source: {policy_src}")
    log(f"Action: {action} (observation-only — no disruption wired)")
    log(f"Watch paths: {watch_paths}")
    log(f"Sandbox: {SANDBOX_DIR}")

    known = snapshot_opens(watch_paths)
    log(f"Baseline open files under watch: {len(known)}")

    try:
        while True:
            time.sleep(interval)
            current = snapshot_opens(watch_paths)
            new_opens = current - known

            for pid, path in sorted(new_opens):
                log(f"FILE_OPEN pid={pid} path={path} action={action}", "ALERT")

            known = current
    except KeyboardInterrupt:
        log("File-open experiment stopped by signal")
        sys.exit(0)

if __name__ == "__main__":
    main()
