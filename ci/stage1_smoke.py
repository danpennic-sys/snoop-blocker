#!/usr/bin/env python3
"""
Stage 1 smoke checks for Snoop-Blocker.
Pure stdlib. Offline. No disruption. Safe to run in CI or locally.
"""

import json
import py_compile
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors = []


def ok(msg: str):
    print(f"  [OK] {msg}")


def fail(msg: str):
    print(f"  [FAIL] {msg}")
    errors.append(msg)


def check_syntax():
    print("== Syntax ==")
    targets = [
        ROOT / "clone.py",
        ROOT / "experiments" / "file-open" / "file_open_watch.py",
    ]
    for path in targets:
        if not path.exists():
            print(f"  [SKIP] {path.relative_to(ROOT)} (not present)")
            continue
        try:
            py_compile.compile(str(path), doraise=True)
            ok(str(path.relative_to(ROOT)))
        except py_compile.PyCompileError as e:
            fail(f"{path.relative_to(ROOT)}: {e}")


def check_policy():
    print("== Policy ==")
    path = ROOT / "policy.json"
    if not path.exists():
        fail("policy.json missing")
        return
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        fail(f"policy.json invalid JSON: {e}")
        return
    ok("policy.json parses")

    mode = data.get("disrupt_mode")
    if mode not in ("log", "freeze", "kill"):
        fail(f"disrupt_mode invalid: {mode!r}")
    else:
        ok(f"disrupt_mode={mode}")

    if "check_interval" not in data:
        fail("check_interval missing")
    else:
        ok(f"check_interval={data['check_interval']}")

    for key in ("suspicious_cmds", "suspicious_ports", "priv_binaries"):
        if key not in data:
            fail(f"{key} missing")
        elif not isinstance(data[key], list):
            fail(f"{key} must be a list")
        else:
            ok(f"{key} present ({len(data[key])} items)")


def check_packaging_refs():
    print("== Packaging references ==")
    install = ROOT / "install.sh"
    service = ROOT / "snoop-blocker.service"
    if not install.exists() or not service.exists():
        fail("install.sh or snoop-blocker.service missing")
        return

    install_txt = install.read_text()
    service_txt = service.read_text()

    if "policy.json" not in install_txt:
        fail("install.sh does not reference policy.json")
    else:
        ok("install.sh references policy.json")

    if "/opt/snoop-blocker" not in install_txt:
        fail("install.sh missing /opt/snoop-blocker")
    else:
        ok("install.sh targets /opt/snoop-blocker")

    if "clone.py" not in service_txt:
        fail("unit file does not reference clone.py")
    else:
        ok("unit file references clone.py")

    if "WorkingDirectory=/opt/snoop-blocker" not in service_txt:
        fail("unit WorkingDirectory not set to /opt/snoop-blocker")
    else:
        ok("unit WorkingDirectory correct")


def check_rule_engine_smoke():
    print("== Rule engine smoke ==")
    clone = ROOT / "clone.py"
    if not clone.exists():
        fail("clone.py missing")
        return

    import importlib.util
    spec = importlib.util.spec_from_file_location("snoop_clone", clone)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        fail(f"import clone.py failed: {e}")
        return
    ok("clone.py imports")

    if not hasattr(mod, "is_suspicious_proc"):
        fail("is_suspicious_proc missing")
        return

    cases = [
        ("bash", "bash -c echo hi", None),
        ("nmap", "nmap -sS 10.0.0.0/24", "matched"),
        ("masscan", "masscan 0.0.0.0/0 -p1-65535", "matched"),
        ("curl", "curl -s http://example.com", None),
    ]
    for comm, cmd, expect in cases:
        reason = mod.is_suspicious_proc(comm, cmd)
        if expect is None:
            if reason is None:
                ok(f"clean: {comm}")
            else:
                fail(f"false positive on {comm}: {reason}")
        else:
            if reason and expect in reason:
                ok(f"detect: {comm}")
            else:
                fail(f"missed {comm}: got {reason!r}")

    if hasattr(mod, "POLICY"):
        mode = mod.POLICY.get("disrupt_mode")
        ok(f"loaded POLICY disrupt_mode={mode}")


def main():
    print("Snoop-Blocker Stage 1 smoke")
    print(f"ROOT={ROOT}")
    check_syntax()
    check_policy()
    check_packaging_refs()
    check_rule_engine_smoke()
    print()
    if errors:
        print(f"FAILED ({len(errors)} issue(s))")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("ALL STAGE 1 CHECKS PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
