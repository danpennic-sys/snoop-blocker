#!/usr/bin/env python3
"""
Snoop-Blocker Clone v0.6 — slim, offline, identical entryway agent.
Zero external deps. Pure stdlib. Drop identical copies at any entryway.

Entryways covered:
  1. Process creation
  2. Network sockets (TCP/UDP)
  3. Privilege escalation
  4. Audit netlink (optional — activates only when kernel allows)

v0.6 changes:
  - systemd unit + install.sh / uninstall.sh
  - Reversible live packaging
"""

import os
import sys
import time
import json
import hashlib
import signal
import socket
import struct
import select
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# === Paths (same for every clone) ===
BASE_DIR = Path(__file__).resolve().parent
POLICY_FILE = BASE_DIR / "policy.json"
LOG_FILE = Path("/tmp/snoop-blocker.log")
STATE_FILE = Path("/tmp/snoop-blocker.state")

# Defaults (overridden by policy.json)
DEFAULTS = {
    "check_interval": 1.5,
    "disrupt_mode": "freeze",          # log | freeze | kill
    "max_new_procs_per_cycle": 12,
    "max_new_sockets_per_cycle": 20,
    "max_outbound_per_pid": 8,
    "suspicious_cmds": [
        "nmap", "masscan", "zmap", "hydra", "medusa",
        "sqlmap", "nikto", "dirb", "gobuster", "ffuf",
        "tcpdump", "wireshark", "tshark", "strace",
        "ltrace", "gdb", "radare2", "r2", "objdump",
    ],
    "suspicious_ports": [22, 23, 445, 3389, 5900, 6379, 27017],
    "priv_binaries": [
        "/usr/bin/sudo", "/bin/su", "/usr/bin/passwd", "/bin/mount",
        "/usr/bin/chsh", "/usr/sbin/useradd", "/usr/sbin/usermod",
        "/usr/sbin/userdel",
    ],
}

_HIGH_RISK_CAPS = {8, 12, 13, 16, 17, 19, 21, 25}
_prev_priv = {}

# Audit netlink constants
AF_NETLINK = 16
NETLINK_AUDIT = 9
AUDIT_GET = 1000
AUDIT_SET = 1001
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLMSG_ERROR = 2
AUDIT_STATUS_ENABLED = 0x0001

def load_policy():
    """Load policy.json. Falls back to defaults if missing/invalid."""
    cfg = dict(DEFAULTS)
    if POLICY_FILE.exists():
        try:
            data = json.loads(POLICY_FILE.read_text())
            cfg.update(data)
        except Exception as e:
            print(f"policy load failed, using defaults: {e}", flush=True)
    # Normalize
    cfg["suspicious_cmds"] = set(cfg.get("suspicious_cmds", []))
    cfg["suspicious_ports"] = set(cfg.get("suspicious_ports", []))
    cfg["priv_binaries"] = set(cfg.get("priv_binaries", []))
    mode = str(cfg.get("disrupt_mode", "freeze")).lower()
    if mode not in ("log", "freeze", "kill"):
        mode = "freeze"
    cfg["disrupt_mode"] = mode
    return cfg

POLICY = load_policy()

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

def get_procs():
    """pid -> (comm, cmdline, ppid)"""
    procs = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
            cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            ppid = -1
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("PPid:"):
                    ppid = int(line.split()[1])
                    break
            procs[pid] = (comm, cmdline, ppid)
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
    return procs

def parse_hex_ip_port(hex_str: str):
    try:
        ip_hex, port_hex = hex_str.split(":")
        ip_bytes = bytes.fromhex(ip_hex)
        ip = ".".join(str(b) for b in reversed(ip_bytes))
        port = int(port_hex, 16)
        return ip, port
    except Exception:
        return "0.0.0.0", 0

def get_sockets():
    sockets = set()
    for proto in ("tcp", "udp", "tcp6", "udp6"):
        path = Path(f"/proc/net/{proto}")
        if not path.exists():
            continue
        try:
            lines = path.read_text().strip().splitlines()[1:]
        except Exception:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            lip, lport = parse_hex_ip_port(parts[1])
            rip, rport = parse_hex_ip_port(parts[2])
            sockets.add((parts[9], lip, lport, rip, rport, parts[3], proto))
    return sockets

def inode_to_pid():
    mapping = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        fd_dir = Path(f"/proc/{pid}/fd")
        try:
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                    if target.startswith("socket:["):
                        mapping[target[8:-1]] = pid
                except (FileNotFoundError, PermissionError, OSError):
                    continue
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            continue
    return mapping

def is_suspicious_proc(comm: str, cmdline: str) -> str | None:
    lower_cmd = (comm + " " + cmdline).lower()
    for bad in POLICY["suspicious_cmds"]:
        if bad in lower_cmd:
            return f"matched rulebook term: {bad}"
    if cmdline.count("-") > 8 and len(cmdline) > 120:
        return "high flag density (possible scanner)"
    return None

def is_suspicious_socket(lip, lport, rip, rport, state, proto) -> str | None:
    if state == "0A" and lport in POLICY["suspicious_ports"]:
        return f"listening on sensitive port {lport}"
    if rport in POLICY["suspicious_ports"] and rip not in ("0.0.0.0", "127.0.0.1", "::"):
        return f"outbound to sensitive port {rport}"
    return None

def disrupt(pid: int, reason: str):
    """Safer disrupt: log | freeze | kill (controlled by policy)"""
    mode = POLICY["disrupt_mode"]
    log(f"DISRUPT pid={pid} mode={mode} reason={reason}", "ALERT")

    if mode == "log":
        return

    if mode == "freeze":
        try:
            os.kill(pid, signal.SIGSTOP)
            log(f"FROZEN pid={pid} (SIGSTOP)", "ALERT")
        except ProcessLookupError:
            log(f"pid={pid} already gone", "INFO")
        except PermissionError:
            log(f"no permission to freeze pid={pid}", "WARN")
        return

    # mode == "kill"
    try:
        os.kill(pid, signal.SIGKILL)
        log(f"KILLED pid={pid}", "ALERT")
    except ProcessLookupError:
        log(f"pid={pid} already gone", "INFO")
    except PermissionError:
        log(f"no permission to kill pid={pid}", "WARN")

def _parse_status_priv(pid: int):
    try:
        uid_eff = gid_eff = None
        cap_eff = 0
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                parts = line.split()
                if len(parts) >= 3:
                    uid_eff = int(parts[2])
            elif line.startswith("Gid:"):
                parts = line.split()
                if len(parts) >= 3:
                    gid_eff = int(parts[2])
            elif line.startswith("CapEff:"):
                parts = line.split()
                if len(parts) >= 2:
                    cap_eff = int(parts[1], 16)
        if uid_eff is None or gid_eff is None:
            return None
        return uid_eff, gid_eff, cap_eff
    except (OSError, ValueError):
        return None

def _cap_has_high_risk(cap_eff: int) -> bool:
    for bit in _HIGH_RISK_CAPS:
        if cap_eff & (1 << bit):
            return True
    return False

def _read_exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return "unknown"

def scan_priv_escalation(all_pids: set, ppid_lookup: dict):
    global _prev_priv
    for pid in all_pids:
        priv = _parse_status_priv(pid)
        if priv is None:
            continue
        uid_curr, gid_curr, cap_curr = priv
        prev = _prev_priv.get(pid)
        uid_prev = prev["uid_eff"] if prev else uid_curr
        gid_prev = prev["gid_eff"] if prev else gid_curr
        cap_prev = prev["cap_eff"] if prev else cap_curr
        exe_path = _read_exe(pid)
        ppid = ppid_lookup.get(pid, -1)

        escalated = False
        rule_id = None

        if uid_prev != 0 and uid_curr == 0:
            escalated, rule_id = True, "PE_UID"
        elif not _cap_has_high_risk(cap_prev) and _cap_has_high_risk(cap_curr):
            escalated, rule_id = True, "PE_CAP"
        elif uid_curr == 0:
            parent = _prev_priv.get(ppid)
            if parent and parent["uid_eff"] != 0:
                escalated, rule_id = True, "PE_PARENT_ROOT"
        elif exe_path in POLICY["priv_binaries"] and uid_curr != 0:
            escalated, rule_id = True, "PE_PRIV_BIN"

        if escalated and rule_id:
            log(
                f"[priv] pid={pid} ppid={ppid} "
                f"uid={uid_prev}->{uid_curr} gid={gid_prev}->{gid_curr} "
                f"cap=0x{cap_prev:016x}->0x{cap_curr:016x} "
                f"exe={exe_path} rule={rule_id}",
                "ALERT",
            )
            disrupt(pid, f"privilege escalation ({rule_id})")

        _prev_priv[pid] = {"uid_eff": uid_curr, "gid_eff": gid_curr, "cap_eff": cap_curr}

    dead = [p for p in _prev_priv if p not in all_pids]
    for p in dead:
        _prev_priv.pop(p, None)

class AuditNetlink:
    def __init__(self):
        self.sock = None
        self.active = False
        self._seq = 1

    def try_activate(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
            self.sock.bind((0, 0))
            self.sock.setblocking(False)
            if not self._send_cmd(AUDIT_GET):
                self._cleanup()
                return False
            status = struct.pack("II", AUDIT_STATUS_ENABLED, 1)
            if not self._send_cmd(AUDIT_SET, status, ack=True):
                log("Audit netlink: open OK but enable denied (restricted environment)", "WARN")
                self._cleanup()
                return False
            self.active = True
            log("Audit netlink: ACTIVE (high-fidelity entryway enabled)", "INFO")
            return True
        except Exception as e:
            log(f"Audit netlink: unavailable ({type(e).__name__})", "INFO")
            self._cleanup()
            return False

    def _send_cmd(self, msg_type: int, payload: bytes = b"", ack: bool = False) -> bool:
        if not self.sock:
            return False
        flags = NLM_F_REQUEST | (NLM_F_ACK if ack else 0)
        hdr = struct.pack("IHHII", 16 + len(payload), msg_type, flags, self._seq, os.getpid())
        self._seq += 1
        try:
            self.sock.send(hdr + payload)
            ready, _, _ = select.select([self.sock], [], [], 0.5)
            if not ready:
                return False
            data = self.sock.recv(65535)
            if len(data) < 16:
                return False
            length, mtype, flags, seq, pid = struct.unpack_from("IHHII", data, 0)
            if mtype == NLMSG_ERROR:
                err = struct.unpack_from("i", data, 16)[0]
                return err == 0
            return True
        except Exception:
            return False

    def poll_events(self) -> list:
        if not self.active or not self.sock:
            return []
        events = []
        try:
            while True:
                ready, _, _ = select.select([self.sock], [], [], 0)
                if not ready:
                    break
                data = self.sock.recv(65535)
                if data:
                    events.append(data)
        except Exception:
            pass
        return events

    def _cleanup(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.active = False

    def close(self):
        self._cleanup()

def main():
    log("=== Snoop-Blocker Clone v0.6 started (slim offline mode) ===")
    log(f"PID of this clone: {os.getpid()}")
    log(f"Policy: disrupt_mode={POLICY['disrupt_mode']} interval={POLICY['check_interval']}s")
    log("Entryways: process + sockets + privilege + optional audit netlink")

    audit = AuditNetlink()
    if not audit.try_activate():
        log("Running in pure /proc fallback mode (still fully functional)", "INFO")

    known_procs = get_procs()
    known_socks = get_sockets()
    log(f"Baseline: {len(known_procs)} processes, {len(known_socks)} sockets")

    try:
        while True:
            time.sleep(POLICY["check_interval"])

            current_procs = get_procs()
            new_pids = set(current_procs) - set(known_procs)
            if len(new_pids) > POLICY["max_new_procs_per_cycle"]:
                log(f"Burst of new processes: {len(new_pids)}", "WARN")

            ppid_lookup = {}
            for pid, (comm, cmdline, ppid) in current_procs.items():
                ppid_lookup[pid] = ppid
                if pid in new_pids:
                    reason = is_suspicious_proc(comm, cmdline)
                    if reason:
                        log(f"SUSPICIOUS process pid={pid} comm={comm} cmd={cmdline[:80]}", "ALERT")
                        disrupt(pid, reason)
                    else:
                        log(f"new process pid={pid} comm={comm}", "DEBUG")

            current_socks = get_sockets()
            new_socks = current_socks - known_socks
            if len(new_socks) > POLICY["max_new_sockets_per_cycle"]:
                log(f"Burst of new sockets: {len(new_socks)}", "WARN")

            inode_map = inode_to_pid() if new_socks else {}
            outbound_count = defaultdict(int)
            for sock in new_socks:
                inode, lip, lport, rip, rport, state, proto = sock
                reason = is_suspicious_socket(lip, lport, rip, rport, state, proto)
                pid = inode_map.get(inode)
                if reason:
                    log(f"SUSPICIOUS socket inode={inode} {proto} {lip}:{lport}->{rip}:{rport} pid={pid}", "ALERT")
                    if pid:
                        disrupt(pid, reason)
                elif rip not in ("0.0.0.0", "127.0.0.1") and rport != 0 and pid:
                    outbound_count[pid] += 1

            for pid, count in outbound_count.items():
                if count >= POLICY["max_outbound_per_pid"]:
                    log(f"High outbound volume pid={pid} count={count}", "ALERT")
                    disrupt(pid, f"excessive outbound sockets ({count})")

            scan_priv_escalation(set(current_procs.keys()), ppid_lookup)

            if audit.active:
                for ev in audit.poll_events():
                    log(f"[audit] received {len(ev)} byte event", "DEBUG")

            known_procs = current_procs
            known_socks = current_socks

    finally:
        audit.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Clone stopped by signal")
        sys.exit(0)
