# Snoop-Blocker Clone

Slim, offline, identical entryway agent.

Detects and disrupts snoop / recon / attack activity at the host level.  
Zero external dependencies. Fully offline. Drop identical copies at any entryway.

## Entryways
1. Process creation
2. Network sockets (TCP/UDP)
3. Privilege escalation (UID, capabilities, privileged binaries)
4. Audit netlink (optional — activates only when kernel permits)

## Disrupt modes (policy controlled)
- `log`    — detect and record only
- `freeze` — SIGSTOP (default, safe for live use)
- `kill`   — SIGKILL

## Quick run
```bash
python3 clone.py
```

## Install as service (live)
```bash
sudo ./install.sh
```
Places clone + policy in `/opt/snoop-blocker` and enables the systemd unit.

```bash
journalctl -u snoop-blocker -f
systemctl status snoop-blocker
```

## Uninstall (reversible)
```bash
sudo ./uninstall.sh
```
Stops service, removes unit and `/opt/snoop-blocker`, confirms no orphaned processes.  
Source tree is left untouched.

## Policy
Edit `policy.json` (same file on every clone).  
Clones stay identical; rules stay tunable.

## Design
- Single file + policy.json
- Pure Python stdlib
- Local integrity-protected log
- Identical clones think the same
- Deterministic offline rules
- Graceful fallback when audit netlink is restricted
- Reversible systemd packaging
