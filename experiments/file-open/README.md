# File-Open Entryway Experiment (v0.7)

Isolated experiment. Branched from locked baseline `79bb24b` (v0.6.1).

## Guardrails
- Separate module — no edits to locked clone.py / packaging
- Reads existing external `policy.json` when present
- Default action: **log only** (no freeze/kill wired)
- Independent install / uninstall
- Explicit sandbox target: `/tmp/snoop-blocker-sandbox`
- Must prove cleanup before any disruption is considered

## Quick test (no service)
```bash
# create sandbox
mkdir -p /tmp/snoop-blocker-sandbox
echo test > /tmp/snoop-blocker-sandbox/fixture.txt

# run observation-only
python3 file_open_watch.py
```

In another shell:
```bash
cat /tmp/snoop-blocker-sandbox/fixture.txt
```

Watch for `FILE_OPEN` log lines. Ctrl-C to stop.

## Service install / uninstall
```bash
sudo ./install-experiment.sh
journalctl -u snoop-blocker-file-open -f

sudo ./uninstall-experiment.sh
# confirms no orphans, removes /opt/snoop-blocker-file-open and sandbox
```

## Stop condition
Entryway verified in observation-only mode + cleanup proven.  
No disruption behavior connected until that checkpoint is accepted.
