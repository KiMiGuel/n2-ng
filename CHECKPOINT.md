# CHECKPOINT — CPU spike diagnosis (n2-ng 0.1.1)

## Status: ROOT CAUSE NARROWED — reproducing with instrumentation next

## CONFIRMED reproduction (user + caged run, 2026-07-21 ~22:20)
- Real mode, click through splash, hit "Start Monitor" (adapter wlan0monmon)
  → airodump-ng starts → GUI freezes.
- Evidence captured before the caged process hit its timeout:
  - main python (root) in state **R at ~18.7% CPU** (cage cap 40%) — main
    thread spinning in Python, NOT sitting in the Tcl event loop.
  - airodump-ng child at ~16.7% (expected, it channel-hops).
- py-spy dump missed the process by seconds (timeout killed it). Next run
  uses a longer timeout and a self-driving harness so py-spy attaches in time.

## Ruled out
- Idle demo launch: 1.6% CPU, mainloop idle. Not the bug.
- Simulated locked-scan feed (FakeWorker, incl. Raw-tab switch): ~2%, calm.
- Startup dependency checks (incl. hashcat -I): bounded one-off.
- Static review: AirodumpWorker (blocking reads + 200ms sleep), WpsScanner
  (blocking readline), Raw view (500-line cap), resize handler (debounced) —
  all clean.

## Remaining suspects in the Start Monitor → scan path
- `SignalGraph._draw` stacking after() chains while canvas unmapped (main.py:1075)
- `_poll_queue` → `_update_networks` → `_refresh_tree` per-150ms `tree.move()`
  storm with real scan data
- `Raw View` append of airodump stdout every 150 ms
- `_refresh_history` rglob over a large ~/hs tree (20s cycle)

## What's been changed (all committed)
- CHECKPOINT.md, diag_run.py, diag_run2.py, diag_click.py (harnesses only)
- No app code changes.

## Next step
- diag_run3.py: non-demo harness (run as root via sudo -n), sets
  adapter_var=wlan0monmon, calls app._start_monitor() at t=5s.
- Caged: `systemd-run --user --scope -p CPUQuota=40% -p MemoryMax=1G
  timeout 180s sudo -n env DISPLAY=:0.0 XAUTHORITY=/home/kali/.Xauthority
  venv/bin/python diag_run3.py`
- At t≈10s: `sudo -n venv/bin/py-spy dump --pid <root-python-pid>` + py-spy top.
- After run: kill orphaned airodump-ng (`sudo pkill -f n2ng_scan`).

## If machine froze mid-step
- Reboot; `git log` + this file resume the work. The cage caps CPU at 40%
  so a full freeze is unlikely; if the GUI is just stuck, the scope is
  `systemctl --user stop n2ng-*.scope` and `sudo pkill -f n2ng_scan`.
