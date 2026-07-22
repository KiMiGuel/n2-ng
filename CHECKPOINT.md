# CHECKPOINT — CPU spike diagnosis (n2-ng 0.1.1)

## Status: DIAGNOSIS IN PROGRESS — no code changes yet

## Hypothesis (to confirm with py-spy, in priority order)
1. Competing/stacking `after()` loops (schedule without cancel)
2. Busy-wait subprocess/pipe polling without sleep
3. Worker threads touching Tk widgets / threads piling up
4. Unbounded tree rebuild every refresh
5. scapy sniffing on main thread

## What's been changed
- Nothing yet. This file is the only change.

## Next step
- Static-read src/n2ng/main.py for after()/thread/poll patterns
- Launch caged app and attach py-spy:
  `systemd-run --user --scope -p CPUQuota=40% -p MemoryMax=1G timeout 90s n2-ng`
- Identify hot function, THEN fix.

## If machine froze mid-step
- Reboot, `git log` / this file shows state. No code modified, so app is still
  the stock 0.1.1 build — same freeze risk applies if you launch it bare.
  Always launch via the caged command above.
