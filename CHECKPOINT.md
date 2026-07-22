# CHECKPOINT — CPU spike diagnosis (n2-ng 0.1.1)

## Status: RUNTIME DIAGNOSIS — no app code changes yet

## Hypotheses (confirm with py-spy, priority order)
1. Competing/stacking `after()` loops (schedule without cancel)
2. Busy-wait subprocess/pipe polling without sleep
3. Worker threads touching Tk widgets / threads piling up
4. Unbounded tree rebuild every refresh
5. scapy sniffing on main thread

## Static analysis findings (main.py)
- `SignalGraph._draw` (main.py:1075-1081): reschedules `after(100, _draw)`
  every call while canvas width <10, and `add_sample` calls `_draw` directly —
  stacking `after()` chains possible while unmapped. Lead suspect.
- `AirodumpWorker`: blocking stdout reader thread + 200ms CSV poll — clean.
- `_poll_queue` (150ms) and `_schedule_history_refresh` (20s) self-reschedule
  once each — look single-chain.
- Normal launch re-execs via sudo (`ensure_root`) and splash needs a click,
  so diagnosis uses `diag_run.py` (demo mode, direct app instantiation).

## What's been changed
- Added `diag_run.py` (diagnosis harness only, not app code).

## Next step
- Caged run:
  `systemd-run --user --scope -p CPUQuota=40% -p MemoryMax=1G timeout 90s venv/bin/python diag_run.py`
- Attach: `venv/bin/py-spy top --pid <pid>` and `py-spy dump --pid <pid>`.
- Confirm hot function, THEN fix.

## If machine froze mid-step
- Reboot, `git log` + this file are the resume point. No app code modified;
  the stock 0.1.1 build still carries the freeze risk — never launch `n2-ng`
  bare, always inside the systemd-run cage above (swap `n2-ng` for the
  launcher path when testing the real entry point).
