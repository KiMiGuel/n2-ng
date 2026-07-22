# CHECKPOINT — CPU spike diagnosis (n2-ng 0.1.1)

## Status: ALL FIXES COMMITTED (9796395, v0.1.3) — final caged verification

## Fixes in 9796395 + 2049944
1. Raw View appends batched (single layout pass, MAX_LINES cap per batch).
2. `_raw_lines` bounded deque(maxlen=1000).
3. Raw View renders only while its tab is visible; backlog catch-up on show.
4. `_poll_queue` re-entrancy guard; "log" queue event.
5. after() hygiene: `_cancel_after`, ids for capture monitors + SignalGraph
   retry, all cancelled in `_cleanup`.
6. Hashcat/attack worker output via queue + after() pump.
7. Clients panel STATION column width measured from mono font (+rescale).
- Version 0.1.3 in code + test assertion. Debian packaging UNTOUCHED
  (submission declined; changelog/README/INSTALL restored to 0.1.1 state).
- 75/75 tests pass.

## Next step
- Final caged verification (diag_run3.py, Start Monitor at t=5s, 150s):
  idle near-0% pre-scan, main thread in mainloop during scan per py-spy,
  stable through 3+ 20s auto-refresh cycles.
- Then: final clean commit + live-test instructions.

## If machine froze mid-step
- Reboot; everything is committed. Only verification + final commit remain.
  Kill leftovers: `systemctl --user stop n2ng-*.scope; sudo pkill -f n2ng_scan`

## Fix committed (2049944, version bump follows)
1. `AirodumpRawView.append_lines`: batched — one config/insert-loop/trim/see
   per flush, batch capped at MAX_LINES; per-line width=10 reconfigure gone.
2. `AirodumpWorker._raw_lines`: bounded deque(maxlen=1000).
3. `_poll_queue`: re-entrancy guard + "log" queue event.
4. after() hygiene: `_cancel_after` helper; ids stored+cancelled for
   capture-size monitor, `_poll_capture`, SignalGraph retry; all cancelled
   in `_cleanup`.
5. HashcatDialog + AttackController: worker→GUI via queue + after() pump.

## Test status
- 75/75 passed (test_helpers.py, test_ui.py) after fix and after version bump.
- Version: 0.1.2 in __init__.py, main.py fallback, debian/changelog (0.1.2-1),
  README.md, docs/INSTALL.md, test_helpers.py assertion.

## ROOT CAUSE (py-spy, two consecutive dumps, pid 73921)
Main thread permanently inside:
`_poll_queue` (main.py:2980) → `AirodumpRawView.append_lines` (1709)
→ `_append_line` (1711-1723) → `text.see(tk.END)` / `text.config(...)`

Mechanism: Start Monitor launches airodump-ng with stdout=PIPE. airodump
redraws its full ANSI screen continuously → `_read_stdout` floods the
unbounded `_raw_lines` buffer. Every 150 ms `_poll_queue` appends ALL
accumulated lines to the Raw View Text widget, and EACH line costs:
config(NORMAL) + insert + index + tag_add + count/top-delete trim +
see(END) + config(DISABLED, width=10). Per-line `see` + double reconfigure
+ top-deletes on a 500-line widget = O(n^2) Tk layout churn on the main
thread → event loop starved → frozen GUI, one core at 100%, X server
hammered → whole-desktop freeze. Happens even with the Raw tab hidden.

## Fix plan (minimal, no feature/UI changes)
1. Batch Raw View appends: one config/insert-loop/trim/see per flush,
   cap batch at MAX_LINES; drop per-line width=10 reconfigure.
2. Bound `_raw_lines` producer buffer (deque maxlen).
3. Re-entrancy guard on `_poll_queue`.
4. after() hygiene: store + cancel ids for SignalGraph._draw,
   _start_capture_size_monitor, _poll_capture; cancel all in _cleanup.
5. HashcatDialog: worker→GUI via queue + after pump (no after() from
   the reader thread).

## What's been changed (all committed)
- CHECKPOINT.md, diag_run.py, diag_run2.py, diag_run3.py, diag_click.py
- No app code changes yet.

## Next step
- Caged verification with the exact freeze repro (diag_run3.py, Start
  Monitor at t=5s): idle near-0% CPU pre-scan, main thread in mainloop
  per py-spy, stable through 3+ 20s auto-refresh cycles (run ~150s).
- Then final clean commit.

## If machine froze mid-step
- Reboot; `git log` + this file resume. Fix and version bump are already
  committed — what remains is verification + final commit. Kill leftovers:
  `systemctl --user stop n2ng-*.scope; sudo pkill -f n2ng_scan`
