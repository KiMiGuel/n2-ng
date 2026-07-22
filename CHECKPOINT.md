# CHECKPOINT — CPU spike diagnosis (n2-ng 0.1.1)

## Status: ROOT CAUSE CONFIRMED — implementing fix

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
- Implement fix in src/n2ng/main.py, commit, then version bumps
  (0.1.2), tests, caged verification (diag_run3 repro must stay idle-calm
  through 3+ refresh cycles), final commit.

## If machine froze mid-step
- Reboot; `git log` + this file resume. Kill leftovers:
  `systemctl --user stop n2ng-*.scope; sudo pkill -f n2ng_scan`
