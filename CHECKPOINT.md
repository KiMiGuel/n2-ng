# CHECKPOINT — CPU spike diagnosis (n2-ng) — RESOLVED in v0.1.3

## Root cause (confirmed via py-spy, two consecutive dumps)
Start Monitor → airodump-ng floods stdout with ANSI screen redraws →
`_poll_queue` appended every line to the Raw View Text widget with per-line
`see()`/`config()`/top-delete → O(n²) Tk layout churn starved the Tk event
loop → frozen GUI, 100% CPU on a core, X server saturation, desktop freeze.

## Fixes (all committed, v0.1.3)
- 2049944 — batched Raw View appends (single layout pass, MAX_LINES cap),
  bounded `_raw_lines` deque(1000), `_poll_queue` re-entrancy guard + "log"
  queue event, after() id hygiene (`_cancel_after`, capture monitors,
  SignalGraph retry, all cancelled in `_cleanup`), Hashcat/Attack worker
  output via queue + after() pump.
- 9796395 — Raw View renders only while its tab is visible (bounded backlog
  catch-up on show); Clients STATION column width measured from mono font;
  version 0.1.3 (code + test assertion; debian files untouched).
- b14cfef — debian/ packaging removed per user (submission declined),
  install.sh pip-only, README deb block + Kali-rolling review section
  removed, version badge added.
- final — Capture Sessions action-bar buttons no longer forced to width=10
  ("Convert to 22000" was clipped).

## Verification (caged: systemd-run CPUQuota=40% MemoryMax=1G)
- Pre-fix: main thread R state, permanently inside `AirodumpRawView
  ._append_line` → frozen.
- Post-fix (150s run, real airodump-ng scan on wlan0monmon, 5+ 20s
  auto-refresh cycles): main thread idle in `mainloop` on every py-spy
  dump, state S, steady CPU, GUI responsive.
- 75/75 tests pass (test_helpers.py, test_ui.py).

## Diagnosis artifacts
- diag_run.py / diag_run2.py / diag_run3.py / diag_click.py were removed
  after use; they remain in git history if ever needed again.
