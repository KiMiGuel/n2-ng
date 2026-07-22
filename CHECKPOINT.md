# CHECKPOINT — CPU spike diagnosis (n2-ng)

## Status: v0.1.3 COMPLETE (b14cfef) — final caged verification run

## Root cause (confirmed via py-spy, two dumps)
Start Monitor → airodump-ng floods stdout with ANSI screen redraws →
`_poll_queue` appended every line to the Raw View Text widget with per-line
`see()`/`config()`/top-delete → O(n²) Tk layout churn starved the event loop
→ frozen GUI, 100% CPU, desktop freeze.

## All changes committed
- 2049944 freeze fix: batched Raw View appends (single layout pass,
  MAX_LINES cap), bounded `_raw_lines` deque(1000), `_poll_queue` re-entrancy
  guard + "log" event, after() id hygiene (`_cancel_after`, capture monitors,
  SignalGraph retry), Hashcat/Attack worker output via queue + after() pump.
- 9796395 Raw View renders only while its tab is visible (backlog catch-up
  on show); Clients STATION column width measured from mono font; v0.1.3.
- b14cfef debian/ packaging removed per user (submission declined),
  install.sh pip-only, README deb block + Kali-rolling review section
  removed, version badge added.
- 75/75 tests pass (test_helpers.py, test_ui.py).

## Next step
- Final caged verification (diag_run3.py, Start Monitor at t=5s, 150s):
  idle near-0% CPU pre-scan, main thread in mainloop during scan per py-spy,
  stable through 3+ 20s auto-refresh cycles.
- Then: final clean commit + live-test instructions for the user.

## If machine froze mid-step
- Reboot; everything is committed. Only verification + final commit remain.
  Kill leftovers: `systemctl --user stop n2ng-*.scope; sudo pkill -f n2ng_scan`
