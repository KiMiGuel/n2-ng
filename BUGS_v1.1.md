# Known minor bugs (found during v1.1, not fixed)

- src/n2ng/main.py:_update_history_selection (~line 3415): `_find_related_22000()` is called up to 3 times per selection update; each miss triggers an `rglob` over the whole capture root — cosmetic perf nit on large capture dirs.
- src/n2ng/main.py:ConversionDialog: `mode="22000"` is now dead code — the only caller (`_convert_selected_to_22000`) was removed in v1.1 when conversion became automatic; dialog is still used with `mode="pcapng"`.
- src/n2ng/main.py:_sort_networks (~line 3820): unparsable numeric values sort as -9999, so in ascending sorts they rank above real values instead of sinking to the bottom.
- test suite (test_helpers.py/test_ui.py): some tests run real `ip link` commands against the host's `wlan0` (visible as "failed to restore MAC on wlan0" warnings after pytest) — tests are not fully isolated from the host network stack.
