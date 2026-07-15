# N2-ng UI Enhancements Design

**Date:** 2026-07-15  
**Status:** Approved for implementation  
**Project location:** `/home/kali/n2-ng/`  
**Scope:** Right-panel scrolling, client-table fix, Raw View tab, visual polish

## 1. Overview

This spec adds four related improvements to the existing single-file tkinter GUI:

1. Make the right-side detail panel scrollable so it never overflows the viewport.
2. Fix the Clients table so it populates correctly and filters by the locked target.
3. Add a read-only "Raw View" tab that renders authentic colored `airodump-ng` output by parsing ANSI escape codes into a `tk.Text` widget.
4. Polish the network Treeview with monospace fonts and a brief flash effect on PWR/Beacons updates.

## 2. Constraints

- tkinter-only; no `pyte`, `ncurses`, `xterm`, or external terminal widgets.
- No embedding of airodump-ng's native ncurses interface (it writes directly to the terminal device).
- Keep changes minimal-intrusion: reuse existing classes where possible.
- Continue using threading for blocking subprocess I/O.

## 3. Design

### 3.1 Scrollable right panel

The main window currently splits into left Treeview + right detail panel. The right panel will be wrapped in a `ttk.Notebook` so the detail content becomes the first tab ("Scan") and the Raw View becomes the second tab ("Raw View").

Inside the "Scan" tab:
- A `tk.Canvas` fills the tab.
- A `ttk.Scrollbar` on the far right controls the canvas.
- A `tk.Frame` (the scrollable container) is created inside the canvas window.
- All existing right-panel widgets (Target card, Clients table, Signal graph, Attacks, Capture Handshake, History) are reparented into this frame.
- The canvas scroll region is updated whenever the frame's size changes via `<Configure>`.

### 3.2 Client table fix

`parse_airodump_csv` currently parses the client section, but the client table is empty/incomplete because:
- Column whitespace is not consistently stripped.
- The display filter does not reliably associate clients with the locked target.

Fixes:
- Strip whitespace from client-section field names.
- In `_update_clients`, show a client only if:
  - `client["bssid"] == locked_target["bssid"]`, OR
  - `locked_target["essid"]` is non-empty and appears in `client["probed"]`.
- Map Treeview columns correctly: STATION → `station`, PWR → `power`, Pkts → `packets`, Probed ESSID → `probed`.

### 3.3 Raw View tab

A new tab "Raw View" contains a read-only `tk.Text` widget with a monospace font.

Behavior:
- When monitor mode starts and a scan/lock is active, launch a separate `airodump-ng` process with `--color` and capture stdout/stderr via `subprocess.PIPE`.
- A daemon thread reads lines from the pipe and puts them on a thread-safe queue.
- The tkinter main loop drains the queue and appends text to the Raw View widget.
- A minimal ANSI SGR parser extracts:
  - Foreground colors: 30-37
  - Background colors: 40-47
  - Bold: 1
  - Reset: 0
- Each unique SGR combination maps to a named `tk.Text` tag (e.g., `ansi_fg_32_bg_40_bold`).
- Tag foreground/background colors match the ANSI standard palette, themed to the app where appropriate:
  - green (`ansi_fg_32`) → `#00ff41`
  - red (`ansi_fg_31`) → `#ff4444`
  - yellow (`ansi_fg_33`) → `#ffcc00`
  - blue/cyan (`ansi_fg_34`/`ansi_fg_36`) → `#00ccff`
  - white (`ansi_fg_37`) → `#ffffff`
  - black (`ansi_fg_30`) → `#000000`
- The widget auto-scrolls to the bottom and limits total lines to avoid unbounded memory growth.
- The Raw View airodump-ng subprocess runs whenever monitor mode is active; text is appended to the widget only when the Raw View tab is selected. The subprocess is terminated when monitor mode stops or the app closes.

### 3.4 Visual polish

- Set the network Treeview font to monospace: `("Consolas", 10)` with fallback `("Courier", 10)`.
- Reduce Treeview row height from 22 to 18.
- Track previous `power` and `beacons` per BSSID in `self._networks_prev`.
- In `_update_networks`, when a network's `power` or `beacons` value changes:
  - Apply a temporary `flash` tag with yellow background (`#ffff00`) to that row.
  - Schedule a 200 ms `root.after()` to remove the flash tag and restore the privacy-based color tag.

## 4. Files changed

- `n2_ng.py` — all implementation.
- `test_ui.py` — new tests for scrollable panel, Raw View ANSI parsing, client filtering, and flash effect.

## 5. Testing approach

- `python3 -m py_compile n2_ng.py`
- `xvfb-run python3 -m pytest -v`
- Manual: verify right panel scrolls when window is short, clients populate for locked target, Raw View shows colored airodump-ng output, and updated rows flash yellow briefly.
