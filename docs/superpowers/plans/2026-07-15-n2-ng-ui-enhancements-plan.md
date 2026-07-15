# N2-ng UI Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a scrollable right panel, fix the client table, add a read-only Raw View tab with ANSI-colored airodump-ng output, and polish the network Treeview.

**Architecture:** Keep the single-file tkinter app. Wrap the right panel in a `ttk.Notebook` with a Canvas+Scrollbar scrollable frame. Fix CSV parsing/filtering for clients. Launch a separate `--color` airodump-ng process for Raw View and parse ANSI SGR codes into `tk.Text` tags. Track per-BSSID previous values to drive a 200 ms yellow flash effect.

**Tech Stack:** Python 3.13, tkinter (stdlib), aircrack-ng suite.

## Global Constraints

- Single main Python file: `n2_ng.py`.
- tkinter-only; no `pyte`, `ncurses`, `xterm`, or external terminal widgets.
- No embedding of airodump-ng's native ncurses interface.
- Continue using threading for blocking subprocess I/O.
- All tests run under `xvfb-run python3 -m pytest -v`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `/home/kali/n2-ng/n2_ng.py` | Main application: scrollable panel, client fix, Raw View, Treeview polish. |
| `/home/kali/n2-ng/test_ui.py` | UI regression tests for the four enhancements. |

---

## Task 1: Scrollable right panel

**Files:**
- Modify: `/home/kali/n2-ng/n2_ng.py:831-849` (`_build_ui`)
- Modify: `/home/kali/n2-ng/n2_ng.py:914-967` (`_build_right_panel`)
- Test: `/home/kali/n2-ng/test_ui.py`

**Interfaces:**
- Consumes: existing `_build_toolbar`, `_build_network_tree`, `_build_right_panel`, `_build_log_pane`, `_build_status_bar`.
- Produces: `self.right_canvas`, `self.right_scrollbar`, `self.right_inner_frame`, `self.notebook`.

### Step 1: Write the failing test

Append to `/home/kali/n2-ng/test_ui.py`:

```python
def test_right_panel_is_scrollable():
    """The right panel must live inside a canvas with a scrollbar."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    assert hasattr(app, "right_canvas"), "missing right_canvas"
    assert hasattr(app, "right_scrollbar"), "missing right_scrollbar"
    assert hasattr(app, "right_inner_frame"), "missing right_inner_frame"
    assert app.right_canvas.winfo_class() == "Canvas"
    assert app.right_scrollbar.cget("orient") == "vertical"

    root.destroy()
```

Run: `xvfb-run python3 -m pytest test_ui.py::test_right_panel_is_scrollable -v`
Expected: FAIL — attributes do not exist.

### Step 2: Reparent right panel into a notebook + scrollable canvas

Replace the body of `_build_ui` in `/home/kali/n2-ng/n2_ng.py`:

```python
    def _build_ui(self):
        self._build_toolbar()

        content_frame = tk.Frame(self.root, bg=THEME["bg"])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left: network tree
        left_frame = tk.Frame(content_frame, bg=THEME["bg"])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._build_network_tree(left_frame)

        # Right: notebook with Scan and Raw View tabs
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False)
        self.notebook.configure(width=420)

        scan_tab = tk.Frame(self.notebook, bg=THEME["bg"])
        self.notebook.add(scan_tab, text="Scan")
        self._build_scrollable_right_panel(scan_tab)

        raw_tab = tk.Frame(self.notebook, bg=THEME["bg"])
        self.notebook.add(raw_tab, text="Raw View")
        self._build_raw_view(raw_tab)

        self._build_log_pane()
        self._build_status_bar()
```

Add the scrollable frame helper:

```python
    def _build_scrollable_right_panel(self, parent):
        """Canvas + Scrollbar wrapper for the right-side detail panel."""
        self.right_canvas = tk.Canvas(parent, bg=THEME["bg"], highlightthickness=0)
        self.right_scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.right_canvas.yview)
        self.right_canvas.configure(yscrollcommand=self.right_scrollbar.set)

        self.right_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.right_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.right_inner_frame = tk.Frame(self.right_canvas, bg=THEME["bg"], width=420)
        self.right_canvas_window = self.right_canvas.create_window((0, 0), window=self.right_inner_frame, anchor=tk.NW, width=420)

        def _on_frame_configure(event=None):
            self.right_canvas.configure(scrollregion=self.right_canvas.bbox("all"))

        def _on_canvas_configure(event=None):
            self.right_canvas.itemconfig(self.right_canvas_window, width=event.width)

        self.right_inner_frame.bind("<Configure>", _on_frame_configure)
        self.right_canvas.bind("<Configure>", _on_canvas_configure)

        self._build_right_panel(self.right_inner_frame)
```

Update `_build_right_panel` to remove the hard-coded `width=420` from its parent frame:

```python
    def _build_right_panel(self, parent):
        self.target_card = tk.LabelFrame(parent, text="Target", bg=THEME["panel"], fg=THEME["fg"])
        ...
```

### Step 3: Run the test

Run: `xvfb-run python3 -m pytest test_ui.py::test_right_panel_is_scrollable -v`
Expected: PASS.

### Step 4: Commit

```bash
git add n2_ng.py test_ui.py
git commit -m "feat: make right panel scrollable with canvas+scrollbar"
```

---

## Task 2: Fix client table parsing and filtering

**Files:**
- Modify: `/home/kali/n2-ng/n2_ng.py:249-253` (`_normalize_csv_reader`)
- Modify: `/home/kali/n2-ng/n2_ng.py:289-301` (client section parsing)
- Modify: `/home/kali/n2-ng/n2_ng.py:1446-1456` (`_update_clients`)
- Test: `/home/kali/n2-ng/test_ui.py`

**Interfaces:**
- Consumes: `parse_airodump_csv`, `self.locked_target`, `self.client_tree`.
- Produces: correctly populated client Treeview for locked targets.

### Step 1: Write the failing test

Append to `/home/kali/n2-ng/test_ui.py`:

```python
def test_clients_filtered_by_locked_target():
    """Only clients associated with the locked target should appear."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    app.locked_target = {"bssid": "AA:BB:CC:DD:EE:FF", "essid": "MyWiFi"}
    app.clients = [
        {"station": "11:22:33:44:55:66", "power": "-60", "packets": "50", "bssid": "AA:BB:CC:DD:EE:FF", "probed": ""},
        {"station": "22:33:44:55:66:77", "power": "-70", "packets": "10", "bssid": "(not associated)", "probed": "MyWiFi"},
        {"station": "33:44:55:66:77:88", "power": "-80", "packets": "5", "bssid": "BB:BB:BB:BB:BB:BB", "probed": ""},
    ]
    app._update_clients(app.clients)

    values = [app.client_tree.item(child, "values") for child in app.client_tree.get_children()]
    stations = {v[0] for v in values}
    assert "11:22:33:44:55:66" in stations
    assert "22:33:44:55:66:77" in stations
    assert "33:44:55:66:77:88" not in stations

    root.destroy()
```

Run: `xvfb-run python3 -m pytest test_ui.py::test_clients_filtered_by_locked_target -v`
Expected: FAIL — wrong clients shown.

### Step 2: Strip client fieldnames and fix filtering

Ensure `_normalize_csv_reader` is applied to both AP and client readers (it already is). Verify the client reader line in `parse_airodump_csv`:

```python
    if len(sections) > 1:
        client_lines = "\n".join(line.strip() for line in sections[1].splitlines())
        reader = _normalize_csv_reader(csv.DictReader(io.StringIO(client_lines)))
```

Update `_update_clients`:

```python
    def _update_clients(self, clients: list[dict]):
        self.clients = clients
        self.client_tree.delete(*self.client_tree.get_children())
        if not self.locked_target:
            return
        target_bssid = self.locked_target["bssid"]
        target_essid = self.locked_target.get("essid", "")
        for c in clients:
            bssid = c.get("bssid", "")
            probed = c.get("probed", "")
            matches = bssid == target_bssid
            if not matches and target_essid and target_essid != "[Hidden]":
                matches = target_essid in probed
            if bssid == "(not associated)" and target_essid and target_essid in probed:
                matches = True
            if matches:
                self.client_tree.insert(
                    "", tk.END,
                    values=(c.get("station", ""), c.get("power", ""), c.get("packets", ""), c.get("probed", "")),
                )
```

### Step 3: Run the test

Run: `xvfb-run python3 -m pytest test_ui.py::test_clients_filtered_by_locked_target -v`
Expected: PASS.

### Step 4: Commit

```bash
git add n2_ng.py test_ui.py
git commit -m "fix: filter clients by locked target BSSID or probed ESSID"
```

---

## Task 3: Raw View tab with ANSI parsing

**Files:**
- Modify: `/home/kali/n2-ng/n2_ng.py` (add `AirodumpRawView` class and `_build_raw_view`)
- Modify: `/home/kali/n2-ng/n2_ng.py:1019-1031` (`_start_monitor`) and `_stop_monitor` to start/stop Raw View airodump-ng
- Test: `/home/kali/n2-ng/test_ui.py`

**Interfaces:**
- Consumes: `self.mon_iface`, `self.current_band`, locked-target channel/BSSID.
- Produces: `self.raw_view` widget, ANSI parser, Raw View subprocess.

### Step 1: Write the failing test

Append to `/home/kali/n2-ng/test_ui.py`:

```python
def test_ansi_parser_produces_tags():
    """ANSI SGR codes must be stripped and returned as tag ranges."""
    parser = _n2ng.AnsiParser()
    text, tags = parser.parse("\x1b[32mWPA2\x1b[0m plain")
    assert text == "WPA2 plain"
    assert any(tag == "ansi_fg_32" and start == 0 and end == 4 for tag, start, end in tags)


def test_raw_view_widget_exists():
    """Raw View tab must contain a tk.Text widget."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    assert hasattr(app, "raw_view")
    assert isinstance(app.raw_view, tk.Text)
    root.destroy()
```

Run: `xvfb-run python3 -m pytest test_ui.py::test_ansi_parser_produces_tags test_ui.py::test_raw_view_widget_exists -v`
Expected: FAIL — `AnsiParser` and `raw_view` do not exist.

### Step 2: Implement ANSI parser

Add after the imports/theme section in `/home/kali/n2-ng/n2_ng.py`:

```python
class AnsiParser:
    """Minimal ANSI SGR parser for airodump-ng --color output."""

    ANSI_RE = re.compile(r"\x1b\[(\d+(?:;\d+)*)m")

    # Map basic ANSI foreground codes to theme colors.
    FG_COLORS = {
        30: "#000000",
        31: "#ff4444",
        32: "#00ff41",
        33: "#ffcc00",
        34: "#00ccff",
        35: "#ff00ff",
        36: "#00ccff",
        37: "#ffffff",
    }
    BG_COLORS = {
        40: "#000000",
        41: "#ff4444",
        42: "#00ff41",
        43: "#ffcc00",
        44: "#00ccff",
        45: "#ff00ff",
        46: "#00ccff",
        47: "#ffffff",
    }

    def parse(self, line: str) -> tuple[str, list[tuple[str, int, int]]]:
        """Return stripped text and list of (tag_name, start, end) tuples."""
        plain = []
        tags = []
        pos = 0
        bold = False
        fg = None
        bg = None
        last_tag = None
        tag_start = 0

        for match in self.ANSI_RE.finditer(line):
            # Append text before the escape code.
            segment = line[pos:match.start()]
            plain.append(segment)
            pos = match.end()

            codes = [int(c) for c in match.group(1).split(";") if c.isdigit()]
            if not codes:
                codes = [0]
            for code in codes:
                if code == 0:
                    bold = False
                    fg = None
                    bg = None
                elif code == 1:
                    bold = True
                elif 30 <= code <= 37:
                    fg = code
                elif 40 <= code <= 47:
                    bg = code

            current_tag = self._tag_name(fg, bg, bold)
            if current_tag != last_tag:
                if last_tag is not None:
                    tags.append((last_tag, tag_start, len("".join(plain))))
                last_tag = current_tag
                tag_start = len("".join(plain))

        # Trailing text after last escape.
        plain.append(line[pos:])
        if last_tag is not None:
            tags.append((last_tag, tag_start, len("".join(plain))))

        return "".join(plain), tags

    def _tag_name(self, fg, bg, bold):
        parts = []
        if fg is not None:
            parts.append(f"fg_{fg}")
        if bg is not None:
            parts.append(f"bg_{bg}")
        if bold:
            parts.append("bold")
        return "ansi_" + "_".join(parts) if parts else "ansi_default"

    def configure_tags(self, text_widget: tk.Text):
        """Create tk.Text tags for all supported ANSI combinations."""
        for fg_code, color in self.FG_COLORS.items():
            text_widget.tag_configure(f"ansi_fg_{fg_code}", foreground=color)
        for bg_code, color in self.BG_COLORS.items():
            text_widget.tag_configure(f"ansi_bg_{bg_code}", background=color)
        text_widget.tag_configure("ansi_bold", font=("Courier", 10, "bold"))
```

### Step 3: Implement Raw View widget and worker

Add the `AirodumpRawView` class:

```python
class AirodumpRawView:
    """Read-only tk.Text widget showing ANSI-colored airodump-ng output."""

    MAX_LINES = 500

    def __init__(self, parent):
        self.text = tk.Text(
            parent,
            bg=THEME["bg"],
            fg=THEME["fg"],
            font=("Consolas", 10),
            wrap=tk.NONE,
            state=tk.DISABLED,
            height=20,
        )
        self.text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ansi = AnsiParser()
        self.ansi.configure_tags(self.text)
        self.queue = queue.Queue()
        self._proc = None
        self._thread = None
        self._running = threading.Event()

    def start(self, cmd: list[str]):
        self.stop()
        self._running.set()
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self):
        for line in self._proc.stdout:
            if not self._running.is_set():
                break
            self.queue.put(line.rstrip("\n"))
        self._proc.wait()

    def stop(self):
        self._running.clear()
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    def flush(self):
        """Call from tkinter main thread to drain queued lines."""
        updated = False
        while not self.queue.empty():
            try:
                line = self.queue.get_nowait()
            except queue.Empty:
                break
            self._append_line(line)
            updated = True
        return updated

    def _append_line(self, line: str):
        self.text.config(state=tk.NORMAL)
        plain, tags = self.ansi.parse(line)
        self.text.insert(tk.END, plain + "\n")
        for tag_name, start, end in tags:
            self.text.tag_add(tag_name, f"end-2c linestart+{start}c", f"end-2c linestart+{end}c")
        # Trim old lines.
        count = int(self.text.index("end-1c").split(".")[0]) - 1
        if count > self.MAX_LINES:
            self.text.delete("1.0", f"{count - self.MAX_LINES}.0")
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)
```

### Step 4: Wire Raw View into the UI

Add `_build_raw_view` to `N2NgApp`:

```python
    def _build_raw_view(self, parent):
        self.raw_view = AirodumpRawView(parent)
```

Update `_start_monitor` to also start the Raw View subprocess:

```python
    def _start_monitor(self):
        iface = self.adapter_var.get()
        if not iface:
            messagebox.showwarning("N2-ng", "No adapter selected.")
            return
        self._log(f"Starting monitor mode on {iface}")
        try:
            self.mon_iface = self.airmon.start_monitor(iface)
            self.status.config(text=f"Monitor: {self.mon_iface}")
            self.pause_btn.config(text="Pause Scan")
            self.worker.start_scan(self.mon_iface, self.current_band.get(), "/tmp/n2ng_scan")
            self._start_raw_view_scan()
        except Exception as e:
            messagebox.showerror("N2-ng", f"Failed to start monitor mode: {e}")

    def _start_raw_view_scan(self):
        if not self.mon_iface:
            return
        band_arg = {"2.4GHz": "bg", "5GHz": "a", "Both": "abg"}.get(self.current_band.get(), "abg")
        cmd = ["airodump-ng", "--band", band_arg, self.mon_iface]
        if _airodump_supports("--color"):
            cmd.append("--color")
        self.raw_view.start(cmd)
```

Update `_stop_monitor`:

```python
    def _stop_monitor(self):
        self.worker.stop()
        self.raw_view.stop()
        if self.mon_iface:
            self.airmon.stop_monitor(self.mon_iface)
            self.mon_iface = None
        self.status.config(text="Monitor stopped")
        self.channel_pill.config(text="SCANNING ALL", bg="red")
        self.pause_btn.config(text="Pause Scan")
```

Update `_lock_target` to also start a locked Raw View subprocess after `self.worker.start_lock(...)`:

```python
        self.worker.start_lock(self.mon_iface, int(ch), bssid, prefix)
        self.capture_manager.set_active_cap(Path(f"{prefix}-01.cap"))
        self._start_raw_view_lock(int(ch), bssid)
```

Add:

```python
    def _start_raw_view_lock(self, channel: int, bssid: str):
        if not self.mon_iface:
            return
        cmd = ["airodump-ng", "-c", str(channel), "--bssid", bssid, self.mon_iface]
        if _airodump_supports("--color"):
            cmd.append("--color")
        self.raw_view.start(cmd)
```

Update `_poll_queue` to flush the Raw View queue:

```python
        # Update Raw View if visible.
        if self.raw_view:
            self.raw_view.flush()
```

### Step 5: Run tests

Run: `xvfb-run python3 -m pytest test_ui.py::test_ansi_parser_produces_tags test_ui.py::test_raw_view_widget_exists -v`
Expected: PASS.

### Step 6: Commit

```bash
git add n2_ng.py test_ui.py
git commit -m "feat: add Raw View tab with ANSI-colored airodump-ng output"
```

---

## Task 4: Visual polish — monospace font, row height, flash effect

**Files:**
- Modify: `/home/kali/n2-ng/n2_ng.py:832-853` (`_configure_ttk_styles`)
- Modify: `/home/kali/n2-ng/n2_ng.py:1458-1476` (`_refresh_tree`)
- Modify: `/home/kali/n2-ng/n2_ng.py` (`__init__` add `_networks_prev`)
- Test: `/home/kali/n2-ng/test_ui.py`

**Interfaces:**
- Consumes: `self.networks`, `self._networks_prev`, `self.tree`.
- Produces: flash effect on PWR/Beacons updates.

### Step 1: Write the failing test

Append to `/home/kali/n2-ng/test_ui.py`:

```python
def test_treeview_is_monospace():
    """Network Treeview must use a monospace font."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    style = ttk.Style(root)
    font = style.lookup("Treeview", "font")
    assert "Courier" in font or "Consolas" in font, f"unexpected Treeview font: {font!r}"
    root.destroy()


def test_flash_on_power_update():
    """A row should temporarily get a flash tag when PWR changes."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    bssid = "AA:BB:CC:DD:EE:FF"
    app.networks[bssid] = {
        "bssid": bssid, "essid": "Net", "power": "-50", "beacons": "10",
        "iv": "0", "channel": "6", "speed": "54", "privacy": "WPA2",
        "cipher": "CCMP", "auth": "PSK", "manufacturer": "",
    }
    app._networks_prev[bssid] = {"power": "-60", "beacons": "10"}
    app._refresh_tree()
    tags = app.tree.item(bssid, "tags")
    assert "flash" in tags
    root.destroy()
```

Run: `xvfb-run python3 -m pytest test_ui.py::test_treeview_is_monospace test_ui.py::test_flash_on_power_update -v`
Expected: FAIL.

### Step 2: Apply monospace font and smaller row height

Update `_configure_ttk_styles`:

```python
        if "Consolas" in tk_font.families():
            self.mono_font = ("Consolas", 10)
            self.mono_font_bold = ("Consolas", 10, "bold")
        else:
            self.mono_font = ("Courier", 10)
            self.mono_font_bold = ("Courier", 10, "bold")

        style.configure(
            "Treeview",
            background=THEME["bg"],
            foreground=THEME["fg"],
            fieldbackground=THEME["bg"],
            font=self.mono_font,
            rowheight=18,
        )
        style.configure(
            "Treeview.Heading",
            background=THEME["panel"],
            foreground=THEME["fg"],
            font=self.mono_font_bold,
        )
```

Add `import tkinter.font as tk_font` at the top of `/home/kali/n2-ng/n2_ng.py`.

### Step 3: Implement flash tracking and effect

In `N2NgApp.__init__`, add:

```python
        self._networks_prev: dict[str, dict] = {}
```

Update `_update_networks`:

```python
    def _update_networks(self, networks: list[dict]):
        flash_bssids = set()
        for net in networks:
            bssid = net["bssid"]
            old = self.networks.get(bssid)
            if old and old.get("essid") == "[Hidden]" and net.get("essid") and net.get("essid") != "[Hidden]":
                self._log(f"Revealed hidden ESSID: {net['essid']} ({bssid})")
            # Detect PWR or Beacons change to flash the row.
            prev = self._networks_prev.get(bssid)
            if prev and (prev.get("power") != net.get("power") or prev.get("beacons") != net.get("beacons")):
                flash_bssids.add(bssid)
            self.networks[bssid] = net
            self._networks_prev[bssid] = {"power": net.get("power", ""), "beacons": net.get("beacons", "")}
            if self.locked_target and self.locked_target["bssid"] == bssid:
                self.locked_target = net
                self._update_target_card(net)
                self.signal_graph.add_sample(net.get("power", -100))
        self._refresh_tree(flash_bssids=flash_bssids)
```

Update `_refresh_tree` signature and flash logic:

```python
    def _refresh_tree(self, flash_bssids: set[str] | None = None):
        flash_bssids = flash_bssids or set()
        ...
        # Insert or update rows.
        for net in networks:
            bssid = net["bssid"]
            values = self._network_values(net)
            tag = self._privacy_tag(net.get("privacy", ""))
            tags = (tag,)
            if bssid in flash_bssids:
                tags = (tag, "flash")
                self.tree.tag_configure("flash", background="#ffff00", foreground="#000000")
                self.root.after(200, lambda b=bssid, t=tag: self._unflash_row(b, t))
            if self.tree.exists(bssid):
                self.tree.item(bssid, values=values, tags=tags)
            else:
                self.tree.insert("", tk.END, iid=bssid, values=values, tags=tags)
        ...

    def _unflash_row(self, bssid: str, tag: str):
        if self.tree.exists(bssid):
            self.tree.item(bssid, tags=(tag,))
```

### Step 4: Run tests

Run: `xvfb-run python3 -m pytest test_ui.py::test_treeview_is_monospace test_ui.py::test_flash_on_power_update -v`
Expected: PASS.

### Step 5: Commit

```bash
git add n2_ng.py test_ui.py
git commit -m "feat: monospace Treeview font and PWR/Beacons flash effect"
```

---

## Task 5: Final verification

**Files:**
- `/home/kali/n2-ng/n2_ng.py`
- `/home/kali/n2-ng/test_ui.py`

### Step 1: Run full test suite

Run: `xvfb-run python3 -m pytest -v`
Expected: all tests pass.

### Step 2: Syntax check

Run: `python3 -m py_compile n2_ng.py`
Expected: no output.

### Step 3: Final commit

```bash
git add n2_ng.py test_ui.py
git commit -m "feat: scrollable right panel, client fix, Raw View, Treeview polish"
```

---

## Self-Review

**Spec coverage:**
- Scrollable right panel → Task 1.
- Client table fix → Task 2.
- Raw View tab → Task 3.
- Visual polish → Task 4.

**Placeholder scan:** No TBD/TODO placeholders.

**Type consistency:**
- `flash_bssids` is `set[str] | None`.
- `AnsiParser.parse` returns `tuple[str, list[tuple[str, int, int]]]`.
- `AirodumpRawView` exposes `start(cmd)`, `stop()`, `flush()`.

All tasks produce independently testable deliverables.
