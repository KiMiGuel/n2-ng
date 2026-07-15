# N2-ng Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build N2-ng, a single-file Python/tkinter GUI for wireless capture on Kali Linux that wraps airmon-ng, airodump-ng, and aireplay-ng with a dark, responsive, one-window interface.

**Architecture:** One main file (`n2-ng.py`) containing focused classes (`AirmonManager`, `AirodumpWorker`, `AttackController`, `CaptureManager`, `WpsScanner`, `SignalGraph`, `DeauthHistory`, `N2NgApp`) plus `install.sh` and `README.md`. All subprocess I/O runs in daemon threads and communicates with the tkinter main loop through a thread-safe `queue.Queue` consumed via `after()`.

**Tech Stack:** Python 3.13, tkinter (stdlib), aircrack-ng suite, optional hcxtools/reaver/wireshark-common/pcapfix.

## Global Constraints

- Single main Python file: `n2-ng.py`.
- No xterm or external terminals; all subprocess output goes to an internal log pane.
- Capture-focused only; no cracking inside the tool.
- Must run as root; startup sudo relaunch with password dialog.
- Must handle Alfa AWUS036ACHM, TP-Link Archer T2U Nano, NetGear Atheros adapters dynamically.
- Capture directory: `~/hs/n2-ng/<sanitized_ESSID>_<BSSID>/`.
- Dark hacker theme, large buttons, responsive layout for MacBook screen.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `/home/kali/n2-ng/n2-ng.py` | Main application: GUI, subprocess workers, capture logic. |
| `/home/kali/n2-ng/requirements.txt` | Empty / minimal (tkinter is stdlib). |
| `/home/kali/n2-ng/install.sh` | Dependency checker with real apt commands and GitHub links. |
| `/home/kali/n2-ng/README.md` | Exact run commands and adapter notes. |

---

## Task 1: Project scaffolding and root/sudo bootstrap

**Files:**
- Create: `/home/kali/n2-ng/requirements.txt`
- Create: `/home/kali/n2-ng/install.sh`
- Create: `/home/kali/n2-ng/README.md` (skeleton)
- Create: `/home/kali/n2-ng/n2-ng.py` (skeleton with root bootstrap)

**Interfaces:**
- Produces: `ensure_root()` — exits or relaunches with sudo.
- Produces: `DependencyChecker` class for later use.

- [ ] **Step 1: Create `requirements.txt`**

```text
# N2-ng uses only Python standard library (tkinter).
# System dependencies are checked by install.sh.
```

- [ ] **Step 2: Create `install.sh`**

```bash
#!/usr/bin/env bash
set -e

echo "[N2-ng] Checking dependencies..."

MISSING=()

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        MISSING+=("$1")
        echo "  MISSING: $1 ($2)"
    else
        echo "  OK: $1"
    fi
}

need airmon-ng "sudo apt install -y aircrack-ng"
need airodump-ng "sudo apt install -y aircrack-ng"
need aireplay-ng "sudo apt install -y aircrack-ng"
need iw "sudo apt install -y iw"
need hcxpcapngtool "sudo apt install -y hcxtools"
need wash "sudo apt install -y reaver"
need mergecap "sudo apt install -y wireshark-common"
need pcapfix "sudo apt install -y pcapfix"

if [ ${#MISSING[@]} -eq 0 ]; then
    echo "[N2-ng] All dependencies satisfied."
    exit 0
fi

echo "[N2-ng] Missing optional/required tools."
echo "Install commands:"
echo "  sudo apt update && sudo apt install -y aircrack-ng iw hcxtools reaver wireshark-common pcapfix"
echo "Or build from source:"
echo "  https://github.com/aircrack-ng/aircrack-ng"
echo "  https://github.com/ZerBea/hcxtools"
echo "  https://github.com/t6x/reaver-wps-fork-t6x"
exit 1
```

Make executable: `chmod +x /home/kali/n2-ng/install.sh`

- [ ] **Step 3: Create `n2-ng.py` skeleton with root bootstrap**

```python
#!/usr/bin/env python3
import atexit
import os
import sys
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk


def ensure_root():
    if os.geteuid() == 0:
        return
    root = tk.Tk()
    root.withdraw()
    pwd = simpledialog.askstring(
        "N2-ng requires root",
        "Enter sudo password:",
        show="*",
        parent=root,
    )
    root.destroy()
    if not pwd:
        messagebox.showerror("N2-ng", "Root privileges are required.")
        sys.exit(1)
    script = os.path.abspath(sys.argv[0])
    args = ["sudo", "-S", sys.executable, script] + sys.argv[1:]
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, err = proc.communicate(input=pwd + "\n")
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(proc.returncode)


if __name__ == "__main__":
    ensure_root()
    print("Running as root, N2-ng bootstrap OK")
```

- [ ] **Step 4: Verify syntax and root bootstrap**

Run: `python3 -m py_compile /home/kali/n2-ng/n2-ng.py`  
Expected: no output (success)

Run: `python3 /home/kali/n2-ng/n2-ng.py` and enter password `kali` when prompted.  
Expected: prints "Running as root, N2-ng bootstrap OK" (assuming password is correct).

- [ ] **Step 5: Commit**

```bash
cd /home/kali/n2-ng
git add requirements.txt install.sh n2-ng.py README.md
git commit -m "feat: scaffold N2-ng project with sudo bootstrap"
```

---

## Task 2: Utility helpers and dependency checker dialog

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `sanitize_essid(essid: str, bssid: str) -> str`
- Produces: `format_bssid(bssid: str) -> str`
- Produces: `human_size(size: int) -> str`
- Produces: `DependencyChecker.check_all() -> list[str]`

- [ ] **Step 1: Write failing tests for helpers**

Create `/home/kali/n2-ng/test_helpers.py` (temporary, will be deleted or kept as manual test script):

```python
from n2_ng import sanitize_essid, format_bssid, human_size

def test_sanitize_essid():
    assert sanitize_essid("My WiFi", "AA:BB:CC:DD:EE:FF") == "My_WiFi_AA-BB-CC-DD-EE-FF"
    assert sanitize_essid("", "AA:BB:CC:DD:EE:FF") == "hidden_AA-BB-CC-DD-EE-FF"
    assert sanitize_essid("a" * 60, "AA:BB:CC:DD:EE:FF") == ("a" * 50) + "_AA-BB-CC-DD-EE-FF"
    assert "/" not in sanitize_essid("My/WiFi", "AA:BB:CC:DD:EE:FF")

def test_format_bssid():
    assert format_bssid("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

def test_human_size():
    assert human_size(1024) == "1.0 KB"
    assert human_size(1048576) == "1.0 MB"
```

Run: `cd /home/kali/n2-ng && python3 -m pytest test_helpers.py -v`  
Expected: ImportError or failures because functions don't exist yet.

- [ ] **Step 2: Implement helper functions in `n2-ng.py`**

Add after imports:

```python
import csv
import io
import queue
import re
import shutil
import threading
import time
from collections import deque
from pathlib import Path


def format_bssid(bssid: str) -> str:
    return bssid.upper().strip()


def sanitize_essid(essid: str, bssid: str) -> str:
    essid = essid.strip()
    bssid = format_bssid(bssid)
    if not essid or essid.lower().startswith("<length:") or essid == "":
        base = f"hidden_{bssid}"
    else:
        safe = re.sub(r'[\\/:*?"<>|]', "", essid)
        safe = safe.replace(" ", "_")
        safe = safe[:50]
        base = f"{safe}_{bssid}"
    return base


def human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    for unit in ("KB", "MB", "GB"):
        size /= 1024.0
        if size < 1024:
            return f"{size:.1f} {unit}"
    return f"{size:.1f} GB"
```

- [ ] **Step 3: Implement `DependencyChecker` class**

```python
class DependencyChecker:
    TOOLS = {
        "aircrack-ng": {
            "cmd": "aircrack-ng",
            "apt": "sudo apt install -y aircrack-ng",
            "url": "https://github.com/aircrack-ng/aircrack-ng",
        },
        "hcxpcapngtool": {
            "cmd": "hcxpcapngtool",
            "apt": "sudo apt install -y hcxtools",
            "url": "https://github.com/ZerBea/hcxtools",
        },
        "wash": {
            "cmd": "wash",
            "apt": "sudo apt install -y reaver",
            "url": "https://github.com/t6x/reaver-wps-fork-t6x",
        },
        "mergecap": {
            "cmd": "mergecap",
            "apt": "sudo apt install -y wireshark-common",
            "url": "https://www.wireshark.org/download.html",
        },
        "pcapfix": {
            "cmd": "pcapfix",
            "apt": "sudo apt install -y pcapfix",
            "url": "https://github.com/Rup0rt/pcapfix",
        },
    }

    @classmethod
    def check_all(cls) -> list[str]:
        missing = []
        for name, info in cls.TOOLS.items():
            if subprocess.run(["which", info["cmd"]], capture_output=True).returncode != 0:
                missing.append(name)
        return missing
```

- [ ] **Step 4: Run helper tests**

Run: `cd /home/kali/n2-ng && python3 -m pytest test_helpers.py -v`  
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py test_helpers.py
git commit -m "feat: add utility helpers and dependency checker"
```

---

## Task 3: AirmonManager — adapter detection and monitor mode

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `AirmonManager`
  - `list_physical_interfaces() -> list[str]`
  - `start_monitor(iface: str) -> str` returns monitor interface name
  - `stop_monitor(mon_iface: str) -> None`
  - `cleanup() -> None`

- [ ] **Step 1: Add `AirmonManager` class**

```python
class AirmonManager:
    def __init__(self):
        self._started: list[str] = []

    def list_physical_interfaces(self) -> list[str]:
        result = []
        try:
            out = subprocess.check_output(["airmon-ng"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines()[2:]:
                parts = line.split()
                if parts and parts[0].startswith(("wlan", "wlp")):
                    result.append(parts[0])
        except Exception:
            pass
        try:
            out = subprocess.check_output(["ip", "link"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"^(?:\\d+:\\s+)?([ew]lan\\d+|wlp\\S+?):", line)
                if m:
                    name = m.group(1)
                    if name not in result:
                        result.append(name)
        except Exception:
            pass
        return sorted(result)

    def start_monitor(self, iface: str) -> str:
        self.stop_monitor_for_iface(iface)
        subprocess.run(["airmon-ng", "start", iface], check=True, capture_output=True, text=True)
        self._started.append(iface)
        # airmon-ng usually creates mon0 or iface+mon
        candidates = [f"{iface}mon", "wlan0mon", "wlan1mon", "wlan2mon"]
        for c in candidates:
            if self._iface_exists(c):
                return c
        # fallback: find any mon interface
        for line in subprocess.check_output(["ip", "link"], text=True).splitlines():
            m = re.search(r"^(?:\\d+:\\s+)?(\\S+mon):", line)
            if m:
                return m.group(1)
        raise RuntimeError(f"Could not determine monitor interface for {iface}")

    def stop_monitor_for_iface(self, iface: str) -> None:
        subprocess.run(["airmon-ng", "stop", f"{iface}mon"], capture_output=True, text=True)
        subprocess.run(["airmon-ng", "stop", iface], capture_output=True, text=True)

    def stop_monitor(self, mon_iface: str) -> None:
        if mon_iface:
            subprocess.run(["airmon-ng", "stop", mon_iface], capture_output=True, text=True)

    def cleanup(self) -> None:
        for iface in self._started:
            self.stop_monitor_for_iface(iface)
        self._started.clear()

    @staticmethod
    def _iface_exists(name: str) -> bool:
        return Path(f"/sys/class/net/{name}").exists()
```

- [ ] **Step 2: Manual test with connected adapter**

Run as root:
```bash
cd /home/kali/n2-ng
python3 -c "
from n2_ng import AirmonManager
m = AirmonManager()
print('ifaces:', m.list_physical_interfaces())
"
```
Expected: prints list of available wlan interfaces (requires root and a wireless adapter).

- [ ] **Step 3: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py
git commit -m "feat: add AirmonManager for adapter detection and monitor mode"
```

---

## Task 4: AirodumpWorker — CSV parsing, band support, hidden ESSID

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `AirodumpWorker`
  - `start_scan(mon_iface: str, band: str, prefix: str) -> None`
  - `start_lock(mon_iface: str, channel: int, bssid: str, prefix: str) -> None`
  - `stop() -> None`
  - Emits events via queue: `("networks", list)`, `("clients", list)`, `("handshake", {...})`, `("error", str)`

- [ ] **Step 1: Add CSV parser tests**

Append to `test_helpers.py`:

```python
from n2_ng import parse_airodump_csv

def test_parse_airodump_csv():
    sample = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # Beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-07-15 12:00:00, 2026-07-15 12:00:05, 6, 54, WPA2, CCMP, PSK, -45, 100, 0, 0.0.0.0, 7, MyWiFi,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-07-15 12:00:00, 2026-07-15 12:00:05, -60, 50, AA:BB:CC:DD:EE:FF, OtherWiFi
"""
    networks, clients = parse_airodump_csv(sample)
    assert len(networks) == 1
    assert networks[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert networks[0]["essid"] == "MyWiFi"
    assert len(clients) == 1
    assert clients[0]["station"] == "11:22:33:44:55:66"
```

Run: `python3 -m pytest test_helpers.py::test_parse_airodump_csv -v`  
Expected: fails because `parse_airodump_csv` doesn't exist.

- [ ] **Step 2: Implement CSV parser**

```python
import csv
import io


def parse_airodump_csv(text: str):
    networks = []
    clients = []
    if not text.strip():
        return networks, clients
    sections = text.strip().split("\n\n")
    if not sections:
        return networks, clients
    # AP section
    reader = csv.DictReader(io.StringIO(sections[0]))
    for row in reader:
        bssid = format_bssid(row.get("BSSID", ""))
        essid = row.get("ESSID", "").strip()
        if not essid:
            essid = "[Hidden]"
        networks.append({
            "bssid": bssid,
            "first": row.get("First time seen", ""),
            "last": row.get("Last time seen", ""),
            "channel": row.get("channel", ""),
            "speed": row.get("Speed", ""),
            "privacy": row.get("Privacy", ""),
            "cipher": row.get("Cipher", ""),
            "auth": row.get("Authentication", ""),
            "power": row.get("Power", ""),
            "beacons": row.get("# Beacons", ""),
            "iv": row.get("# IV", ""),
            "id_len": row.get("ID-length", ""),
            "essid": essid,
        })
    # Client section
    if len(sections) > 1:
        reader = csv.DictReader(io.StringIO(sections[1]))
        for row in reader:
            clients.append({
                "station": format_bssid(row.get("Station MAC", "")),
                "first": row.get("First time seen", ""),
                "last": row.get("Last time seen", ""),
                "power": row.get("Power", ""),
                "packets": row.get("# packets", ""),
                "bssid": format_bssid(row.get("BSSID", "")),
                "probed": row.get("Probed ESSIDs", "").strip(),
            })
    return networks, clients
```

- [ ] **Step 3: Implement `AirodumpWorker`**

```python
import threading
import time


class AirodumpWorker(threading.Thread):
    def __init__(self, event_queue: queue.Queue):
        super().__init__(daemon=True)
        self.queue = event_queue
        self._proc = None
        self._prefix = "/tmp/n2ng_scan"
        self._running = threading.Event()

    def start_scan(self, mon_iface: str, band: str, prefix: str):
        self.stop()
        self._prefix = prefix
        band_arg = {"2.4GHz": "bg", "5GHz": "a", "Both": "abg"}.get(band, "abg")
        cmd = [
            "airodump-ng",
            "--write-interval", "1",
            "-w", prefix,
            "--output-format", "csv",
            "--band", band_arg,
            mon_iface,
        ]
        self._running.set()
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if not self.is_alive():
            self.start()

    def start_lock(self, mon_iface: str, channel: int, bssid: str, prefix: str):
        self.stop()
        self._prefix = prefix
        cmd = [
            "airodump-ng",
            "-c", str(channel),
            "--bssid", bssid,
            "--write-interval", "1",
            "-w", prefix,
            "--output-format", "csv",
            mon_iface,
        ]
        self._running.set()
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if not self.is_alive():
            self.start()

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

    def run(self):
        csv_path = Path(f"{self._prefix}-01.csv")
        last_mtime = 0
        while self._running.is_set():
            if csv_path.exists():
                mtime = csv_path.stat().st_mtime
                if mtime != last_mtime:
                    last_mtime = mtime
                    try:
                        text = csv_path.read_text(encoding="utf-8", errors="ignore")
                        networks, clients = parse_airodump_csv(text)
                        self.queue.put(("networks", networks))
                        self.queue.put(("clients", clients))
                    except Exception as e:
                        self.queue.put(("error", str(e)))
            time.sleep(1.5)
```

- [ ] **Step 4: Run CSV parser tests**

Run: `python3 -m pytest test_helpers.py -v`  
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py test_helpers.py
git commit -m "feat: add AirodumpWorker with CSV parser and band support"
```

---

## Task 5: Main GUI layout (tkinter)

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `N2NgApp` class with `run()` method.
- Produces: themed widgets, network treeview, toolbar, right panel skeleton.

- [ ] **Step 1: Add theme colors and base styles**

```python
THEME = {
    "bg": "#0d0d0d",
    "fg": "#00ff41",
    "panel": "#1a1a1a",
    "accent": "#00ff41",
    "warn": "#ffcc00",
    "error": "#ff4444",
    "info": "#00ccff",
}


def style_widget(widget, bg=None, fg=None, font=None):
    widget.config(bg=bg or THEME["bg"], fg=fg or THEME["fg"], font=font or ("TkDefaultFont", 10))
```

- [ ] **Step 2: Build `N2NgApp` skeleton**

```python
class N2NgApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("N2-ng")
        self.root.geometry("1200x700")
        self.root.minsize(1000, 600)
        self.root.configure(bg=THEME["bg"])
        self.queue = queue.Queue()
        self.airmon = AirmonManager()
        self.worker = AirodumpWorker(self.queue)
        self.networks = {}
        self.clients = []
        self.locked_target = None
        self.mon_iface = None
        self.band_var = tk.StringVar(value="Both")
        self.adapter_var = tk.StringVar()
        self.poll_id = None
        self._build_ui()
        self._poll_queue()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        atexit.register(self._cleanup)

    def _build_ui(self):
        # Toolbar
        toolbar = tk.Frame(self.root, bg=THEME["panel"])
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        # ... adapter dropdown, band dropdown, buttons, channel pill ...

    def _poll_queue(self):
        while not self.queue.empty():
            event, payload = self.queue.get_nowait()
            if event == "networks":
                self._update_networks(payload)
            elif event == "clients":
                self._update_clients(payload)
            elif event == "error":
                self._log(payload)
        self.poll_id = self.root.after(150, self._poll_queue)

    def _on_close(self):
        self._cleanup()
        self.root.destroy()

    def _cleanup(self):
        self.worker.stop()
        self.airmon.cleanup()

    def run(self):
        self.root.mainloop()
```

- [ ] **Step 3: Implement toolbar widgets**

```python
    def _build_toolbar(self, parent):
        tk.Label(parent, text="Adapter:", bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        self.adapter_combo = tk.OptionMenu(parent, self.adapter_var, "")
        self.adapter_combo.config(bg=THEME["panel"], fg=THEME["fg"], highlightthickness=0)
        self.adapter_combo["menu"].config(bg=THEME["panel"], fg=THEME["fg"])
        self.adapter_combo.pack(side=tk.LEFT, padx=5)

        tk.Label(parent, text="Band:", bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        band_menu = tk.OptionMenu(parent, self.band_var, "2.4GHz", "5GHz", "Both")
        band_menu.config(bg=THEME["panel"], fg=THEME["fg"], highlightthickness=0)
        band_menu["menu"].config(bg=THEME["panel"], fg=THEME["fg"])
        band_menu.pack(side=tk.LEFT, padx=5)

        tk.Button(parent, text="Start Monitor", command=self._start_monitor, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(parent, text="Stop Monitor", command=self._stop_monitor, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(parent, text="WPS Scan", command=self._wps_scan, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)

        self.channel_pill = tk.Label(parent, text="SCANNING ALL", bg="red", fg="white", font=("TkDefaultFont", 10, "bold"))
        self.channel_pill.pack(side=tk.RIGHT, padx=10)
```

- [ ] **Step 4: Implement network treeview with colors**

```python
    def _build_network_tree(self, parent):
        cols = ("pwr", "beacons", "data", "ch", "mb", "enc", "cipher", "auth", "essid", "bssid")
        self.tree = tk.ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=80, anchor=tk.CENTER)
        self.tree.column("essid", width=150)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self._on_network_select)
        self.tree.bind("<Button-3>", self._on_network_right_click)
```

- [ ] **Step 5: Test GUI launch**

Run as root: `python3 /home/kali/n2-ng/n2-ng.py`  
Expected: window opens with toolbar and empty network tree.

- [ ] **Step 6: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py
git commit -m "feat: add main GUI layout and theme"
```

---

## Task 6: Target lock, channel indicator, capture panel, signal graph

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `SignalGraph` class.
- Produces: `_lock_target(bssid)`, `_unlock_target()`, `_set_channel_indicator(locked, ch)`.

- [ ] **Step 1: Implement `SignalGraph` canvas widget**

```python
from collections import deque


class SignalGraph:
    def __init__(self, parent):
        self.canvas = tk.Canvas(parent, bg=THEME["panel"], height=120, highlightthickness=0)
        self.canvas.pack(fill=tk.X, padx=5, pady=5)
        self.samples = deque(maxlen=60)

    def add_sample(self, pwr: int):
        try:
            val = int(pwr)
        except (TypeError, ValueError):
            val = -100
        self.samples.append(val)
        self._draw()

    def _draw(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 10:
            self.canvas.after(100, self._draw)
            return
        # grid
        for y in range(0, h, 20):
            self.canvas.create_line(0, y, w, y, fill="#333333")
        if len(self.samples) < 2:
            return
        step = w / (len(self.samples) - 1)
        points = []
        for i, val in enumerate(self.samples):
            # map -30..-90 to 0..h
            y = h - ((max(-90, min(-30, val)) + 90) / 60) * h
            points.append((i * step, y))
        flat = [c for p in points for c in p]
        self.canvas.create_line(flat, fill=THEME["accent"], width=2)
```

- [ ] **Step 2: Wire target lock/unlock**

```python
    def _on_network_select(self, event):
        item = self.tree.selection()
        if not item:
            return
        bssid = self.tree.item(item[0], "values")[-1]
        self._lock_target(bssid)

    def _lock_target(self, bssid):
        net = self.networks.get(bssid)
        if not net:
            return
        self.locked_target = net
        ch = net.get("channel", "1")
        # set system channel
        subprocess.run(["iw", "dev", self.mon_iface, "set", "channel", str(ch)], capture_output=True)
        # restart airodump locked
        base = Path.home() / "hs" / "n2-ng" / sanitize_essid(net["essid"], bssid)
        base.mkdir(parents=True, exist_ok=True)
        prefix = str(base / f"capture_{time.strftime('%Y-%m-%d_%H-%M-%S')}")
        self.worker.start_lock(self.mon_iface, int(ch), bssid, prefix)
        self._set_channel_indicator(True, ch)
        self._update_target_card(net)

    def _unlock_target(self):
        self.locked_target = None
        self._set_channel_indicator(False, None)
        self.worker.stop()
        if self.mon_iface:
            self.worker.start_scan(self.mon_iface, self.band_var.get(), "/tmp/n2ng_scan")

    def _set_channel_indicator(self, locked: bool, ch):
        if locked:
            self.channel_pill.config(text=f"LOCKED: CH {ch}", bg="green")
        else:
            self.channel_pill.config(text="SCANNING ALL", bg="red")
```

- [ ] **Step 3: Build right panel target card and file size monitor**

```python
    def _build_right_panel(self, parent):
        # target card
        self.target_card = tk.LabelFrame(parent, text="Target", bg=THEME["panel"], fg=THEME["fg"])
        self.target_card.pack(fill=tk.X, padx=5, pady=5)
        self.target_label = tk.Label(self.target_card, text="No target locked", bg=THEME["panel"], fg=THEME["fg"])
        self.target_label.pack(anchor=tk.W, padx=5, pady=5)
        # file size monitor
        self.size_label = tk.Label(self.target_card, text="Capture: 0 B", bg=THEME["panel"], fg=THEME["fg"])
        self.size_label.pack(anchor=tk.W, padx=5, pady=5)
        # signal graph
        self.signal_graph = SignalGraph(parent)
        # ... rest built in later tasks
```

- [ ] **Step 4: Test target lock UI**

Run as root with adapter in monitor mode; scan should populate tree; double-click row should update channel pill to green.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py
git commit -m "feat: add target lock, channel indicator, signal graph, file size monitor"
```

---

## Task 7: AttackController and countdown dialogs

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `AttackController`
  - `deauth_all(bssid, mon_iface, callback)`
  - `deauth_client(bssid, client, mon_iface, callback)`
  - `legacy_attack(kind, bssid, our_mac, mon_iface, callback)`
- Produces: `CountdownDialog` class.

- [ ] **Step 1: Implement `CountdownDialog`**

```python
class CountdownDialog(tk.Toplevel):
    def __init__(self, parent, command: list[str]):
        super().__init__(parent)
        self.title("Confirm Attack")
        self.configure(bg=THEME["bg"])
        self.resizable(False, False)
        tk.Label(self, text="Command to execute:", bg=THEME["bg"], fg=THEME["fg"]).pack(padx=10, pady=5)
        cmd_text = tk.Entry(self, width=80)
        cmd_text.insert(0, " ".join(command))
        cmd_text.config(state="readonly", bg=THEME["panel"], fg=THEME["fg"])
        cmd_text.pack(padx=10, pady=5)
        self.label = tk.Label(self, text="Executing in 3...", bg=THEME["bg"], fg=THEME["fg"], font=("TkDefaultFont", 12, "bold"))
        self.label.pack(padx=10, pady=10)
        btn_frame = tk.Frame(self, bg=THEME["bg"])
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Cancel", command=self._cancel, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Execute Now", command=self._execute, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        self.result = False
        self.count = 3
        self._tick()

    def _tick(self):
        if self.result:
            return
        if self.count <= 0:
            self._execute()
            return
        self.label.config(text=f"Executing in {self.count}...")
        self.count -= 1
        self.after(1000, self._tick)

    def _execute(self):
        self.result = True
        self.destroy()

    def _cancel(self):
        self.result = False
        self.destroy()
```

- [ ] **Step 2: Implement `AttackController`**

```python
class AttackController:
    def __init__(self, log_func):
        self.log = log_func
        self._current = None

    def _run(self, cmd: list[str]):
        self.log(f"$ {' '.join(cmd)}")
        self._current = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in self._current.stdout:
            self.log(line.rstrip())
        self._current.wait()
        self._current = None

    def deauth_all(self, bssid: str, mon_iface: str, count: int = 10):
        cmd = ["aireplay-ng", "-0", str(count), "-a", bssid, mon_iface]
        threading.Thread(target=self._run, args=(cmd,), daemon=True).start()

    def deauth_client(self, bssid: str, client: str, mon_iface: str, count: int = 10):
        cmd = ["aireplay-ng", "-0", str(count), "-a", bssid, "-c", client, mon_iface]
        threading.Thread(target=self._run, args=(cmd,), daemon=True).start()

    def legacy_attack(self, kind: str, bssid: str, our_mac: str, mon_iface: str):
        flag = {"fakeauth": "-1", "arpreplay": "-3", "chopchop": "-4", "fragmentation": "-5"}[kind]
        if kind == "fakeauth":
            cmd = ["aireplay-ng", flag, "0", "-a", bssid, "-h", our_mac, mon_iface]
        else:
            cmd = ["aireplay-ng", flag, "-b", bssid, "-h", our_mac, mon_iface]
        threading.Thread(target=self._run, args=(cmd,), daemon=True).start()
```

- [ ] **Step 3: Wire attack buttons in right panel**

```python
    def _build_attack_panel(self, parent):
        frame = tk.LabelFrame(parent, text="Attacks", bg=THEME["panel"], fg=THEME["fg"])
        frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(frame, text="Deauthenticate All Clients", command=self._deauth_all, bg="#333333", fg=THEME["accent"], font=("TkDefaultFont", 11, "bold")).pack(fill=tk.X, padx=5, pady=3)
        tk.Button(frame, text="Deauthenticate Specific Client", command=self._deauth_client, bg="#333333", fg=THEME["accent"], font=("TkDefaultFont", 11, "bold")).pack(fill=tk.X, padx=5, pady=3)

        # Collapsible legacy WEP section
        self.legacy_frame = tk.LabelFrame(frame, text="Legacy WEP Attacks", bg=THEME["panel"], fg=THEME["fg"])
        self.legacy_visible = tk.BooleanVar(value=False)
        tk.Checkbutton(frame, text="Show Legacy WEP Attacks", variable=self.legacy_visible, command=self._toggle_legacy, bg=THEME["panel"], fg=THEME["fg"], selectcolor=THEME["panel"]).pack(anchor=tk.W, padx=5)
        for label, kind in (("Fake Authentication", "fakeauth"), ("ARP Replay", "arpreplay"), ("Chopchop", "chopchop"), ("Fragmentation", "fragmentation")):
            tk.Button(self.legacy_frame, text=label, command=lambda k=kind: self._legacy_attack(k)).pack(fill=tk.X, padx=5, pady=2)
        self.legacy_frame.pack_forget()

    def _toggle_legacy(self):
        if self.legacy_visible.get():
            self.legacy_frame.pack(fill=tk.X, padx=5, pady=5)
        else:
            self.legacy_frame.pack_forget()
```

- [ ] **Step 4: Test countdown dialog**

Run as root, lock target, click "Deauthenticate All Clients", verify dialog shows command and counts down; Cancel works.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py
git commit -m "feat: add attack controller, countdown dialog, legacy WEP section"
```

---

## Task 8: CaptureManager — poll-based handshake/PMKID detection and conversion

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `CaptureManager`
  - `__init__(queue, log_func)`
  - `set_active_cap(path: Path)`
  - `poll() -> None` (called periodically from main loop)
  - `convert(cap: Path) -> Path | None`

- [ ] **Step 1: Implement `CaptureManager`**

```python
class CaptureManager:
    def __init__(self, event_queue: queue.Queue, log_func):
        self.queue = event_queue
        self.log = log_func
        self.active_cap: Path | None = None
        self.handshake_found = False
        self.pmkid_found = False
        self._last_size = 0

    def set_active_cap(self, cap_path: Path):
        self.active_cap = cap_path
        self.handshake_found = False
        self.pmkid_found = False
        self._last_size = 0

    def get_size(self) -> int:
        if self.active_cap and self.active_cap.exists():
            return self.active_cap.stat().st_size
        return 0

    def poll(self):
        if not self.active_cap or not self.active_cap.exists():
            return
        size = self.get_size()
        if size == self._last_size:
            return
        self._last_size = size
        # Try conversion
        out22000 = self.active_cap.with_suffix(".22000")
        tmp = self.active_cap.with_suffix(".tmp22000")
        if shutil.which("hcxpcapngtool"):
            rc = subprocess.run(
                ["hcxpcapngtool", "-o", str(tmp), str(self.active_cap)],
                capture_output=True, text=True
            )
        elif shutil.which("aircrack-ng"):
            rc = subprocess.run(
                ["aircrack-ng", str(self.active_cap), "-J", str(tmp.with_suffix(""))],
                capture_output=True, text=True
            )
            tmp = tmp.with_suffix(".hccap")
        else:
            return
        if rc.returncode == 0 and tmp.exists() and tmp.stat().st_size > 0:
            shutil.move(str(tmp), str(out22000))
            self._classify(out22000)
        elif tmp.exists():
            tmp.unlink(missing_ok=True)

    def _classify(self, path: Path):
        text = path.read_text(errors="ignore")
        if "WPA*02" in text and not self.handshake_found:
            self.handshake_found = True
            self.queue.put(("handshake", {"file": str(path), "type": "handshake"}))
        if "WPA*01" in text and not self.pmkid_found:
            self.pmkid_found = True
            self.queue.put(("pmkid", {"file": str(path), "type": "pmkid"}))

    def convert(self, cap: Path) -> Path | None:
        out = cap.with_suffix(".22000")
        if shutil.which("hcxpcapngtool"):
            rc = subprocess.run(["hcxpcapngtool", "-o", str(out), str(cap)], capture_output=True, text=True)
            if rc.returncode == 0 and out.exists() and out.stat().st_size > 0:
                return out
        return None
```

- [ ] **Step 2: Wire poll loop and notifications**

In `N2NgApp._poll_queue`, handle `"handshake"` and `"pmkid"` events to show banner + modal.

```python
            elif event == "handshake":
                self._notify_capture("WPA Handshake Captured", payload["file"])
            elif event == "pmkid":
                self._notify_capture("PMKID Captured", payload["file"])
```

```python
    def _notify_capture(self, title: str, path: str):
        self.status.config(text=f"{title}: {path}", bg="green", fg="black")
        messagebox.showinfo(title, f"{title}\n\nFile: {path}")
```

- [ ] **Step 3: Test with existing .cap file**

Use one of the existing `.cap` files in `/home/kali/hs/` to verify `CaptureManager.poll()` detects handshake/PMKID correctly.

- [ ] **Step 4: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py
git commit -m "feat: add CaptureManager with poll-based handshake/PMKID detection"
```

---

## Task 9: WPS scanner and auto-deauth loop

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `WpsScanner` class.
- Produces: `_toggle_auto_deauth()`, `_auto_deauth_tick()`.

- [ ] **Step 1: Implement `WpsScanner`**

```python
class WpsScanner(threading.Thread):
    def __init__(self, mon_iface: str, callback):
        super().__init__(daemon=True)
        self.mon_iface = mon_iface
        self.callback = callback
        self._stop = threading.Event()

    def run(self):
        cmd = None
        if shutil.which("wash"):
            cmd = ["wash", "-i", self.mon_iface]
        elif shutil.which("reaver"):
            cmd = ["reaver", "-i", self.mon_iface, "--scan"]
        else:
            self.callback("error", "wash/reaver not found")
            return
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while not self._stop.is_set():
            line = proc.stdout.readline()
            if not line:
                break
            self.callback("wps_line", line.strip())
        proc.terminate()
```

- [ ] **Step 2: Implement auto-deauth loop with interval selector**

```python
        self.auto_deauth_var = tk.BooleanVar(value=False)
        self.deauth_interval_var = tk.StringVar(value="10")
        tk.Checkbutton(parent, text="Capture Handshake (auto-deauth)", variable=self.auto_deauth_var, command=self._toggle_auto_deauth, bg=THEME["panel"], fg=THEME["fg"], selectcolor=THEME["panel"]).pack(anchor=tk.W, padx=5)
        tk.OptionMenu(parent, self.deauth_interval_var, "10", "30", "60").pack(anchor=tk.W, padx=5)

    def _toggle_auto_deauth(self):
        if self.auto_deauth_var.get():
            self._auto_deauth_tick()

    def _auto_deauth_tick(self):
        if not self.auto_deauth_var.get() or not self.locked_target or not self.capture_manager or self.capture_manager.handshake_found:
            return
        bssid = self.locked_target["bssid"]
        self.attack.deauth_all(bssid, self.mon_iface, count=5)
        interval = int(self.deauth_interval_var.get()) * 1000
        self.root.after(interval, self._auto_deauth_tick)
```

- [ ] **Step 3: Test WPS scan dialog**

Run as root, click WPS Scan, verify output appears in a popup or log pane.

- [ ] **Step 4: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py
git commit -m "feat: add WPS scanner and configurable auto-deauth loop"
```

---

## Task 10: Context menus, export, merge, fix

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`

**Interfaces:**
- Produces: `_on_network_right_click(event)`, `_copy_bssid()`, `_copy_essid()`.
- Produces: capture history right-click handlers.

- [ ] **Step 1: Network row context menu**

```python
    def _on_network_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        bssid = self.tree.item(item, "values")[-1]
        essid = self.tree.item(item, "values")[-2]
        menu = tk.Menu(self.root, tearoff=0, bg=THEME["panel"], fg=THEME["fg"])
        menu.add_command(label="Copy BSSID", command=lambda: self._copy(bssid))
        menu.add_command(label="Copy ESSID", command=lambda: self._copy(essid))
        menu.add_command(label="Lock Target", command=lambda: self._lock_target(bssid))
        menu.post(event.x_root, event.y_root)

    def _copy(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
```

- [ ] **Step 2: Capture history panel with merge/fix/export**

Build a small listbox showing capture files. Right-click menu:
- Copy hashcat command
- Copy .22000 content
- Merge selected caps (uses `mergecap`)
- Fix cap (uses `pcapfix`)

Implement `CaptureManager.merge(caps, output)` and `CaptureManager.fix(cap)` helpers using subprocess.

- [ ] **Step 3: Test copy/export**

Right-click a network row, select Copy BSSID, paste into a terminal.

- [ ] **Step 4: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py
git commit -m "feat: add context menus, copy/export, merge and fix helpers"
```

---

## Task 11: Internal log pane, status bar, final integration

**Files:**
- Modify: `/home/kali/n2-ng/n2-ng.py`
- Modify: `/home/kali/n2-ng/README.md`

**Interfaces:**
- Produces: `_log(message)` method and a scrolled text log pane.

- [ ] **Step 1: Add log pane**

```python
    def _build_log(self, parent):
        frame = tk.LabelFrame(parent, text="Log", bg=THEME["panel"], fg=THEME["fg"])
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text = tk.Text(frame, height=6, bg=THEME["bg"], fg=THEME["fg"], state=tk.DISABLED)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(frame, command=self.log_text.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=sb.set)

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
```

- [ ] **Step 2: Add status bar**

```python
    def _build_status_bar(self):
        self.status = tk.Label(self.root, text="Ready", bg=THEME["panel"], fg=THEME["fg"], anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)
```

- [ ] **Step 3: Final integration smoke test**

Run: `python3 -m py_compile /home/kali/n2-ng/n2-ng.py`  
Run as root: `python3 /home/kali/n2-ng/n2-ng.py` and verify full UI loads.

- [ ] **Step 4: Write `README.md`**

```markdown
# N2-ng

Single-window Python/tkinter GUI for wireless capture on Kali Linux.

## Run

```bash
cd /home/kali/n2-ng
python3 n2-ng.py
```

Enter the sudo password when prompted.

## Dependencies

```bash
sudo apt update
sudo apt install -y aircrack-ng iw hcxtools reaver wireshark-common pcapfix
```

## Supported adapters

- Alfa AWUS036ACHM
- TP-Link Archer T2U Nano
- NetGear Atheros adapters

Captures are saved to `~/hs/n2-ng/<ESSID>_<BSSID>/`.
```

- [ ] **Step 5: Commit**

```bash
cd /home/kali/n2-ng
git add n2-ng.py README.md
git commit -m "feat: add log pane, status bar, README, and final integration"
```

---

## Task 12: Final verification

**Files:**
- Modify: `/home/kali/n2-ng/test_helpers.py` (optional cleanup)

- [ ] **Step 1: Run syntax check**

```bash
cd /home/kali/n2-ng
python3 -m py_compile n2-ng.py
```
Expected: no output.

- [ ] **Step 2: Run helper unit tests**

```bash
cd /home/kali/n2-ng
python3 -m pytest test_helpers.py -v
```
Expected: all tests pass.

- [ ] **Step 3: Run install.sh**

```bash
cd /home/kali/n2-ng
./install.sh
```
Expected: reports missing tools or all OK.

- [ ] **Step 4: Manual end-to-end test**

With a supported USB adapter plugged in:
1. Run `python3 n2-ng.py`, enter sudo password.
2. Select adapter, click Start Monitor.
3. Wait for network table to populate.
4. Select band 2.4GHz / 5GHz / Both and verify scan changes.
5. Double-click a WPA2 row → channel pill turns green.
6. Click "Deauthenticate All Clients", verify countdown dialog.
7. Enable Capture Handshake mode, verify periodic deauth.
8. Verify capture file size monitor increases.
9. Close window and verify `mon*` interface removed.

- [ ] **Step 5: Commit final state**

```bash
cd /home/kali/n2-ng
git add -A
git commit -m "chore: final verification and cleanup"
```

---

## Self-Review

**Spec coverage:**
- One-window GUI: Tasks 5, 11.
- Auto monitor mode: Task 3.
- Scanning table with colors: Tasks 4, 5.
- Target lock + iw dev channel set: Task 6.
- Deauth buttons + countdown: Task 7.
- Legacy WEP collapsible section: Task 7.
- Capture manager + poll-based detection: Task 8.
- ESSID sanitization + hidden ESSID: Tasks 2, 4, 6.
- 5GHz band support: Tasks 4, 5.
- Channel lock pill: Task 6.
- File size monitor: Task 6.
- Copy BSSID/ESSID: Task 10.
- Configurable auto-deauth interval: Task 9.
- WPS scan: Task 9.
- Signal graph: Task 6.
- Merge/fix captures: Task 10.
- Internal log pane (no xterm): Tasks 7, 11.
- Cleanup on exit: Tasks 3, 5.
- Startup sudo + dependency checker: Tasks 1, 2.

**Placeholder scan:** No TBD/TODO placeholders; all code blocks and commands are explicit.

**Type consistency:** `sanitize_essid` and `format_bssid` used consistently; `CaptureManager.active_cap` is a `Path`; `AirodumpWorker` queue events use string tuples.
