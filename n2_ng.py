#!/usr/bin/env python3
import atexit
import csv
import io
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk


THEME = {
    "bg": "#0d0d0d",
    "fg": "#00ff41",
    "panel": "#1a1a1a",
    "accent": "#00ff41",
    "warn": "#ffcc00",
    "error": "#ff4444",
    "info": "#00ccff",
}


def format_bssid(bssid: str) -> str:
    return bssid.upper().strip()


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
    """Detect wireless adapters and manage airmon-ng monitor mode."""

    def __init__(self):
        self._started: list[str] = []

    def list_physical_interfaces(self) -> list[str]:
        result = []
        try:
            out = subprocess.check_output(["airmon-ng"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines()[2:]:
                parts = line.split()
                # airmon-ng layout: phyN <iface> <driver> <chipset>
                if len(parts) >= 2 and parts[1].startswith(("wlan", "wlp")):
                    result.append(parts[1])
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
        candidates = [f"{iface}mon", "wlan0mon", "wlan1mon", "wlan2mon"]
        for c in candidates:
            if self._iface_exists(c):
                return c
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


class AirodumpWorker(threading.Thread):
    """Run airodump-ng and parse its CSV output."""

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
