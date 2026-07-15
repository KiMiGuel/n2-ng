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
