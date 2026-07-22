"""Diagnosis harness #3: self-driving real-mode repro of the Start Monitor freeze.

Constructs the real N2NgApp (non-demo), selects wlan0monmon, and invokes
the exact `_start_monitor` button handler at t=5s. Must run as root
(sudo -n) with DISPLAY/XAUTHORITY passed through. Diagnosis only.
"""
import sys
import tkinter as tk

sys.path.insert(0, "src")

from n2ng.main import N2NgApp  # noqa: E402


def main():
    root = tk.Tk()
    app = N2NgApp(root, demo_mode=False)
    app.adapter_var.set("wlan0monmon")

    def begin():
        print("SIM: invoking _start_monitor", flush=True)
        app._start_monitor()
        print(f"SIM: mon_iface={app.mon_iface}", flush=True)

    root.after(5000, begin)
    app.run()


if __name__ == "__main__":
    main()
