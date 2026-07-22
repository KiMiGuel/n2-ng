"""Diagnosis harness #2: simulate a locked-target scan feed.

Reproduces the GUI-side load of a real scan with a locked target without
wireless hardware: a FakeWorker returns networks whose power fluctuates
every poll, so `_poll_queue` takes the full `_update_networks` ->
`signal_graph.add_sample` -> `_draw` path every 150 ms cycle.
Not part of the app; used for CPU diagnosis.
"""
import random
import sys
import tkinter as tk

sys.path.insert(0, "src")

from n2ng.main import N2NgApp  # noqa: E402


class FakeWorker:
    def __init__(self, networks):
        self._networks = networks

    def get_latest(self):
        nets = []
        for net in self._networks:
            n = dict(net)
            n["power"] = str(random.randint(-90, -30))
            n["beacons"] = str(random.randint(0, 9999))
            nets.append(n)
        return nets, []

    def get_raw_lines(self):
        return []


def main():
    root = tk.Tk()
    app = N2NgApp(root, demo_mode=True)

    def begin_sim():
        networks = list(app.networks.values())
        if not networks:
            print("SIM: no demo networks, aborting sim")
            return
        app.locked_target = networks[0]
        app.channel_locked = True
        app.worker = FakeWorker(networks)
        print(f"SIM: locked target {networks[0]['bssid']}, feeding {len(networks)} networks")

    def switch_to_raw_tab():
        app.notebook.select(1)
        print("SIM: switched to Raw View tab (scan tab unmapped)")

    root.after(3000, begin_sim)
    root.after(30000, switch_to_raw_tab)
    app.run()


if __name__ == "__main__":
    main()
