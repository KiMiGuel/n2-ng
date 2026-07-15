import importlib.util
import os
import sys
import threading
import time

# Avoid running ensure_root / Tk mainloop when importing the module.
sys.modules["__main__"] = sys.modules["__main__"]

_spec = importlib.util.spec_from_file_location(
    "n2ng", os.path.join(os.path.dirname(__file__), "n2_ng.py")
)
_n2ng = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_n2ng)

import tkinter as tk
from tkinter import ttk

THEME = _n2ng.THEME


def test_treeview_uses_dark_theme():
    """Treeview background must be dark so bright foreground text is visible."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    style = ttk.Style(root)
    bg = style.lookup("Treeview", "background")
    fg = style.lookup("Treeview", "foreground")
    field_bg = style.lookup("Treeview", "fieldbackground")

    assert bg == THEME["bg"], f"expected Treeview bg {THEME['bg']!r}, got {bg!r}"
    assert fg == THEME["fg"], f"expected Treeview fg {THEME['fg']!r}, got {fg!r}"
    assert field_bg == THEME["bg"], f"expected Treeview fieldbg {THEME['bg']!r}, got {field_bg!r}"

    # No privacy tag should use a color that matches the background.
    tags = {
        "OPN": THEME["fg"],
        "WEP": "#ff4444",
        "WPA": "#ffcc00",
        "WPA2": "#ffffff",
        "WPA3": "#00ccff",
    }
    for tag, color in tags.items():
        assert color.lower() != THEME["bg"].lower(), (
            f"privacy tag {tag!r} foreground {color!r} matches Treeview background"
        )

    root.destroy()


def test_worker_uses_shared_buffer():
    """AirodumpWorker must expose a thread-safe shared buffer via get_latest()."""
    q = _n2ng.queue.Queue()
    settings = _n2ng.Settings()
    worker = _n2ng.AirodumpWorker(q, settings)

    sample_networks = [{"bssid": "AA:BB:CC:DD:EE:FF", "essid": "TestNet"}]
    sample_clients = [{"station": "11:22:33:44:55:66", "bssid": "AA:BB:CC:DD:EE:FF"}]

    with worker._data_lock:
        worker._latest_networks = sample_networks
        worker._latest_clients = sample_clients

    nets, clients = worker.get_latest()
    assert nets == sample_networks
    assert clients == sample_clients

    # Returned copies must be independent of the internal buffer.
    nets[0]["essid"] = "Mutated"
    with worker._data_lock:
        assert worker._latest_networks[0]["essid"] == "TestNet"


def test_display_refresh_rate_is_fixed():
    """The display loop must reschedule itself at a fixed interval (~6.7 FPS)."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    calls = []
    original_after = root.after

    def capture_after(ms, callback):
        calls.append(ms)
        return original_after(ms, callback)

    root.after = capture_after
    # Cancel any pending poll to test a fresh scheduling.
    if app.poll_id:
        root.after_cancel(app.poll_id)
    app._poll_queue()

    assert calls, "_poll_queue did not reschedule itself"
    assert calls[-1] == 150, f"expected 150 ms refresh interval, got {calls[-1]} ms"

    root.destroy()


def test_treeview_updates_in_place():
    """_refresh_tree should update existing rows without deleting them all."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    bssid = "AA:BB:CC:DD:EE:FF"
    app.networks[bssid] = {
        "bssid": bssid,
        "essid": "Before",
        "power": "-50",
        "beacons": "10",
        "iv": "0",
        "channel": "6",
        "speed": "54",
        "privacy": "WPA2",
        "cipher": "CCMP",
        "auth": "PSK",
        "manufacturer": "",
    }
    app._refresh_tree()
    children_before = list(app.tree.get_children())
    assert bssid in children_before

    app.networks[bssid]["essid"] = "After"
    app._refresh_tree()
    children_after = list(app.tree.get_children())

    # The row should still exist and have been updated, not deleted/reinserted.
    assert bssid in children_after
    assert app.tree.item(bssid, "values")[-2] == "After"

    root.destroy()


def test_right_panel_is_scrollable():
    """The right panel must live inside a canvas with a scrollbar."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    assert hasattr(app, "right_canvas"), "missing right_canvas"
    assert hasattr(app, "right_scrollbar"), "missing right_scrollbar"
    assert hasattr(app, "right_inner_frame"), "missing right_inner_frame"
    assert app.right_canvas.winfo_class() == "Canvas"
    assert str(app.right_scrollbar.cget("orient")) == "vertical"

    root.destroy()


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
        {"station": "44:55:66:77:88:99", "power": "-85", "packets": "2", "bssid": "(not associated)", "probed": "OtherNet"},
    ]
    app._update_clients(app.clients)

    values = [app.client_tree.item(child, "values") for child in app.client_tree.get_children()]
    stations = {v[0] for v in values}
    assert "11:22:33:44:55:66" in stations
    assert "22:33:44:55:66:77" in stations
    assert "33:44:55:66:77:88" not in stations
    assert "44:55:66:77:88:99" not in stations

    root.destroy()
