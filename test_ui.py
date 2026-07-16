import os
import sys
import threading
import time
import types
from pathlib import Path
from unittest.mock import Mock

# Avoid running ensure_root / Tk mainloop when importing the module.
sys.modules["__main__"] = sys.modules["__main__"]

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import n2ng.main as _n2ng

import tkinter as tk
from tkinter import ttk

THEME = _n2ng.THEME


def test_gui_only_settings_apply_does_not_restart_scan():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.worker.restart_with_settings = Mock(return_value=(True, None))
    app.settings.save = Mock(return_value=(True, None))
    proposed = dict(app.settings.data, sort_by="ESSID", filter_encryption="Open only")

    assert app._apply_settings(proposed, app.worker.is_paused()) == (True, None)
    app.worker.restart_with_settings.assert_not_called()
    assert app.settings.get("sort_by") == "ESSID"
    root.destroy()


def test_restart_failure_restores_settings_and_status():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.worker.is_running = Mock(return_value=True)
    app.worker.restart_with_settings = Mock(return_value=(False, "launch failed"))
    app.settings.save = Mock(return_value=(True, None))
    previous = dict(app.settings.data)
    proposed = dict(previous, write_interval=5)

    assert app._apply_settings(proposed, False) == (False, "launch failed")
    assert app.settings.data == previous
    assert "launch failed" in app.status.cget("text")
    root.destroy()


def test_quiet_mode_apply_restarts_running_scan():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.worker.is_running = Mock(return_value=True)
    app.worker.restart_with_settings = Mock(return_value=(True, None))
    app.settings.save = Mock(return_value=(True, None))
    proposed = dict(app.settings.data, quiet_mode=not app.settings.get("quiet_mode"))

    assert app._apply_settings(proposed, False) == (True, None)

    app.worker.restart_with_settings.assert_called_once()
    root.destroy()


def test_settings_dialog_constructs_with_pause_state():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    dialog = _n2ng.SettingsDialog(root, app.settings, app._apply_settings)

    assert dialog.pause_var.get() is app.worker.is_paused()
    dialog.destroy()
    root.destroy()


def test_toolbar_selectors_use_readonly_comboboxes():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    assert app.adapter_combo.winfo_class() == "TCombobox"
    assert app.band_combo.winfo_class() == "TCombobox"
    assert str(app.adapter_combo.cget("state")) == "readonly"
    assert str(app.band_combo.cget("state")) == "readonly"
    root.destroy()


def test_stop_scan_clears_tree_and_disables_pause():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.worker.stop = Mock()
    bssid = "AA:BB:CC:DD:EE:FF"
    app.networks[bssid] = {
        "bssid": bssid,
        "essid": "Net",
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
    app.pause_btn.config(state=tk.NORMAL, text="Resume Scan")

    app._stop_scan()

    app.worker.stop.assert_called_once()
    assert app.networks == {}
    assert app.tree.get_children() == ()
    assert app.status.cget("text") == "Scan stopped"
    assert str(app.pause_btn.cget("state")) == tk.DISABLED
    assert app.pause_btn.cget("text") == "Pause Scan"
    root.destroy()


def test_spacebar_toggles_scan_pause():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.worker._proc = Mock()
    app.worker.is_paused = Mock(return_value=False)
    app.worker.pause = Mock()

    assert app._on_spacebar_pause(types.SimpleNamespace(widget=app.tree)) == "break"

    app.worker.pause.assert_called_once()
    assert app.pause_btn.cget("text") == "Resume Scan"
    root.destroy()


def test_stop_attack_stops_controller_and_auto_deauth():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.attack.stop_current = Mock(return_value=True)
    app.auto_deauth_var.set(True)

    app._stop_attack()

    app.attack.stop_current.assert_called_once()
    assert app.auto_deauth_var.get() is False
    assert "Attack stopped" in app.status.cget("text")
    root.destroy()


def test_start_monitor_reports_scan_launch_failure(monkeypatch, tmp_path):
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    monkeypatch.setattr(_n2ng, "scan_prefix", lambda: str(tmp_path / "n2ng_scan"))
    app.adapter_var.set("wlan0")
    app.airmon.start_monitor = Mock(return_value="wlan0mon")
    app.airmon.stop_monitor = Mock()
    app.worker.start_scan = Mock(return_value=(False, "airodump missing"))
    app.raw_view.start = Mock()

    app._start_monitor()

    app.airmon.stop_monitor.assert_called_once_with("wlan0mon")
    app.raw_view.start.assert_not_called()
    assert "airodump missing" in app.status.cget("text")
    assert str(app.pause_btn.cget("state")) == tk.DISABLED
    root.destroy()


def test_lock_target_reports_scan_launch_failure(monkeypatch, tmp_path):
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    monkeypatch.setattr(_n2ng, "target_capture_prefix", lambda _essid, _bssid: str(tmp_path / "capture"))
    app.mon_iface = "wlan0mon"
    bssid = "AA:BB:CC:DD:EE:FF"
    app.networks[bssid] = {
        "bssid": bssid,
        "essid": "Net",
        "channel": "6",
        "power": "-50",
        "privacy": "WPA2",
        "cipher": "CCMP",
        "auth": "PSK",
    }
    app.worker.start_lock = Mock(return_value=(False, "lock failed"))
    app.raw_view.start = Mock()

    app._lock_target(bssid)

    app.raw_view.start.assert_not_called()
    assert app.locked_target is None
    assert "lock failed" in app.status.cget("text")
    root.destroy()


def test_client_update_preserves_selection():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.locked_target = {"bssid": "AA:BB:CC:DD:EE:FF", "essid": "MyWiFi"}
    clients = [
        {"station": "11:22:33:44:55:66", "power": "-60", "packets": "50", "bssid": "AA:BB:CC:DD:EE:FF", "probed": ""},
    ]

    app._update_clients(clients)
    app.client_tree.selection_set("11:22:33:44:55:66")
    app._update_clients(clients)

    assert app.client_tree.selection() == ("11:22:33:44:55:66",)
    root.destroy()


def test_client_right_click_deauths_selected_station():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.locked_target = {"bssid": "AA:BB:CC:DD:EE:FF", "essid": "MyWiFi"}
    app.mon_iface = "wlan0mon"
    app._confirm_attack = Mock(return_value=True)
    app.attack.deauth_client = Mock()
    clients = [
        {"station": "11:22:33:44:55:66", "power": "-60", "packets": "50", "bssid": "AA:BB:CC:DD:EE:FF", "probed": ""},
    ]
    app._update_clients(clients)

    app._deauth_client_by_station("11:22:33:44:55:66")

    app.attack.deauth_client.assert_called_once_with(
        "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "wlan0mon", count=10
    )
    root.destroy()


def test_reaver_button_runs_locked_target_command():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.locked_target = {"bssid": "AA:BB:CC:DD:EE:FF", "channel": "6"}
    app.mon_iface = "wlan0mon"
    app._confirm_attack = Mock(return_value=True)
    app.attack.reaver = Mock()

    app._reaver_attack()

    app.attack.reaver.assert_called_once_with("AA:BB:CC:DD:EE:FF", "6", "wlan0mon")
    root.destroy()


def test_context_menu_dismissal_destroys_active_menu():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    menu = Mock()
    menu.winfo_exists.return_value = True
    app._context_menu = menu

    app._dismiss_context_menu(types.SimpleNamespace(widget=app.tree))

    menu.unpost.assert_called_once()
    menu.destroy.assert_called_once()
    assert app._context_menu is None
    root.destroy()


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
    assert isinstance(app.raw_view, _n2ng.AirodumpRawView)
    root.destroy()


def test_raw_view_has_vertical_and_horizontal_scrollbars():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    assert str(app.raw_view.y_scrollbar.cget("orient")) == "vertical"
    assert str(app.raw_view.x_scrollbar.cget("orient")) == "horizontal"
    assert app.raw_view.text.cget("wrap") == tk.NONE
    assert app.raw_view.text.cget("xscrollcommand")
    assert app.raw_view.text.cget("yscrollcommand")
    root.destroy()


def test_raw_view_flushes_worker_raw_lines_without_own_process():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    app.worker.get_latest = Mock(return_value=([], []))
    app.worker.get_raw_lines = Mock(return_value=["BSSID PWR CH ESSID", "AA:BB:CC:DD:EE:FF -50 6 Net"])
    app.raw_view.start = Mock()

    app._poll_queue()

    assert app.raw_view.start.call_count == 0
    text = app.raw_view.text.get("1.0", tk.END)
    assert "AA:BB:CC:DD:EE:FF" in text
    root.destroy()


def test_main_content_grid_expands_with_window():
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)

    assert root.grid_rowconfigure(1)["weight"] == 1
    assert root.grid_columnconfigure(0)["weight"] == 1
    assert app.content_frame.grid_rowconfigure(0)["weight"] == 1
    assert app.content_frame.grid_columnconfigure(0)["weight"] == 1
    assert app.content_frame.grid_columnconfigure(1)["weight"] == 1
    root.destroy()


def test_treeview_is_monospace():
    """Network Treeview must use a monospace font."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    style = ttk.Style(root)
    font = style.lookup("Treeview", "font")
    assert "Courier" in font or "Consolas" in font, f"unexpected Treeview font: {font!r}"
    root.destroy()


def test_power_update_does_not_flash_row():
    """PWR changes should update values without rapid flash highlighting."""
    root = tk.Tk()
    root.withdraw()
    app = _n2ng.N2NgApp(root)
    bssid = "AA:BB:CC:DD:EE:FF"
    net = {
        "bssid": bssid, "essid": "Net", "power": "-50", "beacons": "10",
        "iv": "0", "channel": "6", "speed": "54", "privacy": "WPA2",
        "cipher": "CCMP", "auth": "PSK", "manufacturer": "",
    }
    app._networks_prev[bssid] = {"power": "-60", "beacons": "10"}
    app._update_networks([net])
    tags = app.tree.item(bssid, "tags")
    assert "flash" not in tags
    root.destroy()
