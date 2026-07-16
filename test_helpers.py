import os
import sys
import types
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import n2ng.main as _n2ng

sanitize_essid = _n2ng.sanitize_essid
format_bssid = _n2ng.format_bssid
human_size = _n2ng.human_size


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


parse_airodump_csv = _n2ng.parse_airodump_csv


def test_worker_restart_preserves_latest_networks(monkeypatch, tmp_path):
    """Restarting a scan must retain discoveries already shown by the GUI."""
    settings = _n2ng.Settings()
    worker = _n2ng.AirodumpWorker(_n2ng.queue.Queue(), settings)
    worker._last_mon_iface = "wlan0mon"
    worker._last_band = "Both"
    worker._prefix = str(tmp_path / "n2ng_scan")
    worker._proc = Mock()
    worker._proc.poll.return_value = None
    worker._latest_networks = [{"bssid": "AA:BB:CC:DD:EE:FF", "essid": "Known"}]
    monkeypatch.setattr(_n2ng.subprocess, "Popen", lambda *args, **kwargs: Mock())

    assert worker.restart_with_settings() == (True, None)
    assert worker.get_latest()[0] == [{"bssid": "AA:BB:CC:DD:EE:FF", "essid": "Known"}]


def test_worker_launch_streams_raw_airodump_output(monkeypatch, tmp_path):
    settings = _n2ng.Settings()
    worker = _n2ng.AirodumpWorker(_n2ng.queue.Queue(), settings)
    proc = Mock()
    proc.stdout = iter(["BSSID PWR CH ESSID\n", "AA:BB:CC:DD:EE:FF -50 6 Net\n"])
    proc.poll.return_value = None
    proc.wait.return_value = 0
    popen_calls = []

    def fake_popen(cmd, **kwargs):
        popen_calls.append((cmd, kwargs))
        return proc

    monkeypatch.setattr(_n2ng.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(_n2ng.AirodumpWorker, "_ensure_poll_thread", lambda self: None)
    worker.start_scan("wlan0mon", "Both", str(tmp_path / "scan"))
    worker._stdout_thread.join(timeout=1)

    assert popen_calls[0][1]["stdout"] == _n2ng.subprocess.PIPE
    assert popen_calls[0][1]["stderr"] == _n2ng.subprocess.STDOUT
    assert worker.get_raw_lines() == [
        "BSSID PWR CH ESSID",
        "AA:BB:CC:DD:EE:FF -50 6 Net",
    ]


def test_latest_airodump_csv_path_uses_numbered_scan_file(tmp_path):
    prefix = tmp_path / "n2ng_scan"
    (tmp_path / "n2ng_scan-06.csv").write_text("old")
    (tmp_path / "n2ng_scan-07.kismet.csv").write_text("ignore")
    newest = tmp_path / "n2ng_scan-07.csv"
    newest.write_text("new")

    assert _n2ng.latest_airodump_csv_path(str(prefix)) == newest


def test_color_arguments_explicitly_disable_color():
    settings = _n2ng.Settings()
    settings.set("color_output", False)

    assert _n2ng.airodump_color_args(settings) == ["--color", "0"]


def test_default_airodump_output_format_uses_pcap_not_cap(monkeypatch):
    settings = _n2ng.Settings()
    monkeypatch.setattr(_n2ng, "_airodump_supports", lambda _flag: False)
    worker = _n2ng.AirodumpWorker(_n2ng.queue.Queue(), settings)

    cmd = worker._build_base_cmd("/tmp/prefix")

    assert "--output-format" in cmd
    assert cmd[cmd.index("--output-format") + 1] == "csv,pcap"


def test_manufacturer_setting_uses_supported_airodump_flag(monkeypatch):
    settings = _n2ng.Settings()
    settings.set("show_manufacturers", True)
    monkeypatch.setattr(_n2ng, "_airodump_supports", lambda flag: flag == "--manufacturer")
    worker = _n2ng.AirodumpWorker(_n2ng.queue.Queue(), settings)

    cmd = worker._build_base_cmd("/tmp/prefix")

    assert "--manufacturer" in cmd
    assert "-M" not in cmd


def test_capture_fix_uses_pcapfix_outfile_flag(monkeypatch, tmp_path):
    calls = []
    cap = tmp_path / "capture.cap"
    out = tmp_path / "capture.fixed.cap"
    cap.write_bytes(b"pcap")

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        out.write_bytes(b"fixed")
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/pcapfix" if cmd == "pcapfix" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    assert manager.fix(cap) == out
    assert calls == [["pcapfix", "-o", str(out), str(cap)]]


def test_dependency_checker_uses_command_v_return_code(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0 if "pcapfix" in cmd[-1] else 1)

    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)

    statuses = _n2ng.DependencyChecker.check_all()

    assert statuses["pcapfix"]["installed"] is True
    assert statuses["airmon-ng"]["installed"] is False
    assert any(cmd[:2] == ["sh", "-c"] and "command -v pcapfix" in cmd[-1] for cmd in calls)


def test_attack_controller_can_stop_running_attack(monkeypatch):
    proc = Mock()
    proc.stdout = []
    proc.wait.return_value = None
    proc.poll.return_value = None
    monkeypatch.setattr(_n2ng.subprocess, "Popen", lambda *args, **kwargs: proc)
    attack = _n2ng.AttackController(lambda _msg: None)

    attack._run(["aireplay-ng", "-0", "10", "-a", "AA:BB:CC:DD:EE:FF", "wlan0mon"])
    attack._current = proc

    assert attack.stop_current() is True
    proc.terminate.assert_called_once()


def test_reaver_attack_command_targets_locked_bssid_channel(monkeypatch):
    calls = []
    monkeypatch.setattr(_n2ng.threading.Thread, "start", lambda self: calls.append(self._args[0]))
    attack = _n2ng.AttackController(lambda _msg: None)

    attack.reaver("AA:BB:CC:DD:EE:FF", "6", "wlan0mon")

    assert calls == [["reaver", "-i", "wlan0mon", "-b", "AA:BB:CC:DD:EE:FF", "-c", "6", "-vv"]]


def test_scan_prefix_lives_under_hs_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(_n2ng, "user_home", lambda: tmp_path)

    prefix = _n2ng.scan_prefix()

    assert prefix == str(tmp_path / "hs" / "n2-ng" / "scan" / "n2ng_scan")
    assert (tmp_path / "hs" / "n2-ng" / "scan").is_dir()


def test_target_capture_prefix_reuses_target_folder_and_avoids_collision(monkeypatch, tmp_path):
    monkeypatch.setattr(_n2ng, "user_home", lambda: tmp_path)
    bssid = "AA:BB:CC:DD:EE:FF"
    target_dir = tmp_path / "hs" / "n2-ng" / "Cafe_AA-BB-CC-DD-EE-FF"

    first = _n2ng.target_capture_prefix("Cafe", bssid, now="2026-07-15_12-00-00")
    (target_dir / "capture_2026-07-15_12-00-00-01.cap").write_bytes(b"one")
    second = _n2ng.target_capture_prefix("Cafe", bssid, now="2026-07-15_12-00-00")

    assert first == str(target_dir / "capture_2026-07-15_12-00-00")
    assert second == str(target_dir / "capture_2026-07-15_12-00-00_2")
    assert target_dir.is_dir()
    assert len(list((tmp_path / "hs" / "n2-ng").iterdir())) == 1


def test_settings_save_uses_redirected_user_config(monkeypatch, tmp_path):
    monkeypatch.setattr(_n2ng, "user_home", lambda: tmp_path)
    settings = _n2ng.Settings()
    settings.set("sort_by", "ESSID")

    assert settings.save() == (True, None)
    assert _n2ng.Settings().get("sort_by") == "ESSID"


def test_root_settings_initialization_assigns_config_to_sudo_user(monkeypatch, tmp_path):
    monkeypatch.setattr(_n2ng, "user_home", lambda: tmp_path)
    monkeypatch.setattr(_n2ng.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "kali")
    monkeypatch.setitem(_n2ng.sys.modules, "pwd", types.SimpleNamespace(getpwnam=lambda _: types.SimpleNamespace(pw_uid=1000, pw_gid=1000)))
    chown = Mock()
    monkeypatch.setattr(_n2ng.os, "chown", chown)

    _n2ng.Settings()

    assert chown.called


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
