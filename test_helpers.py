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

    result = manager.fix(cap)

    assert result.ok is True
    assert result.output == out
    assert calls == [["/usr/bin/pcapfix", "-k", "-o", str(out), str(cap)]]


def test_capture_fix_reports_no_output_even_when_pcapfix_returns_zero(monkeypatch, tmp_path):
    cap = tmp_path / "capture.cap"
    cap.write_bytes(b"pcap")

    def fake_run(cmd, **kwargs):
        return types.SimpleNamespace(returncode=0, stdout="Nothing to fix!", stderr="")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/pcapfix" if cmd == "pcapfix" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.fix(cap)

    assert result.ok is False
    assert result.returncode == 0
    assert "did not write" in result.message
    assert "Nothing to fix" in result.stdout


def test_dependency_checker_uses_shared_path_resolution(monkeypatch):
    calls = []

    def fake_which(cmd):
        calls.append(cmd)
        return "/usr/bin/pcapfix" if cmd == "pcapfix" else None

    monkeypatch.setattr(_n2ng.shutil, "which", fake_which)

    statuses = _n2ng.DependencyChecker.check_all()

    assert statuses["pcapfix"]["installed"] is True
    assert statuses["pcapfix"]["path"] == "/usr/bin/pcapfix"
    assert statuses["airmon-ng"]["installed"] is False
    assert "pcapfix" in calls


def test_capture_merge_uses_resolved_mergecap_and_reports_failure(monkeypatch, tmp_path):
    calls = []
    cap1 = tmp_path / "one.cap"
    cap2 = tmp_path / "two.cap"
    out = tmp_path / "merged.cap"
    cap1.write_bytes(b"one")
    cap2.write_bytes(b"two")

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=2, stdout="", stderr="bad input")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/mergecap" if cmd == "mergecap" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.merge([cap1, cap2], out)

    assert result.ok is False
    assert result.returncode == 2
    assert "bad input" in result.stderr
    assert calls == [["/usr/bin/mergecap", "-w", str(out), str(cap1), str(cap2)]]


def test_capture_to_22000_uses_hcxpcapngtool_and_validates_records(monkeypatch, tmp_path):
    calls = []
    cap = tmp_path / "capture with space.cap"
    cap.write_bytes(b"pcap")

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        Path(cmd[cmd.index("-o") + 1]).write_text("WPA*02*abc\n")
        return types.SimpleNamespace(returncode=0, stdout="processed", stderr="")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/hcxpcapngtool" if cmd == "hcxpcapngtool" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.convert_to_22000(cap)

    assert result.ok is True
    assert result.output == tmp_path / "capture with space.22000"
    assert result.record_count == 1
    assert calls == [["/usr/bin/hcxpcapngtool", "-o", str(result.output), str(cap)]]


def test_capture_to_22000_reports_no_hashes(monkeypatch, tmp_path):
    cap = tmp_path / "capture.cap"
    cap.write_bytes(b"pcap")

    def fake_run(cmd, **kwargs):
        Path(cmd[cmd.index("-o") + 1]).write_text("")
        return types.SimpleNamespace(returncode=0, stdout="processed", stderr="")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/hcxpcapngtool" if cmd == "hcxpcapngtool" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.convert_to_22000(cap)

    assert result.ok is False
    assert "no usable PMKID or EAPOL" in result.message


def test_capture_to_pcapng_uses_editcap(monkeypatch, tmp_path):
    calls = []
    cap = tmp_path / "capture.cap"
    cap.write_bytes(b"pcap")

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        Path(cmd[-1]).write_bytes(b"pcapng")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/editcap" if cmd == "editcap" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.convert_to_pcapng(cap)

    assert result.ok is True
    assert result.output == tmp_path / "capture.pcapng"
    assert calls == [["/usr/bin/editcap", "-F", "pcapng", str(cap), str(result.output)]]


def test_reconstruct_cap_from_hash_uses_hcxhash2cap(monkeypatch, tmp_path):
    calls = []
    hash_file = tmp_path / "capture.22000"
    hash_file.write_text("WPA*01*abc\n")

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        Path(cmd[cmd.index("-c") + 1]).write_bytes(b"cap")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/hcxhash2cap" if cmd == "hcxhash2cap" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.reconstruct_cap_from_hash(hash_file)

    assert result.ok is True
    assert result.output == tmp_path / "capture.reconstructed.cap"
    assert calls == [["/usr/bin/hcxhash2cap", f"--pmkid-eapol={hash_file}", "-c", str(result.output)]]


def test_hashcat_command_builder_requires_attack_mode_and_wordlist(tmp_path):
    hash_file = tmp_path / "capture.22000"
    wordlist = tmp_path / "words.txt"

    command = _n2ng.build_hashcat_command(hash_file, wordlist, session="n2ng-test")

    assert command == [
        "hashcat",
        "-m",
        "22000",
        "-a",
        "0",
        "--session",
        "n2ng-test",
        str(hash_file),
        str(wordlist),
    ]


def test_dependency_checker_reports_workflow_tools(monkeypatch):
    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setattr(_n2ng.DependencyChecker, "_tool_version", classmethod(lambda cls, resolved: "v1"))
    monkeypatch.setattr(_n2ng.DependencyChecker, "_hashcat_backend_status", classmethod(lambda cls, resolved: (False, "No backend")))

    statuses = _n2ng.DependencyChecker.check_all()

    assert statuses["hcxpcapngtool"]["feature"] == "Capture to Hashcat 22000 conversion"
    assert statuses["hashcat"]["installed"] is True
    assert statuses["hashcat"]["usable"] is False
    assert statuses["hashcat"]["runtime_status"] == "No backend"
    assert statuses["editcap"]["feature"] == "Capture to PCAPNG normalization"


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
