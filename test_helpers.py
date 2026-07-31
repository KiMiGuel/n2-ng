import os
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import n2ng.main as _n2ng

sanitize_essid = _n2ng.sanitize_essid
format_bssid = _n2ng.format_bssid
human_size = _n2ng.human_size


def test_module_launch_has_no_duplicate_import_warning():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent / "src")
    result = subprocess.run(
        [sys.executable, "-Werror::RuntimeWarning", "-m", "n2ng.main", "--version"],
        cwd=Path(__file__).resolve().parent,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"n2-ng {_n2ng.__version__}"
    assert "RuntimeWarning" not in result.stderr


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
    cap.write_bytes(b"pcap")
    monkeypatch.setattr(_n2ng, "capture_root", lambda create=True: tmp_path)

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        Path(cmd[cmd.index("-o") + 1]).write_bytes(b"fixed")
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/pcapfix" if cmd == "pcapfix" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.fix(cap)

    assert result.ok is True
    assert result.output.name == "capture.fixed.cap"
    assert "fixed" in str(result.output)
    assert result.output.exists()
    assert calls == [["/usr/bin/pcapfix", "-k", "-o", str(result.output), str(cap)]]


def test_capture_fix_reports_no_output_even_when_pcapfix_returns_zero(monkeypatch, tmp_path):
    cap = tmp_path / "capture.cap"
    cap.write_bytes(b"pcap")
    monkeypatch.setattr(_n2ng, "capture_root", lambda create=True: tmp_path)

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
    monkeypatch.setattr(_n2ng, "capture_root", lambda create=True: tmp_path)

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        Path(cmd[cmd.index("-o") + 1]).write_text("WPA*02*abc\n")
        return types.SimpleNamespace(returncode=0, stdout="processed", stderr="")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/hcxpcapngtool" if cmd == "hcxpcapngtool" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.convert_to_22000(cap)

    assert result.ok is True
    assert result.output.name == "capture with space.22000"
    assert "hashcat" in str(result.output)
    assert result.output.exists()
    assert result.record_count == 1
    assert calls == [["/usr/bin/hcxpcapngtool", "-o", str(result.output), str(cap)]]


def test_capture_to_22000_reports_no_hashes(monkeypatch, tmp_path):
    cap = tmp_path / "capture.cap"
    cap.write_bytes(b"pcap")
    monkeypatch.setattr(_n2ng, "capture_root", lambda create=True: tmp_path)

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
    monkeypatch.setattr(_n2ng, "capture_root", lambda create=True: tmp_path)

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        Path(cmd[-1]).write_bytes(b"pcapng")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/editcap" if cmd == "editcap" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.convert_to_pcapng(cap)

    assert result.ok is True
    assert result.output.name == "capture.pcapng"
    assert "pcapng" in str(result.output)
    assert result.output.exists()
    assert calls == [["/usr/bin/editcap", "-F", "pcapng", str(cap), str(result.output)]]


def test_reconstruct_cap_from_hash_uses_hcxhash2cap(monkeypatch, tmp_path):
    calls = []
    hash_file = tmp_path / "capture.22000"
    hash_file.write_text("WPA*01*abc\n")
    monkeypatch.setattr(_n2ng, "capture_root", lambda create=True: tmp_path)

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        Path(cmd[cmd.index("-c") + 1]).write_bytes(b"cap")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(_n2ng.shutil, "which", lambda cmd: "/usr/bin/hcxhash2cap" if cmd == "hcxhash2cap" else None)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)

    result = manager.reconstruct_cap_from_hash(hash_file)

    assert result.ok is True
    assert result.output.name == "capture.reconstructed.cap"
    assert "reconstructed" in str(result.output)
    assert result.output.exists()
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


def test_list_physical_interfaces_falls_back_to_ip_link_and_includes_monitor_iface(monkeypatch):
    """When airmon-ng fails, existing monitor interfaces must still appear."""
    airmon = _n2ng.AirmonManager()

    def fake_check_output(cmd, **kwargs):
        if cmd[0] == "airmon-ng":
            raise subprocess.CalledProcessError(1, "airmon-ng")
        if cmd[0] == "ip" and cmd[1] == "link":
            return "1: lo: <LOOPBACK>\n9: wlan0mon: <BROADCAST,MULTICAST,UP>\n"
        raise RuntimeError(f"unexpected command: {cmd}")

    monkeypatch.setattr(_n2ng.subprocess, "check_output", fake_check_output)
    assert airmon.list_physical_interfaces() == ["wlan0mon"]


def test_start_monitor_uses_iface_directly_when_already_monitor_mode(monkeypatch):
    """Selecting an existing monitor interface should not try to recreate it."""
    airmon = _n2ng.AirmonManager()
    run_calls = []

    def fake_check_output(cmd, **kwargs):
        if cmd[0] == "iw" and cmd[1] == "dev" and cmd[2] == "wlan0mon":
            return "\tInterface wlan0mon\n\t\ttype monitor\n"
        raise RuntimeError(f"unexpected command: {cmd}")

    def fake_run(cmd, **kwargs):
        run_calls.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(_n2ng.subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(_n2ng.subprocess, "run", fake_run)

    assert airmon.start_monitor("wlan0mon") == "wlan0mon"
    assert not any(cmd[0] == "airmon-ng" for cmd in run_calls)
    assert airmon._mon_map.get("wlan0mon") == "wlan0mon"


clamp_to_screen = _n2ng.clamp_to_screen


def test_clamp_to_screen_keeps_default_on_large_display():
    assert clamp_to_screen(1320, 760, 1920, 1080) == (1320, 760)


def test_clamp_to_screen_shrinks_to_fit_small_display():
    assert clamp_to_screen(1320, 760, 800, 480) == (800, 480)


def test_clamp_to_screen_applies_margins():
    assert clamp_to_screen(900, 560, 800, 480, margin_w=40, margin_h=60) == (760, 420)


classify_22000 = _n2ng.classify_22000
classify_22000_text = _n2ng.classify_22000_text


def _eapol_line(messagepair: str) -> str:
    return f"WPA*02*aa11*bb22*cc33*64646464*ee55*ff66*{messagepair}"


def test_classify_22000_authorized_messagepairs():
    assert classify_22000_text(_eapol_line("02") + "\n") == "AUTHORIZED"
    # 0x80 flag (nonce-error-correction) must be masked off: 0x82 & 0x07 == 2.
    assert classify_22000_text(_eapol_line("82") + "\n") == "AUTHORIZED"
    # Any authorized line wins even when challenge lines are also present.
    text = _eapol_line("00") + "\n" + _eapol_line("05") + "\n"
    assert classify_22000_text(text) == "AUTHORIZED"


def test_classify_22000_challenge_messagepairs():
    # 0x10 and 0x80 both mask to messagepair 0: M1+M2 challenge only.
    assert classify_22000_text(_eapol_line("00") + "\n") == "CHALLENGE"
    assert classify_22000_text(_eapol_line("10") + "\n") == "CHALLENGE"
    assert classify_22000_text(_eapol_line("80") + "\n") == "CHALLENGE"


def test_classify_22000_pmkid_and_empty():
    assert classify_22000_text("WPA*01*aa11*bb22*cc33\n") == "PMKID"
    assert classify_22000_text("") == "NONE"
    assert classify_22000_text("garbage\n") == "NONE"


def test_classify_22000_reads_file(tmp_path):
    hash_file = tmp_path / "cap.22000"
    hash_file.write_text(_eapol_line("03") + "\n")
    assert classify_22000(hash_file) == "AUTHORIZED"
    assert classify_22000(tmp_path / "missing.22000") == "NONE"


def test_capture_gate_challenge_does_not_set_handshake_found(tmp_path):
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)
    challenge = tmp_path / "challenge.22000"
    challenge.write_text(_eapol_line("00") + "\n")

    manager._classify(challenge)

    event, payload = manager.queue.get_nowait()
    assert event == "challenge"
    assert payload["file"] == str(challenge)
    # The auto-deauth stop condition must stay false: keep capturing.
    assert manager.handshake_found is False
    assert manager.pmkid_found is False


def test_capture_gate_authorized_fires_handshake(tmp_path):
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)
    authorized = tmp_path / "authorized.22000"
    authorized.write_text(_eapol_line("82") + "\n")

    manager._classify(authorized)

    event, _payload = manager.queue.get_nowait()
    assert event == "handshake"
    assert manager.handshake_found is True


def test_capture_gate_pmkid_still_fires(tmp_path):
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)
    pmkid = tmp_path / "pmkid.22000"
    pmkid.write_text("WPA*01*aa11*bb22*cc33\n")

    manager._classify(pmkid)

    event, _payload = manager.queue.get_nowait()
    assert event == "pmkid"
    assert manager.pmkid_found is True


# ------------------------------------------------------------------
# v1.6.0: security profiling, attack routing, PMKID helpers
# ------------------------------------------------------------------

security_profile = _n2ng.security_profile
recommend_attack = _n2ng.recommend_attack


def _net(privacy="", cipher="", auth=""):
    return {"privacy": privacy, "cipher": cipher, "auth": auth}


def test_security_profile_wpa2_psk():
    profile = security_profile(_net("WPA2", "CCMP", "PSK"))
    assert profile["wpa3"] is False
    assert profile["transition"] is False
    assert profile["pmf"] == "unknown"


def test_security_profile_wpa3_transition():
    profile = security_profile(_net("WPA3 WPA2", "CCMP", "SAE PSK"))
    assert profile["wpa3"] is True
    assert profile["transition"] is True
    assert profile["pmf"] == "capable"


def test_security_profile_pure_wpa3_requires_pmf():
    profile = security_profile(_net("WPA3", "CCMP", "SAE"))
    assert profile["wpa3"] is True
    assert profile["transition"] is False
    assert profile["pmf"] == "required"


def test_security_profile_wep_and_open():
    assert security_profile(_net("WEP", "WEP", ""))["wep"] is True
    assert security_profile(_net("WEP", "WEP", ""))["pmf"] == "none"
    assert security_profile(_net("OPN", "", ""))["open"] is True


def test_recommend_attack_pmkid_first_for_wpa2():
    plan = recommend_attack(security_profile(_net("WPA2", "CCMP", "PSK")))
    assert plan[0]["id"] == "pmkid"
    assert any(step["id"] == "deauth_handshake" for step in plan)


def test_recommend_attack_no_deauth_when_pmf_required():
    plan = recommend_attack(security_profile(_net("WPA3", "CCMP", "SAE")))
    ids = [step["id"] for step in plan]
    assert "pmkid" in ids
    assert "sae-online" in ids
    assert "deauth_handshake" not in ids


def test_recommend_attack_transition_suggests_downgrade_and_deauth():
    plan = recommend_attack(security_profile(_net("WPA3 WPA2", "CCMP", "SAE PSK")))
    ids = [step["id"] for step in plan]
    assert ids[0] == "pmkid"
    assert "downgrade" in ids
    assert "deauth_handshake" in ids


def test_recommend_attack_wep_and_open():
    assert recommend_attack(security_profile(_net("WEP", "WEP", "")))[0]["id"] == "arpreplay"
    assert recommend_attack(security_profile(_net("OPN", "", "")))[0]["id"] == "none"


def test_extract_pmkid_finds_rsn_kde():
    pmkid = bytes(range(16))
    frame = b"\x88\x8e" + b"\x00" * 20 + _n2ng.PMKID_KDE + pmkid + b"\x00" * 4
    assert _n2ng.extract_pmkid(frame) == pmkid
    assert _n2ng.extract_pmkid(b"no kde here") is None
    # Truncated KDE must not match.
    assert _n2ng.extract_pmkid(b"\x00\x0f\xac\x04" + b"\x01" * 10) is None


def test_build_pmkid_22000_line_format():
    line = _n2ng.build_pmkid_22000_line(bytes(range(16)), "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "Cafe")
    assert line == "WPA*01*000102030405060708090a0b0c0d0e0f*aabbccddeeff*112233445566*43616665***"


def test_pmkid_output_path_under_target_folder(monkeypatch, tmp_path):
    monkeypatch.setattr(_n2ng, "user_home", lambda: tmp_path)
    path = _n2ng.pmkid_output_path("Cafe", "AA:BB:CC:DD:EE:FF")
    assert path.parent == tmp_path / "hs" / "n2-ng" / "Cafe_AA-BB-CC-DD-EE-FF"
    assert path.name.startswith("pmkid_")
    assert path.suffix == ".22000"


def test_hashcat_command_with_rules_and_nonce_corrections(tmp_path):
    hash_file = tmp_path / "capture.22000"
    wordlist = tmp_path / "words.txt"
    rules = tmp_path / "best64.rule"

    command = _n2ng.build_hashcat_command(
        hash_file, wordlist, rules=rules, nonce_error_corrections=64
    )

    assert command == [
        "hashcat", "-m", "22000", "-a", "0",
        "--nonce-error-corrections=64",
        str(hash_file), str(wordlist), "-r", str(rules),
    ]


def test_hashcat_command_defaults_unchanged(tmp_path):
    hash_file = tmp_path / "capture.22000"
    wordlist = tmp_path / "words.txt"
    command = _n2ng.build_hashcat_command(hash_file, wordlist)
    assert command == ["hashcat", "-m", "22000", "-a", "0", str(hash_file), str(wordlist)]


class _FakePmkidAttacker:
    """Test double: starts instantly, finds nothing, dies immediately."""

    instances = []

    def __init__(self, *args, **kwargs):
        self.result_path = None
        _FakePmkidAttacker.instances.append(self)

    def start(self):
        pass

    def is_alive(self):
        return False

    def stop(self):
        pass


def test_smart_attack_pmf_required_never_deauths(monkeypatch):
    monkeypatch.setattr(_n2ng, "PmkidAttacker", _FakePmkidAttacker)
    monkeypatch.setattr(_n2ng, "pmkid_output_path", lambda e, b: Path("/tmp/x.22000"))
    logs = []
    attack = Mock()
    capture = Mock(handshake_found=False, pmkid_found=False)
    net = {"bssid": "AA:BB:CC:DD:EE:FF", "essid": "Net", "privacy": "WPA3", "cipher": "CCMP", "auth": "SAE"}

    orchestrator = _n2ng.SmartAttackOrchestrator(
        net, "wlan0mon", "11:22:33:44:55:66", attack, capture, logs.append,
    )
    orchestrator.run()

    attack.deauth_all.assert_not_called()
    assert any("PMF" in msg for msg in logs)


def test_smart_attack_wpa2_deauths_until_handshake(monkeypatch):
    monkeypatch.setattr(_n2ng, "PmkidAttacker", _FakePmkidAttacker)
    monkeypatch.setattr(_n2ng, "pmkid_output_path", lambda e, b: Path("/tmp/x.22000"))
    logs = []
    capture = Mock(handshake_found=False, pmkid_found=False)
    attack = Mock()
    # Handshake lands after the first deauth burst.
    attack.deauth_all.side_effect = lambda *a, **k: setattr(capture, "handshake_found", True)
    net = {"bssid": "AA:BB:CC:DD:EE:FF", "essid": "Net", "privacy": "WPA2", "cipher": "CCMP", "auth": "PSK"}

    orchestrator = _n2ng.SmartAttackOrchestrator(
        net, "wlan0mon", "11:22:33:44:55:66", attack, capture, logs.append,
        clients=["22:33:44:55:66:77"], interval=0,
    )
    orchestrator.run()

    attack.deauth_all.assert_called_once_with(
        "AA:BB:CC:DD:EE:FF", "wlan0mon", count=1, clients=["22:33:44:55:66:77"]
    )


def test_challenge_then_authorized_upgrades_to_handshake(tmp_path):
    """Regression guard for the v1.4.0-era silent gate revert (commit 7abb12c).

    Invariant: an M1+M2 challenge (messagepair 0) must NOT satisfy the capture
    gate — auto-deauth keeps running — and a later AUTHORIZED record must still
    fire the handshake event. If a future change makes CHALLENGE set
    handshake_found, this test fails immediately.
    """
    manager = _n2ng.CaptureManager(_n2ng.queue.Queue(), lambda _msg: None)
    challenge = tmp_path / "challenge.22000"
    challenge.write_text(_eapol_line("00") + "\n")
    manager._classify(challenge)
    event, _ = manager.queue.get_nowait()
    assert event == "challenge"
    assert manager.handshake_found is False  # gate NOT satisfied -> keep capturing

    authorized = tmp_path / "authorized.22000"
    authorized.write_text(_eapol_line("02") + "\n")
    manager._classify(authorized)
    event, _ = manager.queue.get_nowait()
    assert event == "handshake"
    assert manager.handshake_found is True


# ------------------------------------------------------------------
# v1.7.0: OMNI Attack orchestrator
# ------------------------------------------------------------------

from n2ng.omni import EvilTwinStage, OmniAttackOrchestrator, wps_state


class _OmniPmkidBase:
    def __init__(self, result_path=None):
        self.result_path = result_path

    def start(self):
        pass

    def is_alive(self):
        return False

    def stop(self):
        pass


def _make_omni(net, profile, **kw):
    attack = Mock()
    capture = Mock(handshake_found=False, pmkid_found=False)
    logs = []
    params = dict(
        mon_iface="wlan0mon",
        sta_mac="11:22:33:44:55:66",
        run_cmd=lambda cmd, timeout: (1, ""),
        pmkid_factory=lambda: _OmniPmkidBase(),
        pmkid_window=1,
        deauth_interval=0,
        max_deauth_rounds=2,
    )
    params.update(kw)
    omni = OmniAttackOrchestrator(
        net, profile, params.pop("mon_iface"), params.pop("sta_mac"),
        attack, capture, logs.append, **params,
    )
    return omni, attack, capture, logs


_OMNI_NET = {"bssid": "AA:BB:CC:DD:EE:FF", "essid": "Net", "channel": "6",
             "privacy": "WPA2", "cipher": "CCMP", "auth": "PSK"}


def test_omni_pmkid_success_escapes_to_crack(tmp_path):
    (tmp_path / "cap.22000").write_text("WPA*01*aa11\n")
    profile = _n2ng.security_profile(_OMNI_NET)
    omni, attack, _capture, _logs = _make_omni(
        _OMNI_NET, profile,
        pmkid_factory=lambda: _OmniPmkidBase(result_path=tmp_path / "cap.22000"),
        target_dir=tmp_path,
        build_crack_cmd=lambda batch: ["hashcat", str(batch)],
        run_cmd=lambda cmd, timeout: (0, "Recovered........: 1/1 (100.00%) Digests"),
    )
    omni.run()

    stages = [(r["stage"], r["result"]) for r in omni.stage_results]
    assert stages == [("PROFILE", "OK"), ("PMKID", "OK"), ("CRACK", "OK")]
    assert omni.succeeded_stage == "PMKID"
    attack.deauth_all.assert_not_called()


def test_omni_wps_skipped_when_locked(tmp_path):
    profile = _n2ng.security_profile(_OMNI_NET)
    omni, attack, capture, _logs = _make_omni(
        _OMNI_NET, profile,
        wps_lines=["AA:BB:CC:DD:EE:FF  6  -45  2.0  Yes  Vendor  Net"],
        target_dir=tmp_path,
    )
    # Handshake lands on first deauth round so the chain terminates promptly.
    attack.deauth_all.side_effect = lambda *a, **k: setattr(capture, "handshake_found", True)
    omni.run()

    results = {r["stage"]: r["result"] for r in omni.stage_results}
    assert results["WPS"] == "SKIP"
    assert results["HANDSHAKE"] == "OK"
    assert omni.succeeded_stage == "HANDSHAKE"


def test_omni_pmf_required_skips_handshake(tmp_path):
    wpa3_net = dict(_OMNI_NET, privacy="WPA3", auth="SAE")
    profile = _n2ng.security_profile(wpa3_net)
    omni, attack, _capture, _logs = _make_omni(wpa3_net, profile, target_dir=tmp_path)
    omni.run()

    results = {r["stage"]: r["result"] for r in omni.stage_results}
    assert results["HANDSHAKE"] == "SKIP"
    assert results["EVILTWIN"] == "STUB"
    attack.deauth_all.assert_not_called()


def test_omni_crack_batch_dedups_records(tmp_path):
    (tmp_path / "a.22000").write_text("WPA*01*aa\nWPA*02*bb\n")
    (tmp_path / "b.22000").write_text("WPA*01*aa\nWPA*01*cc\n")
    omni, _a, _c, _l = _make_omni(_OMNI_NET, _n2ng.security_profile(_OMNI_NET), target_dir=tmp_path)

    assert omni.collect_22000_records() == ["WPA*01*aa", "WPA*02*bb", "WPA*01*cc"]


def test_eviltwin_stage_stub_raises():
    try:
        EvilTwinStage().run()
    except NotImplementedError:
        return
    raise AssertionError("EvilTwinStage.run() must raise NotImplementedError")


def test_wps_state_parsing():
    assert wps_state("AA:BB:CC:DD:EE:FF", ["AA:BB:CC:DD:EE:FF  6  -45  2.0  Yes  V  Net"]) == "locked"
    assert wps_state("AA:BB:CC:DD:EE:FF", ["AA:BB:CC:DD:EE:FF  6  -45  2.0  No   V  Net"]) == "enabled"
    assert wps_state("AA:BB:CC:DD:EE:FF", []) == "unknown"
    assert wps_state("AA:BB:CC:DD:EE:FF", ["garbage line"]) == "unknown"


def test_clear_airodump_outputs_removes_caps_and_csvs(tmp_path):
    prefix = tmp_path / "n2ng_scan_lock"
    for name in (
        "n2ng_scan_lock-01.cap", "n2ng_scan_lock-02.cap",
        "n2ng_scan_lock-01.csv", "n2ng_scan_lock-01.kismet.csv",
        "n2ng_scan_lock-01.netxml",
    ):
        (tmp_path / name).write_text("stale")
    (tmp_path / "other-01.cap").write_text("keep")

    _n2ng.clear_airodump_outputs(str(prefix))

    assert list(tmp_path.iterdir()) == [tmp_path / "other-01.cap"]


def test_launch_clears_prior_caps_so_suffix_restarts_at_01(monkeypatch, tmp_path):
    """airodump-ng never overwrites prefix-NN files: stale caps must be
    deleted before spawn or the new run lands on a higher suffix and
    CaptureManager polls a dead file forever."""
    settings = _n2ng.Settings()
    worker = _n2ng.AirodumpWorker(_n2ng.queue.Queue(), settings)
    prefix = tmp_path / "n2ng_scan"
    (tmp_path / "n2ng_scan-07.cap").write_text("stale")
    (tmp_path / "n2ng_scan-07.csv").write_text("stale")
    proc = Mock()
    proc.stdout = iter([])
    proc.poll.return_value = None
    monkeypatch.setattr(_n2ng.subprocess, "Popen", lambda *a, **kw: proc)
    monkeypatch.setattr(_n2ng.AirodumpWorker, "_ensure_poll_thread", lambda self: None)

    ok, _ = worker.start_scan("wlan0mon", "Both", str(prefix))

    assert ok
    assert not (tmp_path / "n2ng_scan-07.cap").exists()
    assert not (tmp_path / "n2ng_scan-07.csv").exists()


def test_latest_airodump_cap_path_picks_highest_suffix(tmp_path):
    prefix = tmp_path / "cap"
    (tmp_path / "cap-01.cap").write_text("a")
    (tmp_path / "cap-12.cap").write_text("b")
    (tmp_path / "cap-02.cap").write_text("c")
    (tmp_path / "cap-12.csv").write_text("ignore")

    assert _n2ng.latest_airodump_cap_path(str(prefix)) == tmp_path / "cap-12.cap"
    assert _n2ng.latest_airodump_cap_path(str(tmp_path / "missing")) is None
