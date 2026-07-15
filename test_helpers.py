import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "n2ng", os.path.join(os.path.dirname(__file__), "n2_ng.py")
)
_n2ng = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_n2ng)

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
