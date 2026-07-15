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
