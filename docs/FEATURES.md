# N2-NG Features (v1.1)

N2-NG is a Python 3 + Tkinter GUI for WiFi auditing on Kali Linux. It wraps the
aircrack-ng suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`) and hcxtools
(`hcxpcapngtool`, `hcxhash2cap`) into a single window, and adds capture
verification and automation on top.

## Feature list

### Scanning and monitor mode

- One-click monitor mode via `airmon-ng` (uses the interface directly if it is
  already in monitor mode).
- Live channel-hopping scan on 2.4 GHz, 5 GHz, or both bands via `airodump-ng`.
- Sortable network table: BSSID, PWR, Beacons, #Data, CH, MB, ENC, CIPHER,
  AUTH, manufacturer, ESSID. Column visibility is configurable.
- Manufacturer (OUI) detection with `airodump-ng -M`.
- Encryption filter (All / WEP / WPA-WPA2 / WPA3 / Open).
- Raw View tab with the live `airodump-ng` terminal output, ANSI colors
  included.
- Channel lock: selecting a target locks the adapter to its channel and keeps
  the system channel aligned so `aireplay-ng` does not complain about
  mismatches. Manual unlock, or automatic unlock after a successful capture.
- MAC randomization before entering monitor mode (optional, on by default per
  settings).
- Managed-mode restore on quit: interfaces N2-NG put into monitor mode are
  returned to managed mode when the app closes; pre-existing monitor
  interfaces are left alone.

### WPA handshake capture with verification gate (new in v1.1)

- Deauthentication attacks (all clients or a specific client) via
  `aireplay-ng -0`.
- Auto-deauth loop: fires a deauth burst every 10/30/60 s until a *verified*
  handshake or a PMKID is captured, then stops on its own.
- The capture is continuously converted to hashcat 22000 format in the
  background while capturing, and every WPA\*02 (EAPOL) record is classified
  by its MESSAGEPAIR byte (low 3 bits; flag bits such as
  nonce-error-correction `0x80` are masked off):
  - **AUTHORIZED** (messagepair 1–5): the AP accepted the client's proof, so
    the client knew the correct PSK. The handshake is crackable. This is the
    only EAPOL verdict that stops the auto-deauth loop.
  - **CHALLENGE** (messagepair 0, M1+M2 only): the AP's M1 and the client's
    M2 were captured, but the AP never confirmed the client. This commonly
    happens when a client authenticates with a *wrong password* — the
    resulting MIC is computed from the wrong PSK and can never be cracked.
    Treating it as "handshake captured" is a classic false positive of the
    raw aircrack-ng workflow. N2-NG logs a warning
    ("Handshake UNVERIFIED … keep capturing") and keeps deauthing.
  - **PMKID**: WPA\*01 records are always valid attack material (no client
    interaction needed at capture time), so they stop the loop as before.
- Verdict badge in the Capture Sessions action bar shows the selected
  session's verdict: AUTHORIZED (green), CHALLENGE (orange), PMKID (green),
  NO PAIR (grey/red), or "—" when no .22000 exists yet. Verdicts are cached
  per file path + mtime and recomputed whenever the .22000 is regenerated.

### Automatic .22000 pipeline (new in v1.1)

- A current hashcat .22000 file is produced automatically; the manual
  "Convert to 22000" button was removed. Conversion happens:
  - continuously during capture (the gate above),
  - after **Fix Capture** succeeds,
  - after **Merge** succeeds,
  - lazily when a capture session without a .22000 is selected
    (background thread, once per file, never blocks the UI).
- Conversion uses `hcxpcapngtool` and validates that the output actually
  contains PMKID/EAPOL records.

### Capture session management

- Sessions list of all captures and hashes under `~/hs/n2-ng/`, auto-refreshed
  every 20 s.
- Inspect: file metadata, hashcat record counts and types, related .22000.
- Fix Capture: repair damaged captures with `pcapfix`.
- Merge: combine 2+ captures with `mergecap`; the merged output is verified
  to still contain WPA records, and the originals can optionally be archived
  to `~/hs/n2-ng/.archive/<date>/` after a successful merge.
- Normalize to PCAPNG with `editcap`.
- Reconstruct a synthetic .cap from a .22000 hash file with `hcxhash2cap`
  (with an explicit warning that it is not the original capture).
- Copy hashcat command or raw .22000 content to the clipboard.
- Right-click context menu with all of the above.

### Attacks

- Deauthenticate All Clients / Specific Client (`aireplay-ng -0`).
- Auto-deauth loop (see above).
- WPS scan (`wash`, falling back to `reaver --scan`) with a live output
  dialog.
- Reaver WPS PIN attack against the locked target.
- Legacy WEP attacks (behind a "Show Legacy WEP Attacks" toggle): fake
  authentication, ARP replay, chopchop, fragmentation. Source MAC is resolved
  from sysfs so these work with randomized MACs.
- Stop Attack kills the entire attack process group — no orphaned
  `aireplay-ng`/`reaver` processes.

### Hashcat integration

- Hashcat dialog for any session with a valid .22000: dictionary attack
  (`-m 22000 -a 0`) with wordlist picker, live command preview, streaming
  output, Start/Stop, and a named session (`n2ng-<timestamp>`) so runs can be
  resumed with `hashcat --session n2ng-<timestamp> --restore`.

### UI / quality of life

- Two-level table sorting (new in v1.1): sorting by PWR breaks ties by
  channel ascending; sorting by CH breaks ties by power descending. All other
  columns keep single-key behavior.
- Click column headers to sort; click again to reverse direction.
- Small-screen support down to 800x480 (window and dialogs clamp to the
  screen, right panel scrolls).
- Dark terminal-style theme, monospace scan table, signal-strength graph for
  the locked target.
- Dependency checking at startup and per feature: missing optional tools
  (hcxtools, reaver, mergecap, editcap, pcapfix, hashcat, tshark) produce a
  warning with the `apt` install command instead of a crash.
- Settings persist per user (including the invoking user when run via sudo).

## Compared to the manual tooling

### vs. the raw aircrack-ng workflow (airmon-ng + airodump-ng + aireplay-ng + aircrack-ng)

The classic workflow needs at least three terminals: one running
`airodump-ng` locked on a channel, one firing `aireplay-ng -0` bursts, and
one to check the capture — where "is the handshake good?" usually means
re-reading airodump's `WPA handshake` note, opening the capture in Wireshark,
or running `aircrack-ng`/`cowpatty` against it. That note appears for *any*
M1+M2 pair, including pairs from clients that used the wrong password, which
are uncrackable.

N2-NG automates the whole loop in one window: monitor mode, channel locking,
deauth bursts, and — since v1.1 — *verification* of what was captured by
parsing the messagepair byte of every EAPOL record, so the auto-deauth loop
only stops on material that can actually be cracked. Captures are converted
to hashcat format automatically instead of by hand.

What it does **not** replace: the fine-grained control of the individual
tools. There is no way to craft custom `aireplay-ng` invocations, tweak
`airodump-ng` beyond the exposed settings, or run `aircrack-ng` itself for
WEP cracking — the legacy WEP attacks are convenience wrappers, not a full
WEP toolkit.

### vs. hcxtools (hcxdumptool + hcxpcapngtool)

`hcxdumptool` is a dedicated attack/capture engine: it does AP-less PMKID
attacks, active EAPOL probing, and beacon-less interaction that
`airodump-ng` + `aireplay-ng` simply do not do. N2-NG does **not** replace
hcxdumptool — its capture engine is still `airodump-ng`, and PMKIDs are only
collected passively when an AP offers them.

What N2-NG adds on the hcxtools side is the post-processing automation: every
capture is run through `hcxpcapngtool` automatically (during capture, after
fix, after merge, and on selection), the output is validated, and the
messagepair-based verdict tells you whether the extracted hash is worth
feeding to hashcat before you spend GPU time on it. If you want hcxdumptool's
active attack modes, run hcxdumptool and import the resulting pcapng into
N2-NG's session list — the .22000 pipeline and verdict badge work on those
files too.
