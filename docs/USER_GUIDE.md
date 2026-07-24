# N2-NG User Guide (v1.1)

Use N2-NG only on networks you own or are explicitly authorized to test.

## Launching

```bash
n2-ng
```

From a source checkout:

```bash
cd /home/kali/n2-ng
./n2-ng
```

## GUI Layout

- **Toolbar**: adapter and band selection, monitor/scan controls, WPS scan,
  settings, channel-lock indicator.
- **Main table**: live access point scan results.
- **Scan tab**: locked-target details, client list, signal graph, attack
  controls, capture sessions.
- **Raw View tab**: live `airodump-ng` output from the same scan process.
- **Log pane**: application status, executed commands, and capture notices.

## The basic workflow

1. Pick your adapter in the **Adapter** dropdown (its current MAC is shown
   next to it) and a band (**2.4GHz**, **5GHz**, or **Both**).
2. Click **Start Monitor**. The adapter goes into monitor mode (with a
   randomized MAC if that setting is on) and scanning starts immediately.
3. Find your target in the table. Click a column header to sort — e.g. PWR
   for the strongest signal first.
4. Double-click the network (or right-click → Lock Target). The adapter
   locks onto the target's channel and the target panel fills in.
5. Enable **Auto-deauth until handshake** and watch the log. Clients get
   deauthed on the chosen interval until a *verified* handshake or a PMKID
   is captured — then the loop stops by itself.
6. Check the **verdict badge** in the Capture Sessions action bar (see
   below) to confirm the capture is actually crackable.
7. Select the session and click **Hashcat** to crack, or right-click to copy
   the hashcat command / .22000 content for your own rig.

### The verdict badge

Every capture is automatically converted to hashcat 22000 format, and the
EAPOL records are classified by their messagepair byte:

| Badge | Meaning | What to do |
|-------|---------|------------|
| **AUTHORIZED** (green) | The AP accepted the client's proof (messagepair 1–5). The handshake is crackable. | Crack it. |
| **CHALLENGE** (orange) | M1+M2 only (messagepair 0) — the AP never confirmed the client. Typical for a client that used the wrong password; the MIC is uncrackable. | Keep capturing. The auto-deauth loop does **not** stop on this. |
| **PMKID** (green) | A PMKID was captured. Always valid attack material. | Crack it. |
| **NO PAIR** (grey/red) | The .22000 exists but contains no usable records. | Keep capturing or pick another session. |
| **—** | Nothing selected, or no .22000 generated yet. | Wait a moment — conversion is automatic. |

Since v1.1 the auto-deauth loop only stops on AUTHORIZED or PMKID. A
CHALLENGE verdict logs
`Handshake UNVERIFIED (M1+M2 challenge only — possible failed auth, keep capturing)`
and the loop keeps running.

### Automatic .22000 conversion

You never convert captures by hand anymore. A .22000 is (re)generated
automatically: continuously while capturing, after Fix Capture, after Merge,
and in the background whenever you select a capture that doesn't have one
yet. The old **Convert to 22000** button was removed in v1.1 because of this.
The badge updates as soon as the new .22000 lands.

## Toolbar reference

| Control | What it does |
|---------|--------------|
| **Adapter** dropdown | Selects the wireless interface; shows its MAC next to it. |
| **Band** dropdown | Restricts the scan to 2.4 GHz, 5 GHz, or Both. |
| **Start Monitor** | Puts the adapter into monitor mode (randomizing its MAC first if enabled) and starts the scan. Uses the interface as-is if it's already a monitor interface. |
| **Stop Scan** | Stops `airodump-ng` and clears the network table. Monitor mode stays on. |
| **Pause Scan** / **Resume Scan** | Suspends/resumes the scan process (SIGSTOP/SIGCONT) without losing state. Spacebar does the same. |
| **Unlock** | Releases the channel lock so the adapter hops channels again. Enabled only while a channel is locked. |
| **Stop Monitor** | Stops the scan and returns the adapter to managed mode. |
| **WPS Scan** | Runs `wash` (or `reaver --scan` if wash is missing) and shows WPS-enabled networks in a live dialog. |
| **Refresh Adapters** | Re-detects wireless interfaces (use after plugging in a USB adapter). |
| **Settings** | Opens the Airodump Settings dialog (below). |
| Channel pill (right edge) | Shows `SCANNING ALL` (red) while hopping, or the locked channel while locked. |

## Network table and sorting

Columns: PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, MANU, ESSID, BSSID.

- **Click a column header** to sort by it; click again to reverse direction.
  A ▲/▼ arrow marks the active column. BSSID is not sortable.
- **Two-level tiebreak (new in v1.1):** when sorting by PWR, equal power
  values are ordered by channel ascending; when sorting by CH, equal channels
  are ordered by power descending. Other columns sort single-key as before.
- Right-click a header to show/hide columns.
- Right-click a network row: lock target, copy BSSID/ESSID.
- Double-click a network row: lock it as the target.
- The **ENC** colors: green = Open, red = WEP, yellow = WPA, white = WPA2,
  blue = WPA3.

## Attack panel

| Control | What it does |
|---------|--------------|
| **Deauthenticate All Clients** | One `aireplay-ng -0 10` burst against the locked target's BSSID. Use for a quick manual handshake attempt. |
| **Deauthenticate Specific Client** | Same, aimed at one client (pick it in the client list or right-click a client → deauth). Gentler on the network. |
| **Reaver WPS Attack** | Starts a Reaver WPS PIN attack against the locked target (requires `reaver`; check WPS Scan first). |
| **Stop Attack** | Kills the entire attack process group (aireplay/reaver), not just the parent. |
| **Show Legacy WEP Attacks** | Reveals the WEP museum: Fake Authentication, ARP Replay, Chopchop, Fragmentation. Only useful on WEP networks. |
| **Auto-deauth until handshake** | Checkbox: deauth bursts every **10 / 30 / 60 s** (dropdown) until a verified handshake (AUTHORIZED) or PMKID is captured. Does not stop on CHALLENGE. |

## Capture Sessions panel

Lists every capture and hash file under `~/hs/n2-ng/` (auto-refreshed every
20 s). Select one or more rows to enable actions.

Action bar:

| Control | What it does |
|---------|--------------|
| **Inspect** | Shows file metadata in the details pane: size, mtime, hashcat record count/types, related .22000. |
| Verdict badge | Verdict of the selected session (AUTHORIZED / CHALLENGE / PMKID / NO PAIR / —). See the table above. |
| **Fix Capture** | Repairs a damaged capture with `pcapfix`. The fixed file's .22000 is generated automatically. |
| **Merge** | Merges 2+ selected captures with `mergecap` and verifies the result still contains WPA records. If *Archive originals* is on, sources move to `~/hs/n2-ng/.archive/<date>/` after a verified merge. The merged file's .22000 is generated automatically. |
| **Hashcat** | Opens the Hashcat dialog for the session's .22000 (enabled when a valid one exists). |

Right-click menu adds: **Copy hashcat command**, **Copy .22000 content**,
**Fix capture**, **Normalize to PCAPNG** (editcap), **Reconstruct CAP from
Hash** (hcxhash2cap — creates a *synthetic* cap from hash material, not the
original packets), **Copy path**, **Merge selected**. The old
**Convert to 22000** entry was removed in v1.1 — conversion is automatic.

## Hashcat dialog

Dictionary attack (`hashcat -m 22000 -a 0`) against the session's .22000:

- **Hash file**: the .22000 to crack (pre-filled).
- **Wordlist** + **Browse**: defaults to `/usr/share/wordlists/rockyou.txt`
  when present.
- Live **command preview** so you can see exactly what will run.
- **Start** / **Stop**: runs hashcat with streaming output in the dialog.
  Runs under a named session (`n2ng-<timestamp>`) — resume later with
  `hashcat --session n2ng-<timestamp> --restore`.
- **Close** stops a running attack before closing.

## Settings dialog

| Setting | Effect |
|---------|--------|
| **Color output** | Passes `--color` to airodump-ng (colors in Raw View). |
| **Quiet mode (-q)** | Less airodump-ng terminal noise. |
| **Pause scan** | Opens the dialog with the scan paused. |
| **Realtime sort** | Continuously re-sorts the table as scan data updates (instead of only on header clicks). |
| **Show manufacturers (-M)** | Fills the MANU column via airodump-ng's OUI lookup. |
| **Sort by** | Default sort column when you haven't clicked a header (PWR / Beacons / #Data / CH / ESSID / BSSID). |
| **Filter encryption** | Show only All / WEP / WPA-WPA2 / WPA3 / Open networks. |
| **Write interval (s)** | How often airodump-ng flushes output files (1–60). |
| **Output formats** | Which files airodump-ng writes: csv / pcap / kismet (csv is always kept). |
| **Auto-unlock channel after capture** | Resume channel hopping automatically once a verified handshake/PMKID is captured. |
| **Randomize MAC before monitor mode** | Randomize the adapter MAC each time monitor mode starts (on by default). |
| **Archive originals after successful merge** | Move merge sources into `~/hs/n2-ng/.archive/<date>/` after the merged output is verified. |

**Apply** saves immediately; GUI-only settings take effect without restarting
the scan, scan-affecting ones restart it.

## Captures on disk

```text
~/hs/n2-ng/<ESSID>_<BSSID>/           raw captures per target
~/hs/n2-ng/hashcat/<date>/            generated .22000 files
~/hs/n2-ng/fixed/<date>/              repaired captures
~/hs/n2-ng/merged/<date>/             merged captures
~/hs/n2-ng/pcapng/<date>/             normalized pcapng files
~/hs/n2-ng/reconstructed/<date>/      synthetic caps rebuilt from hashes
~/hs/n2-ng/.archive/<date>/           merge sources (optional archiving)
```

## Keyboard shortcuts

- **Spacebar**: pause/resume scan (not while typing in an entry field).
- **Double-click** network: lock target.
- **Right-click** network: copy BSSID/ESSID or lock target.
- **Right-click** client: deauth that client.
- **Right-click** capture session: full action menu.

## Common use cases

- Scan nearby APs with live channel hopping; sort by PWR (ties now break by
  channel) to find the strongest target.
- Lock a target and let auto-deauth run until an AUTHORIZED handshake stops
  it — a CHALLENGE badge means keep waiting, not start cracking.
- Merge several captures of the same target into one, let the .22000
  regenerate, then crack from the Hashcat dialog.
- Repair a truncated capture with Fix Capture; the fixed file is re-converted
  automatically.
- Export clean .22000 material for an external cracking rig via right-click →
  Copy hashcat command / Copy .22000 content.
