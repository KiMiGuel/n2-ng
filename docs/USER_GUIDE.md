# N2-NG User Guide

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

- Toolbar: adapter selection, band selection, monitor controls, WPS scan, settings.
- Main table: live access point scan results.
- Scan tab: locked target details, clients, signal graph, attack controls, capture history.
- Raw View tab: live `airodump-ng` output from the same scan process.
- Log pane: application status, commands, and capture notices.

## Columns

- BSSID: access point MAC address.
- PWR: signal power.
- Beacons: beacon frames seen.
- #Data: data packets seen.
- CH: channel.
- MB: advertised speed.
- ENC: encryption family.
- CIPHER: cipher suite.
- AUTH: authentication mode.
- ESSID: network name.

## Sorting

Columns are designed to support sortable workflows. PWR, Beacons, and #Data should sort high-to-low and low-to-high. Current builds include settings-driven sorting; clickable column sorting remains a roadmap polish item.

## Capturing Handshakes

1. Select an adapter.
2. Click `Start Monitor`.
3. Double-click a network or right-click and choose `Lock Target`.
4. Use `Deauthenticate All Clients`, `Deauthenticate Specific Client`, or auto-deauth.
5. Watch for the handshake or PMKID notification.

Use only on networks you own or are authorized to test.

## Saving Captures

Captures are saved under:

```text
~/hs/n2-ng/<ESSID>_<BSSID>/
```

Supported outputs:

- `.cap`
- `.pcap`
- `.22000`

## Right-Click Context Menus

The capture history right-click menu can:

- Copy a hashcat command
- Copy `.22000` content
- Fix a capture with `pcapfix`
- Merge selected captures with `mergecap`

Cap merge/fix is currently accessible only via right-click. There is no visible button yet.

## Keyboard Shortcuts

- Spacebar: pause/resume scan
- Double-click network: lock target
- Right-click network: copy BSSID/ESSID or lock target
- Right-click client: deauth that client

## Common Use Cases

- Scan all nearby access points with live channel hopping.
- Lock a target and keep channel/BSSID aligned.
- Capture WPA handshakes and PMKIDs.
- Export captures for hashcat.
- Repair or merge captures from the history menu.
