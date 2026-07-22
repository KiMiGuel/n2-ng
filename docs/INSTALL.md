# Install N2-NG

## Git Clone Method

```bash
git clone https://github.com/KiMiGuel/n2-ng.git
cd n2-ng
sudo ./install.sh
```

Fallback without the installer:

```bash
sudo apt update
sudo apt install -y aircrack-ng python3 python3-tk wireless-tools
python3 -m pip install .
n2-ng
```

## APT Repo Method

The APT repository is a bleeding-edge goal. Until packages are published, use the Git clone method or build the Debian package locally:

```bash
sudo apt update
sudo apt install -y debhelper dh-python python3-setuptools python3-tk aircrack-ng wireless-tools
dpkg-buildpackage -us -uc -b
sudo apt install ../n2-ng_0.1.2-1_all.deb
```

## Dependencies

- `aircrack-ng`
- `python3`
- `python3-tk`
- `wireless-tools`
- `scapy`

Optional helpers:

- `hcxtools` for `.22000` conversion
- `reaver` / `wash` for WPS scanning and Reaver support
- `wireshark-common` for `mergecap`
- `pcapfix` for capture repair

## Kali Linux Notes

N2-NG is built for Kali. Run it from a graphical session with a compatible wireless adapter that supports monitor mode and packet injection.

The tool asks for root privileges because monitor mode, channel changes, capture writing, and deauthentication require root.

## NetHunter Notes

NetHunter compatibility depends on the kernel, external adapter support, and whether `python3-tk` can open a usable graphical display. Use a full Kali NetHunter desktop session when possible.

## Troubleshooting

- No adapters listed: confirm the adapter is visible with `ip link` and supported by the kernel.
- Monitor mode starts but no networks appear: check the Raw View tab and verify that `airodump-ng` is producing data.
- Main table is empty but Raw View works: remove stale scan files only if needed; current builds follow the newest numbered CSV automatically.
- Deauth fails: lock a target first and verify the adapter supports packet injection.
- Tkinter import fails: install `python3-tk`.
