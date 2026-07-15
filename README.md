# N2-ng

Single-window Python/tkinter GUI for wireless capture on Kali Linux.

## Run

```bash
cd /home/kali/n2-ng
python3 n2-ng.py
```

Enter the sudo password when prompted.

## Dependencies

```bash
sudo apt update
sudo apt install -y aircrack-ng iw hcxtools reaver wireshark-common pcapfix
```

## Supported adapters

- Alfa AWUS036ACHM
- TP-Link Archer T2U Nano
- NetGear Atheros adapters

Captures are saved to `~/hs/n2-ng/<ESSID>_<BSSID>/`.
