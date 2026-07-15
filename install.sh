#!/usr/bin/env bash
set -e

echo "[N2-ng] Checking dependencies..."

MISSING=()

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        MISSING+=("$1")
        echo "  MISSING: $1 ($2)"
    else
        echo "  OK: $1"
    fi
}

need airmon-ng "sudo apt install -y aircrack-ng"
need airodump-ng "sudo apt install -y aircrack-ng"
need aireplay-ng "sudo apt install -y aircrack-ng"
need iw "sudo apt install -y iw"
need hcxpcapngtool "sudo apt install -y hcxtools"
need wash "sudo apt install -y reaver"
need mergecap "sudo apt install -y wireshark-common"
need pcapfix "sudo apt install -y pcapfix"

if [ ${#MISSING[@]} -eq 0 ]; then
    echo "[N2-ng] All dependencies satisfied."
    exit 0
fi

echo "[N2-ng] Missing optional/required tools."
echo "Install commands:"
echo "  sudo apt update && sudo apt install -y aircrack-ng iw hcxtools reaver wireshark-common pcapfix"
echo "Or build from source:"
echo "  https://github.com/aircrack-ng/aircrack-ng"
echo "  https://github.com/ZerBea/hcxtools"
echo "  https://github.com/t6x/reaver-wps-fork-t6x"
exit 1
