#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${N2NG_REPO_URL:-https://github.com/KiMiGuel/n2-ng.git}"
WORKDIR="${N2NG_WORKDIR:-}"

if ! command -v apt-get >/dev/null 2>&1; then
    echo "N2-NG installer expects a Debian/Kali system with apt-get." >&2
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}" in
        kali|debian|ubuntu) ;;
        *) echo "Warning: unsupported distro '${ID:-unknown}'. Continuing because apt-get exists." ;;
    esac
fi

if [ "$(id -u)" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi

apt-get update
apt-get install -y \
    aircrack-ng \
    git \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-tk \
    python3-wheel \
    wireless-tools

if [ ! -f setup.py ]; then
    WORKDIR="$(mktemp -d)"
    git clone "$REPO_URL" "$WORKDIR/n2-ng"
    cd "$WORKDIR/n2-ng"
fi

python3 -m pip install .

# Add a convenient alias for the source-tree launcher when installing from git.
add_alias() {
    local user="${SUDO_USER:-$USER}"
    local home
    home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
    [ -z "$home" ] && return
    local rc="$home/.bashrc"
    local line="alias n2-ng='\$HOME/n2-ng/n2-ng'"
    if [ -f "$rc" ] && ! grep -qxF "$line" "$rc" 2>/dev/null; then
        printf '\n# N2-NG launcher alias\n%s\n' "$line" >> "$rc"
    fi
}
add_alias

echo "N2-NG installed. Launch with: n2-ng"
