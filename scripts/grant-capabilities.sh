#!/bin/sh
# Grant raw-socket capability to the few scanners that need it, so they work
# for a normal user WITHOUT running Daru (or the tools) as root.
#
# Tools like arp-scan, nmap (SYN/ARP scans), masscan, zmap, and packet capture
# need CAP_NET_RAW. The safe way to provide it is Linux file capabilities on
# each binary, not running the whole app as root. This grants exactly that.
#
# Linux only (setcap). On macOS these tools use a different mechanism and you
# typically run them with sudo instead.
#
# Usage: sh scripts/grant-capabilities.sh
set -eu

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }

if [ "$(uname -s)" != "Linux" ]; then
  warn "This script is Linux-only. On macOS, run capture/scan tools with sudo."
  exit 0
fi
if ! command -v setcap >/dev/null 2>&1; then
  warn "setcap not found. Install it first:"
  warn "  Debian/Ubuntu/BackBox/Kali:  sudo apt-get install -y libcap2-bin"
  warn "  Fedora/RHEL:                 sudo dnf install -y libcap"
  warn "  Arch:                        sudo pacman -S libcap"
  exit 1
fi

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

# binary -> capabilities it needs.
grant() {
  name="$1"; caps="$2"
  path=$(command -v "$name" 2>/dev/null || true)
  [ -z "$path" ] && { warn "skip $name (not installed)"; return; }
  # Resolve symlinks so setcap lands on the real file.
  real=$(readlink -f "$path" 2>/dev/null || echo "$path")
  if $SUDO setcap "$caps" "$real" 2>/dev/null; then
    say "granted [$caps] to $real"
  else
    warn "could not setcap $real (a wrapper script cannot take caps; the real binary can)"
  fi
}

# Packet capture (tshark) runs dumpcap, which on Debian/Ubuntu is installed as
# root:wireshark mode 0750 so only members of the 'wireshark' group may execute
# it. Add the invoking user to that group and grant dumpcap the capability, so
# live capture works without root. Group membership applies on next login.
setup_capture_group() {
  command -v getent >/dev/null 2>&1 || return 0
  getent group wireshark >/dev/null 2>&1 || return 0
  user="${SUDO_USER:-$(id -un)}"
  [ "$user" = "root" ] && return 0
  if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx wireshark; then
    say "$user is already in the wireshark group"
  else
    if $SUDO usermod -aG wireshark "$user" 2>/dev/null; then
      say "added $user to the wireshark group (log out and back in to take effect)"
    else
      warn "could not add $user to the wireshark group; run: sudo usermod -aG wireshark $user"
    fi
  fi
}

say "Granting raw-socket capability to scan and capture tools"
setup_capture_group
grant nmap     "cap_net_raw,cap_net_admin,cap_net_bind_service+eip"
grant masscan  "cap_net_raw,cap_net_admin+eip"
grant zmap     "cap_net_raw,cap_net_admin+eip"
grant arp-scan "cap_net_raw+eip"
grant netdiscover "cap_net_raw+eip"
grant hping3   "cap_net_raw+eip"
grant rustscan "cap_net_raw,cap_net_admin+eip"
grant fping    "cap_net_raw+eip"
grant tcpdump  "cap_net_raw,cap_net_admin+eip"
# tshark captures through dumpcap; grant the helper, not tshark itself.
grant dumpcap  "cap_net_raw,cap_net_admin+eip"

say "Done. These tools now work for your normal user, no root needed."
say "Daru itself still runs as your user; only these binaries got the capability."
