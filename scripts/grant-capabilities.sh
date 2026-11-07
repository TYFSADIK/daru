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

say "Granting raw-socket capability to scan and capture tools"
grant nmap     "cap_net_raw,cap_net_admin,cap_net_bind_service+eip"
grant masscan  "cap_net_raw,cap_net_admin+eip"
grant zmap     "cap_net_raw,cap_net_admin+eip"
grant arp-scan "cap_net_raw+eip"
grant netdiscover "cap_net_raw+eip"
grant hping3   "cap_net_raw+eip"
grant fping    "cap_net_raw+eip"
grant tcpdump  "cap_net_raw,cap_net_admin+eip"
# tshark captures through dumpcap; grant the helper, not tshark itself.
grant dumpcap  "cap_net_raw,cap_net_admin+eip"

say "Done. These tools now work for your normal user, no root needed."
say "Daru itself still runs as your user; only these binaries got the capability."
