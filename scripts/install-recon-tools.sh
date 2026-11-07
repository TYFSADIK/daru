#!/bin/sh
# Optional: install the security scanners Daru's recon connectors can drive.
#
# These are standard, dual-use security tools. Install them ONLY if you will
# use them for authorized testing of systems you own or are permitted to test.
# Daru runs each tool only when its binary is present and behind an
# authorization gate; this script just installs the binaries.
#
# It uses your system package manager and installs nothing offensive by
# default: port/host discovery, vulnerability and web scanners, DNS/OSINT,
# and traffic analysis. It never installs DoS tools, mass auto-exploiters,
# or anti-virus evasion tooling.
#
# Usage: sh install-recon-tools.sh
set -eu

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }

cat <<'EOF'
This installs security scanners used by Daru's recon connectors
(nmap, masscan, nikto, nuclei, httpx, subfinder, amass, dnsx, whatweb,
wafw00f, sslyze, tshark, and similar).

Use them only against systems you own or are explicitly authorized to test.
EOF
printf 'Continue? [y/N] '
read -r ans
case "$ans" in y|Y|yes|YES) : ;; *) echo "Aborted."; exit 0 ;; esac

# Package sets by manager. Names differ a little per platform; missing ones
# are skipped rather than failing the whole run.
APT="nmap masscan nikto whatweb wafw00f dnsutils dnsrecon amass sslyze tshark tcpdump fping hping3 theharvester"
BREW="nmap masscan nikto whatweb wafw00f amass sslyze wireshark fping hping theharvester nuclei httpx subfinder dnsx"
PKG="nmap masscan nikto tshark tcpdump fping"
DNF="nmap nikto whatweb tcpdump wireshark-cli fping theHarvester"
PACMAN="nmap nikto whatweb tcpdump wireshark-cli fping"

install_each() {
  mgr="$1"; shift
  for pkg in "$@"; do
    say "Installing $pkg"
    case "$mgr" in
      apt)    sudo apt-get install -y "$pkg" 2>/dev/null || warn "skip $pkg" ;;
      brew)   brew install "$pkg" 2>/dev/null || warn "skip $pkg" ;;
      pkg)    pkg install -y "$pkg" 2>/dev/null || warn "skip $pkg" ;;
      dnf)    sudo dnf install -y "$pkg" 2>/dev/null || warn "skip $pkg" ;;
      pacman) sudo pacman -S --noconfirm "$pkg" 2>/dev/null || warn "skip $pkg" ;;
    esac
  done
}

if [ -n "${PREFIX:-}" ] && printf '%s' "$PREFIX" | grep -q com.termux; then
  say "Termux detected"; pkg update -y || true; install_each pkg $PKG
elif command -v apt-get >/dev/null 2>&1; then
  say "apt detected"; sudo apt-get update || true; install_each apt $APT
elif command -v brew >/dev/null 2>&1; then
  say "Homebrew detected"; install_each brew $BREW
elif command -v dnf >/dev/null 2>&1; then
  say "dnf detected"; install_each dnf $DNF
elif command -v pacman >/dev/null 2>&1; then
  say "pacman detected"; install_each pacman $PACMAN
else
  warn "No supported package manager found. Install the tools you need manually."
  exit 1
fi

say "Done. Tools that installed will show as available in Daru's Recon tab."
say "Projects such as nuclei, httpx, subfinder, and amass may also be installed with 'go install' from their official repos."
