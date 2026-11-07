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
# Non-interactive when called with -y/--yes or RECON_ASSUME_YES=1 (the main
# installer's --with-tools uses this). Otherwise ask for consent.
ASSUME_YES="${RECON_ASSUME_YES:-0}"
case "${1:-}" in -y|--yes|yes) ASSUME_YES=1 ;; esac
if [ "$ASSUME_YES" != 1 ]; then
  printf 'Continue? [y/N] '
  read -r ans
  case "$ans" in y|Y|yes|YES) : ;; *) echo "Aborted."; exit 0 ;; esac
else
  say "Consent given via flag; installing without prompting."
fi

# Package sets by manager. Names differ a little per platform; missing ones
# are skipped rather than failing the whole run. These are discovery,
# vulnerability, web, DNS/OSINT, and traffic-analysis tools only.
APT="nmap masscan zmap nikto whatweb wafw00f dnsutils dnsrecon dnsenum fierce amass sslscan sslyze tshark tcpdump fping hping3 arp-scan netdiscover theharvester wapiti nbtscan onesixtyone snmp smbclient nuclei whois wordlists seclists hydra sqlmap wfuzz gobuster dirb ncat socat net-tools traceroute mtr-tiny"
BREW="nmap masscan zmap nikto whatweb wafw00f amass sslscan sslyze wireshark fping hping theharvester nuclei httpx subfinder dnsx gobuster ffuf sqlmap hydra arp-scan whois ncat socat"
PKG="nmap masscan nikto tshark tcpdump fping hydra sqlmap gobuster whois ncat socat net-tools"
DNF="nmap masscan nikto whatweb tcpdump wireshark-cli fping arp-scan theHarvester hydra sqlmap gobuster whois nmap-ncat socat"
PACMAN="nmap masscan nikto whatweb tcpdump wireshark-cli fping arp-scan hydra sqlmap gobuster whois gnu-netcat socat"

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

# Several popular scanners (ProjectDiscovery's nuclei, httpx, subfinder, dnsx,
# katana, and ffuf) ship as Go programs and are often not in the package
# manager. Install them with `go install` when Go is present.
if command -v go >/dev/null 2>&1; then
  say "Installing Go-based scanners with go install"
  GOBIN="${GOBIN:-$HOME/go/bin}"; export GOBIN
  for spec in \
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest" \
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
    "katana:github.com/projectdiscovery/katana/cmd/katana@latest" \
    "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" \
    "ffuf:github.com/ffuf/ffuf/v2@latest" \
    "gobuster:github.com/OJ/gobuster/v3@latest" \
    "amass:github.com/owasp-amass/amass/v4/...@master"
  do
    name=${spec%%:*}; pkg=${spec#*:}
    if command -v "$name" >/dev/null 2>&1; then say "have $name"; continue; fi
    say "go install $name"
    go install "$pkg" 2>/dev/null || warn "skip $name (go install failed)"
  done
  case ":$PATH:" in *":$GOBIN:"*) : ;; *) warn "Add $GOBIN to your PATH to use the Go-based tools" ;; esac
else
  say "Go not found; skipping nuclei/httpx/subfinder/dnsx (install Go to get them)."
fi

# Offer the capability grant so raw-socket tools work without running as root.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$(uname -s)" = "Linux" ] && [ -f "$SCRIPT_DIR/grant-capabilities.sh" ]; then
  say "Granting raw-socket capability to scan/capture tools (so no root is needed)"
  sh "$SCRIPT_DIR/grant-capabilities.sh" || warn "capability grant skipped; run scripts/grant-capabilities.sh later"
fi

say "Done. Tools that installed will show as available in Daru's Recon tab."
