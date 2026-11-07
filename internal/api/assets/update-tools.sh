#!/bin/sh
# Update every scanner Daru drives that is already installed: system packages,
# Go-based tools (@latest), pipx tools, and the nuclei templates. It updates
# what you have; it does not install new tools (use install-recon-tools.sh for
# that). Safe to run on its own or from a serve script.
set -u

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }

# Use sudo only when not already root and sudo exists.
SUDO=""
[ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

# --- system packages ---------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
  say "Updating apt scanner packages"
  $SUDO apt-get update -y >/dev/null 2>&1 || true
  PKGS="nmap masscan zmap nikto whatweb wafw00f dnsutils dnsrecon dnsenum fierce sslscan testssl.sh tshark tcpdump fping hping3 arp-scan netdiscover theharvester wapiti smbmap dnstwist recon-ng unicornscan nbtscan onesixtyone smbclient whois hydra sqlmap wfuzz gobuster dirb amass nuclei"
  up=""
  for p in $PKGS; do dpkg -s "$p" >/dev/null 2>&1 && up="$up $p"; done
  if [ -n "$up" ]; then
    # shellcheck disable=SC2086
    $SUDO apt-get install -y --only-upgrade $up 2>/dev/null || warn "some apt upgrades were skipped"
  fi
elif command -v brew >/dev/null 2>&1; then
  say "Updating Homebrew tools"; brew update >/dev/null 2>&1 || true; brew upgrade 2>/dev/null || true
elif [ -n "${PREFIX:-}" ] && command -v pkg >/dev/null 2>&1; then
  say "Updating Termux packages"; pkg update -y 2>/dev/null || true; pkg upgrade -y 2>/dev/null || true
fi

# --- Go-based tools: @latest re-fetches the newest release -------------------
if command -v go >/dev/null 2>&1; then
  GOBIN="${GOBIN:-$HOME/go/bin}"; export GOBIN
  say "Updating Go-based scanners"
  for spec in \
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest" \
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
    "katana:github.com/projectdiscovery/katana/cmd/katana@latest" \
    "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" \
    "ffuf:github.com/ffuf/ffuf/v2@latest"
  do
    name=${spec%%:*}; pkg=${spec#*:}
    [ -x "$GOBIN/$name" ] || command -v "$name" >/dev/null 2>&1 || continue
    say "go install $name@latest"
    go install "$pkg" 2>/dev/null || warn "skip $name"
  done
fi

# --- pipx tools --------------------------------------------------------------
if command -v pipx >/dev/null 2>&1; then
  say "Upgrading pipx tools"
  pipx upgrade-all 2>/dev/null || true
fi

# --- nuclei templates (the detection content, not just the binary) -----------
NUC=""
command -v nuclei >/dev/null 2>&1 && NUC=$(command -v nuclei)
[ -z "$NUC" ] && [ -x "$HOME/go/bin/nuclei" ] && NUC="$HOME/go/bin/nuclei"
if [ -n "$NUC" ]; then
  say "Updating nuclei templates"
  "$NUC" -update-templates 2>/dev/null || "$NUC" -ut 2>/dev/null || true
fi

say "Tool update complete."
