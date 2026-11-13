#!/bin/sh
# Update every scanner Daru drives that is already installed: system packages,
# Go-based tools (pinned versions below), pipx tools, and the nuclei templates.
# It updates what you have; it does not install new tools (use
# install-recon-tools.sh for that). Safe to run on its own or from a serve
# script.
#
# Versions are pinned on purpose and were verified against the projects'
# release pages on 2026-11-08. Bump a pin deliberately, never to @latest:
# @latest lets any upstream release change what runs on the host without
# review. The server also gates this script behind DARU_ALLOW_TOOL_UPDATE,
# a re-confirmation header, and a refusal to run as root.
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
  say "Updating Homebrew scanner tools"
  brew update >/dev/null 2>&1 || true
  for f in nmap masscan zmap nikto whatweb wafw00f dnsrecon fierce sslscan testssl tshark tcpdump fping hping3 arp-scan netdiscover theharvester wapiti smbmap dnstwist recon-ng unicornscan nbtscan onesixtyone smbclient whois hydra sqlmap wfuzz gobuster amass nuclei; do
    brew list --formula "$f" >/dev/null 2>&1 && brew upgrade "$f" 2>/dev/null || true
  done
elif [ -n "${PREFIX:-}" ] && command -v pkg >/dev/null 2>&1; then
  say "Updating Termux packages"; pkg update -y 2>/dev/null || true; pkg upgrade -y 2>/dev/null || true
fi

# --- Go-based tools: pinned versions, never @latest --------------------------
if command -v go >/dev/null 2>&1; then
  GOBIN="${GOBIN:-$HOME/go/bin}"; export GOBIN
  say "Updating Go-based scanners (pinned versions)"
  for spec in \
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1" \
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@v1.11.0" \
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0" \
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1" \
    "katana:github.com/projectdiscovery/katana/cmd/katana@v1.8.0" \
    "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.7.0" \
    "ffuf:github.com/ffuf/ffuf/v2@v2.3.0"
  do
    name=${spec%%:*}; pkg=${spec#*:}
    [ -x "$GOBIN/$name" ] || command -v "$name" >/dev/null 2>&1 || continue
    say "go install $name ${pkg##*@}"
    go install "$pkg" 2>/dev/null || warn "skip $name"
  done
fi

# --- pipx tools --------------------------------------------------------------
# pipx has no per-package version pin file here, so this only upgrades
# packages already installed through pipx. It installs nothing new.
if command -v pipx >/dev/null 2>&1; then
  say "Upgrading pipx tools"
  pipx upgrade-all 2>/dev/null || true
fi

# --- git-installed tools (recon-ng, spiderfoot) ------------------------------
# These track their default branch on purpose: the tools have no release
# tags. This only runs when an admin explicitly enables tool updates.
if command -v git >/dev/null 2>&1 && [ -d "$HOME/.daru/tools" ]; then
  for d in "$HOME/.daru/tools"/*; do
    [ -d "$d/.git" ] || continue
    say "Updating $(basename "$d")"
    ( cd "$d" && git pull --ff-only 2>/dev/null || true )
    if [ -x "$d/.venv/bin/pip" ] && [ -f "$d/requirements.txt" ]; then
      "$d/.venv/bin/pip" install -q -r "$d/requirements.txt" 2>/dev/null || true
    fi
  done
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
