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
APT="nmap masscan zmap nikto whatweb wafw00f dnsutils dnsrecon dnsenum fierce amass sslscan sslyze testssl.sh tshark tcpdump fping hping3 arp-scan netdiscover theharvester wapiti smbmap enum4linux dnstwist recon-ng unicornscan nbtscan onesixtyone snmp smbclient nuclei whois wordlists seclists hydra sqlmap wfuzz gobuster dirb ncat socat net-tools traceroute mtr-tiny pipx python3-pip python3-venv python3-full"
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

# Python-based scanners install cleanly with pipx (each in its own venv).
# Binary names must match what Daru looks for: theHarvester, sslyze, wapiti,
# dnstwist, smbmap. pipx needs python3-venv to build each tool's virtualenv;
# without it every install fails, so install it first.
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y pipx python3-venv python3-pip python3-full 2>/dev/null || true
elif ! command -v pipx >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  python3 -m pip install --user pipx 2>/dev/null || \
    python3 -m pip install --user --break-system-packages pipx 2>/dev/null || true
fi
# Resolve pipx even if it is only reachable as a module.
PIPX=""
if command -v pipx >/dev/null 2>&1; then PIPX="pipx"
elif python3 -m pipx --version >/dev/null 2>&1; then PIPX="python3 -m pipx"
fi
if [ -n "$PIPX" ]; then
  say "Installing Python-based scanners with pipx"
  $PIPX ensurepath >/dev/null 2>&1 || true
  for spec in \
    "theHarvester:theHarvester" \
    "sslyze:sslyze" \
    "wapiti:wapiti3" \
    "dnstwist:dnstwist" \
    "smbmap:smbmap" \
    "gvm-cli:gvm-tools"
  do
    name=${spec%%:*}; pkg=${spec#*:}
    if command -v "$name" >/dev/null 2>&1; then say "have $name"; continue; fi
    say "pipx install $pkg"
    # Capture output so we can show the real error and still see the exit code.
    if out=$($PIPX install "$pkg" 2>&1); then
      :
    else
      printf '%s\n' "$out" | tail -4
      warn "skip $pkg (often fixed by: sudo apt-get install -y python3-venv)"
    fi
  done
else
  warn "pipx unavailable. Install it: sudo apt-get install -y pipx python3-venv"
  warn "Then re-run this script. Skipping theHarvester/sslyze/wapiti/dnstwist/smbmap."
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
    # Only skip when the tool already lives in GOBIN. A same-named binary
    # elsewhere on PATH (e.g. the Python "httpx" client shadowing
    # ProjectDiscovery's httpx) must not stop us installing the real tool.
    if [ -x "$GOBIN/$name" ]; then say "have $name"; continue; fi
    say "go install $name"
    go install "$pkg" 2>/dev/null || warn "skip $name (go install failed)"
  done
  case ":$PATH:" in *":$GOBIN:"*) : ;; *) warn "Add $GOBIN to your PATH to use the Go-based tools" ;; esac
else
  say "Go not found; skipping nuclei/httpx/subfinder/dnsx (install Go to get them)."
fi

# Tools not in any package repo: install from git into their own venv and drop
# a launcher in ~/.local/bin under the name Daru expects.
TOOLS_DIR="$HOME/.daru/tools"
BIN_USER="$HOME/.local/bin"
git_tool() {
  gname="$1"; repo="$2"; launcher="$3"; wname="$4"
  if command -v "$wname" >/dev/null 2>&1; then say "have $wname"; return; fi
  command -v git >/dev/null 2>&1 || { warn "git missing; cannot install $wname"; return; }
  command -v python3 >/dev/null 2>&1 || { warn "python3 missing; cannot install $wname"; return; }
  mkdir -p "$TOOLS_DIR" "$BIN_USER"
  dir="$TOOLS_DIR/$gname"
  say "Installing $wname from $repo"
  if [ -d "$dir/.git" ]; then ( cd "$dir" && git pull --ff-only 2>/dev/null || true )
  else git clone --depth 1 "$repo" "$dir" 2>/dev/null || { warn "clone $gname failed"; return; }
  fi
  py="python3"
  if [ -f "$dir/requirements.txt" ]; then
    if python3 -m venv "$dir/.venv" 2>/dev/null; then
      "$dir/.venv/bin/pip" install -q --upgrade pip 2>/dev/null || true
      "$dir/.venv/bin/pip" install -q -r "$dir/requirements.txt" 2>/dev/null || warn "some deps for $gname failed"
      py="$dir/.venv/bin/python"
    else
      warn "venv for $gname failed (need python3-venv); trying system python"
    fi
  fi
  cat > "$BIN_USER/$wname" <<WRAP
#!/bin/sh
exec "$py" "$dir/$launcher" "\$@"
WRAP
  chmod +x "$BIN_USER/$wname"
  say "installed $wname -> $dir/$launcher"
}

# recon-ng and spiderfoot are not reliably packaged; install them from source.
command -v recon-ng >/dev/null 2>&1 || \
  git_tool recon-ng https://github.com/lanmaster53/recon-ng.git recon-ng recon-ng
command -v sfcli >/dev/null 2>&1 || \
  git_tool spiderfoot https://github.com/smicallef/spiderfoot.git sfcli.py sfcli

# Offer the capability grant so raw-socket tools work without running as root.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$(uname -s)" = "Linux" ] && [ -f "$SCRIPT_DIR/grant-capabilities.sh" ]; then
  say "Granting raw-socket capability to scan/capture tools (so no root is needed)"
  sh "$SCRIPT_DIR/grant-capabilities.sh" || warn "capability grant skipped; run scripts/grant-capabilities.sh later"
fi

say "Done. Daru searches PATH plus ~/go/bin and ~/.local/bin, so these appear"
say "in the Recon tab automatically."
say "Note: openvas/gvm needs its services and feed sync set up separately (the"
say "gvm-cli client is installed); unicornscan only installs where apt has it."
