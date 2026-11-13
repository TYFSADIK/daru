#!/usr/bin/env bash
# Daru installer for Linux, macOS, Raspberry Pi, and Android (Termux).
#
# It installs only what Daru needs to run: a Go toolchain (if missing), the
# Daru binary, and ClickHouse (via Docker when available). Optional security
# scanners are NOT installed here; run scripts/install-recon-tools.sh for those.
#
# Go downloads are verified against the official SHA-256 checksums published
# at https://go.dev/dl/ for Go 1.27.3 before anything is extracted. A
# checksum mismatch fails the install.
#
# Usage:
#   ./install.sh                 build and set up everything
#   ./install.sh --with-tools    also install the security scanners (nmap, etc.)
#   ./install.sh --no-clickhouse skip the ClickHouse step
#   ./install.sh --help
set -euo pipefail

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX_BIN="${DARU_BIN_DIR:-}"
WITH_CLICKHOUSE=1
WITH_TOOLS=0
GO_MIN_MAJOR=1
GO_MIN_MINOR=27

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --no-clickhouse) WITH_CLICKHOUSE=0 ;;
    --with-tools) WITH_TOOLS=1 ;;
    -h|--help)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown option: $arg (see --help)" ;;
  esac
done

# --- detect platform ---------------------------------------------------------
detect_platform() {
  OS=$(uname -s 2>/dev/null || echo unknown)
  ARCH=$(uname -m 2>/dev/null || echo unknown)
  IS_TERMUX=0
  if [ -n "${PREFIX:-}" ] && printf '%s' "$PREFIX" | grep -q com.termux; then
    IS_TERMUX=1
  fi
  case "$OS" in
    Linux)  GOOS=linux ;;
    Darwin) GOOS=darwin ;;
    *) warn "unrecognized OS '$OS'; assuming linux" ; GOOS=linux ;;
  esac
  case "$ARCH" in
    x86_64|amd64) GOARCH=amd64; GOARCH_DL=amd64 ;;
    aarch64|arm64) GOARCH=arm64; GOARCH_DL=arm64 ;;
    armv7l|armv6l) GOARCH=arm; GOARCH_DL=armv6l ;;
    i386|i686) GOARCH=386; GOARCH_DL=386 ;;
    *) warn "unrecognized arch '$ARCH'; assuming amd64" ; GOARCH=amd64; GOARCH_DL=amd64 ;;
  esac
  if [ "$IS_TERMUX" = 1 ]; then
    PLATFORM="Android (Termux)"
  elif [ "$GOOS" = linux ] && [ "$GOARCH" = arm64 ] && [ -f /proc/device-tree/model ] && grep -qi raspberry /proc/device-tree/model 2>/dev/null; then
    PLATFORM="Raspberry Pi"
  else
    PLATFORM="$OS/$GOARCH"
  fi
}

pick_bin_dir() {
  if [ -n "$PREFIX_BIN" ]; then echo "$PREFIX_BIN"; return; fi
  if [ "$IS_TERMUX" = 1 ] && [ -n "${PREFIX:-}" ]; then echo "$PREFIX/bin"; return; fi
  if [ -w /usr/local/bin ] 2>/dev/null; then echo /usr/local/bin; return; fi
  echo "$HOME/.local/bin"
}

# --- Go toolchain ------------------------------------------------------------
# find_go echoes a usable go path, searching PATH and common install dirs
# (a non-login shell may not have Go on PATH even when it is installed).
find_go() {
  if command -v go >/dev/null 2>&1; then command -v go; return; fi
  for p in /usr/local/go/bin/go /usr/lib/go/bin/go /snap/bin/go \
           "$HOME/.daru/go/bin/go" "$HOME/go/bin/go" /opt/go/bin/go; do
    [ -x "$p" ] && { echo "$p"; return; }
  done
}

have_recent_go() {
  gp=$(find_go); [ -n "$gp" ] || return 1
  v=$("$gp" version 2>/dev/null | awk '{print $3}' | sed 's/go//')
  maj=$(echo "$v" | cut -d. -f1); min=$(echo "$v" | cut -d. -f2)
  if [ "${maj:-0}" -gt "$GO_MIN_MAJOR" ] || { [ "${maj:-0}" -eq "$GO_MIN_MAJOR" ] && [ "${min:-0}" -ge "$GO_MIN_MINOR" ]; }; then
    GO="$gp"; return 0
  fi
  return 1
}

# Official SHA-256 checksums for Go 1.27.3, from https://go.dev/dl/.
# If Go is bumped, update GOVER and every checksum here, plus go.mod,
# Dockerfile, CI, install.ps1, and the README badge.
go_sha256() {
  case "$1" in
    linux-amd64) echo 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
    linux-arm64) echo a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
    linux-armv6l) echo d6f4e11dd7157030d7ac11c51c8f73201a2db932d593c3106b1da11cc32bfdf8 ;;
    linux-386) echo cfc243057c03dd131413b91269d16b5061f87f312059c1ed78681cbb95d6afbf ;;
    darwin-amd64) echo b6f8e931e4ab497fcde6da8ae4499a58f9d258e55c8a80824a516eae5950a750 ;;
    darwin-arm64) echo dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2 ;;
    *) return 1 ;;
  esac
}

verify_sha256() {
  # verify_sha256 <file> <expected-sha256>: fail closed on any mismatch.
  local file="$1" want="$2" got=""
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    die "need sha256sum or shasum to verify the Go download"
  fi
  [ "$got" = "$want" ] || die "Go download checksum mismatch: got $got, expected $want. Aborting."
}

install_go() {
  say "Go $GO_MIN_MAJOR.$GO_MIN_MINOR+ not found; installing it"
  if [ "$IS_TERMUX" = 1 ]; then
    pkg install -y golang && return 0
  fi
  if command -v brew >/dev/null 2>&1; then brew install go && return 0; fi
  if command -v apt-get >/dev/null 2>&1; then
    warn "Distro Go may be old; downloading the official toolchain instead"
  fi
  GOVER=1.27.3
  url="https://go.dev/dl/go${GOVER}.${GOOS}-${GOARCH_DL}.tar.gz"
  want=$(go_sha256 "${GOOS}-${GOARCH_DL}") || die "no pinned SHA-256 for Go on ${GOOS}-${GOARCH_DL}"
  dest="$HOME/.daru/go"
  say "Downloading $url"
  mkdir -p "$HOME/.daru"
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$url" -o "$tmp"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$tmp" "$url"
  else die "need curl or wget to download Go"; fi
  verify_sha256 "$tmp" "$want"
  say "Go download checksum verified"
  rm -rf "$dest"; mkdir -p "$dest"
  tar -C "$dest" --strip-components=1 -xzf "$tmp"
  rm -f "$tmp"
  trap - EXIT
  GO="$dest/bin/go"
}

# --- ClickHouse --------------------------------------------------------------
# Poll the HTTP interface until it answers, so a port or startup problem is
# reported here rather than as a silent wait loop when Daru starts.
wait_for_clickhouse() {
  ping_cmd=""
  if command -v curl >/dev/null 2>&1; then
    ping_cmd='curl -fsS -m 2 http://127.0.0.1:8123/ping'
  elif command -v wget >/dev/null 2>&1; then
    ping_cmd='wget -q -T 2 -O - http://127.0.0.1:8123/ping'
  fi
  [ -z "$ping_cmd" ] && return 0
  i=0
  while [ "$i" -lt 30 ]; do
    if eval "$ping_cmd" >/dev/null 2>&1; then
      say "ClickHouse is reachable at 127.0.0.1:8123"
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  die "ClickHouse did not become reachable at 127.0.0.1:8123. Check 'docker compose -f deploy/docker-compose.yml logs clickhouse' and that port 8123 is published."
}

setup_clickhouse() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    say "Starting ClickHouse with Docker"
    if ( cd "$REPO_DIR/deploy" && \
         CLICKHOUSE_PASSWORD="$CH_PASS" docker compose up -d clickhouse ); then
      wait_for_clickhouse
    else
      die "Could not start ClickHouse via Docker; set DARU_CLICKHOUSE_URL to an existing instance"
    fi
    return
  fi
  if [ "$IS_TERMUX" = 1 ]; then
    warn "ClickHouse does not run on Android. Point Daru at a ClickHouse on another machine:"
    warn "  export DARU_CLICKHOUSE_URL=http://<host>:8123"
    return
  fi
  warn "Docker not found. Install ClickHouse natively with its official installer (review it first, do not pipe it straight to sh blindly):"
  warn "  curl https://clickhouse.com/ | sh"
  warn "Then start it, or set DARU_CLICKHOUSE_URL to an existing instance."
}

# --- run ---------------------------------------------------------------------
main() {
  detect_platform
  say "Platform: $PLATFORM  (GOOS=$GOOS GOARCH=$GOARCH)"

  GO="go"
  if have_recent_go; then
    say "Using $("$GO" version)"
  else
    install_go
    say "Using $("$GO" version)"
  fi

  say "Building Daru"
  ( cd "$REPO_DIR" && CGO_ENABLED=0 "$GO" build -trimpath -ldflags "-s -w" -o daru ./cmd/daru )

  BIN_DIR=$(pick_bin_dir)
  mkdir -p "$BIN_DIR"
  # Install atomically: copy to a temp name, then rename over the target. A
  # plain cp onto a running binary fails with "Text file busy"; rename does
  # not, because the running process keeps the old inode.
  tmpbin="$BIN_DIR/.daru.new.$$"
  cp "$REPO_DIR/daru" "$tmpbin"
  chmod +x "$tmpbin"
  mv -f "$tmpbin" "$BIN_DIR/daru"
  say "Installed daru to $BIN_DIR/daru"
  case ":$PATH:" in *":$BIN_DIR:"*) : ;; *) warn "Add $BIN_DIR to your PATH" ;; esac

  # Generate credentials on first install.
  ENV_FILE="$HOME/.daru/daru.env"
  if [ ! -f "$ENV_FILE" ]; then
    mkdir -p "$HOME/.daru"
    CH_PASS=$(rand_secret); ADMIN_PASS=$(rand_secret)
    cat > "$ENV_FILE" <<EOF
DARU_CLICKHOUSE_URL=http://127.0.0.1:8123
DARU_CLICKHOUSE_DB=daru
DARU_CLICKHOUSE_USER=daru
DARU_CLICKHOUSE_PASSWORD=$CH_PASS
DARU_ADMIN_USER=admin
DARU_ADMIN_PASSWORD=$ADMIN_PASS
DARU_LISTEN=:8088
EOF
    chmod 600 "$ENV_FILE"
    say "Wrote config and generated credentials to $ENV_FILE"
  else
    say "Using existing config at $ENV_FILE"
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    CH_PASS="${DARU_CLICKHOUSE_PASSWORD:-}"; ADMIN_PASS="${DARU_ADMIN_PASSWORD:-}"
    # Verify the stored credentials instead of silently reusing a broken or
    # default one from an earlier install.
    [ -n "$CH_PASS" ] || die "stored ClickHouse password is empty in $ENV_FILE; delete the file and re-run to generate new credentials"
    [ -n "$ADMIN_PASS" ] || die "stored admin password is empty in $ENV_FILE; delete the file and re-run to generate new credentials"
    [ "$CH_PASS" != "change-me-clickhouse" ] || die "stored ClickHouse password is still the old default in $ENV_FILE; rotate it before running Daru"
    [ "$ADMIN_PASS" != "change-me-admin" ] || die "stored admin password is still the old default in $ENV_FILE; rotate it before running Daru"
  fi

  if [ "$WITH_CLICKHOUSE" = 1 ]; then setup_clickhouse; fi

  if [ "$WITH_TOOLS" = 1 ]; then
    say "Installing security scanners (--with-tools)"
    # Make sure `go` is on PATH for the recon script's go-install step, even
    # when we just downloaded the toolchain to $HOME/.daru/go/bin.
    GO_BIN_DIR=$(dirname "$GO")
    RECON_ASSUME_YES=1 PATH="$GO_BIN_DIR:$PATH" bash "$REPO_DIR/scripts/install-recon-tools.sh" || \
      warn "Some scanners could not be installed; you can re-run scripts/install-recon-tools.sh later"
  fi

  tools_line="  Optional security scanners (nmap, masscan, etc.), opt-in:
              sh \"$REPO_DIR/scripts/install-recon-tools.sh\"
              or re-run this installer with --with-tools"
  [ "$WITH_TOOLS" = 1 ] && tools_line="  Security scanners were installed (--with-tools). They appear in the Recon tab."

  cat <<EOF

$(printf '\033[32mDaru is installed.\033[0m')

  Start it:   set -a; . "$ENV_FILE"; set +a; daru serve
  Then open:  http://localhost:8088
  Sign in:    admin / $ADMIN_PASS

$tools_line

EOF
}

rand_secret() {
  # Cryptographic randomness only. Fail instead of falling back to a weak
  # time-based secret.
  command -v openssl >/dev/null 2>&1 || die "openssl is required to generate credentials"
  openssl rand -hex 16
}

main "$@"
