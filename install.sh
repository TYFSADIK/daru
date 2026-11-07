#!/bin/sh
# Daru installer for Linux, macOS, Raspberry Pi, and Android (Termux).
#
# It installs only what Daru needs to run: a Go toolchain (if missing), the
# Daru binary, and ClickHouse (via Docker when available). Optional security
# scanners are NOT installed here; run scripts/install-recon-tools.sh for those.
#
# Usage:
#   ./install.sh                 build and set up everything
#   ./install.sh --with-tools    also install the security scanners (nmap, etc.)
#   ./install.sh --no-clickhouse skip the ClickHouse step
#   ./install.sh --help
set -eu

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX_BIN="${DARU_BIN_DIR:-}"
WITH_CLICKHOUSE=1
WITH_TOOLS=0
GO_MIN_MAJOR=1
GO_MIN_MINOR=23

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --no-clickhouse) WITH_CLICKHOUSE=0 ;;
    --with-tools) WITH_TOOLS=1 ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) warn "ignoring unknown option: $arg" ;;
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
    x86_64|amd64) GOARCH=amd64 ;;
    aarch64|arm64) GOARCH=arm64 ;;
    armv7l|armv6l) GOARCH=arm ;;
    *) warn "unrecognized arch '$ARCH'; assuming amd64" ; GOARCH=amd64 ;;
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
have_recent_go() {
  command -v go >/dev/null 2>&1 || return 1
  v=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
  maj=$(echo "$v" | cut -d. -f1); min=$(echo "$v" | cut -d. -f2)
  [ "${maj:-0}" -gt "$GO_MIN_MAJOR" ] && return 0
  [ "${maj:-0}" -eq "$GO_MIN_MAJOR" ] && [ "${min:-0}" -ge "$GO_MIN_MINOR" ]
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
  GOVER=1.25.3
  url="https://go.dev/dl/go${GOVER}.${GOOS}-${GOARCH}.tar.gz"
  dest="$HOME/.daru/go"
  say "Downloading $url"
  mkdir -p "$HOME/.daru"
  tmp=$(mktemp)
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$url" -o "$tmp"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$tmp" "$url"
  else die "need curl or wget to download Go"; fi
  rm -rf "$dest"; mkdir -p "$dest"
  tar -C "$dest" --strip-components=1 -xzf "$tmp"
  rm -f "$tmp"
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
  warn "ClickHouse did not become reachable at 127.0.0.1:8123."
  warn "Check 'docker compose -f deploy/docker-compose.yml logs clickhouse' and that port 8123 is published."
  return 1
}

setup_clickhouse() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    say "Starting ClickHouse with Docker"
    if ( cd "$REPO_DIR/deploy" && \
         CLICKHOUSE_PASSWORD="$CH_PASS" docker compose up -d clickhouse ); then
      wait_for_clickhouse
    else
      warn "Could not start ClickHouse via Docker; set DARU_CLICKHOUSE_URL to an existing instance"
    fi
    return
  fi
  if [ "$IS_TERMUX" = 1 ]; then
    warn "ClickHouse does not run on Android. Point Daru at a ClickHouse on another machine:"
    warn "  export DARU_CLICKHOUSE_URL=http://<host>:8123"
    return
  fi
  warn "Docker not found. Install ClickHouse natively with its official script:"
  warn "  curl https://clickhouse.com/ | sh   (review it first)"
  warn "Then start it, or set DARU_CLICKHOUSE_URL to an existing instance."
}

# --- run ---------------------------------------------------------------------
main() {
  detect_platform
  say "Platform: $PLATFORM  (GOOS=$GOOS GOARCH=$GOARCH)"

  GO="go"
  if have_recent_go; then
    say "Using $(go version)"
  else
    install_go
    say "Using $($GO version)"
  fi

  say "Building Daru"
  ( cd "$REPO_DIR" && CGO_ENABLED=0 "$GO" build -trimpath -ldflags "-s -w" -o daru ./cmd/daru )

  BIN_DIR=$(pick_bin_dir)
  mkdir -p "$BIN_DIR"
  cp "$REPO_DIR/daru" "$BIN_DIR/daru"
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
    CH_PASS="$DARU_CLICKHOUSE_PASSWORD"; ADMIN_PASS="$DARU_ADMIN_PASSWORD"
  fi

  if [ "$WITH_CLICKHOUSE" = 1 ]; then setup_clickhouse; fi

  if [ "$WITH_TOOLS" = 1 ]; then
    say "Installing security scanners (--with-tools)"
    RECON_ASSUME_YES=1 sh "$REPO_DIR/scripts/install-recon-tools.sh" || \
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
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 16; return; fi
  head -c 16 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || date +%s%N | sha1sum 2>/dev/null | cut -c1-32
}

main
