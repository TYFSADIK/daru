#!/bin/sh
# Run Daru, and therefore every scan and capture tool it drives, as root.
#
# Use this ONLY on a local box that is not reachable by anyone else. Running as
# root means anyone who can reach this Daru can run root commands through it, so
# keep it bound to localhost (DARU_LISTEN=127.0.0.1:8088) or your trusted LAN.
# For a shared or exposed instance, use scripts/grant-capabilities.sh instead
# and run Daru as a normal user.
set -eu

ENV_FILE="${DARU_ENV:-$HOME/.daru/daru.env}"
if [ -f "$ENV_FILE" ]; then
  set -a; . "$ENV_FILE"; set +a
fi

BIN=$(command -v daru 2>/dev/null || echo "$HOME/.local/bin/daru")
[ -x "$BIN" ] || { echo "daru binary not found; run ./install.sh first" >&2; exit 1; }

# -E keeps the DARU_* and PATH values; SUDO_USER is set so Daru still finds
# tools you installed in your own ~/go/bin and ~/.local/bin.
echo "Starting Daru as root (local use). Listen: ${DARU_LISTEN:-:8088}"
exec sudo -E "$BIN" serve
