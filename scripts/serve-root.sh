#!/bin/sh
# Run Daru, and therefore every scan and capture tool it drives, as root.
#
# Use this ONLY on a local box that is not reachable by anyone else. Running as
# root means anyone who can reach this Daru can run root commands through it, so
# it is bound to localhost by default (DARU_LISTEN=127.0.0.1:8088).
# For a shared or exposed instance, use scripts/grant-capabilities.sh instead
# and run Daru as a normal user.
#
# This script never auto-updates tools as root. Update tools separately, as a
# normal user, before starting Daru.
set -eu

# Default to loopback only. An explicit DARU_LISTEN is honoured, but a
# wildcard listen is refused unless DARU_ALLOW_PUBLIC_LISTEN=1 is set.
DARU_LISTEN="${DARU_LISTEN:-127.0.0.1:8088}"
export DARU_LISTEN
case "$DARU_LISTEN" in
  :*|0.0.0.0:*|\[::\]:*)
    if [ "${DARU_ALLOW_PUBLIC_LISTEN:-0}" != "1" ]; then
      echo "Refusing to serve Daru as root on a public interface ($DARU_LISTEN)." >&2
      echo "Set DARU_LISTEN=127.0.0.1:8088, or DARU_ALLOW_PUBLIC_LISTEN=1 to override." >&2
      exit 1
    fi
    ;;
esac

# Source the env file only when it is safe to trust as root: it must be owned
# by root and not writable by group or others. A user-writable env file is
# never sourced as root, since it could set PATH or DARU_* values.
ENV_FILE="${DARU_ENV:-$HOME/.daru/daru.env}"
if [ -f "$ENV_FILE" ]; then
  owner=$(stat -c '%u' "$ENV_FILE" 2>/dev/null || stat -f '%u' "$ENV_FILE" 2>/dev/null || echo "")
  perms=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null || echo "")
  if [ "$owner" = "0" ]; then
    case "$perms" in
      *2|*3|*6|*7) echo "Refusing to source $ENV_FILE as root: it is group or world writable (perms $perms)." >&2; exit 1 ;;
    esac
    set -a; . "$ENV_FILE"; set +a
  else
    echo "Not sourcing $ENV_FILE as root: it is owned by uid $owner, not root. Fix ownership or run Daru as that user." >&2
    exit 1
  fi
fi

BIN=$(command -v daru 2>/dev/null || echo "$HOME/.local/bin/daru")
[ -x "$BIN" ] || { echo "daru binary not found; run ./install.sh first" >&2; exit 1; }

# -E keeps the DARU_* and PATH values. SUDO_USER is deliberately not passed
# through: Daru no longer trusts tools from the invoking user's home when it
# runs as root.
echo "Starting Daru as root (local use only). Listen: $DARU_LISTEN"
exec sudo -E "$BIN" serve
