#!/usr/bin/env bash
# Daru restore: restores a backup made by scripts/backup.sh.
#
# Usage:
#   ./scripts/restore.sh <backup-file>
#   ./scripts/restore.sh --dry-run <backup-file>   (checks the file exists and is a zip)
#   BACKUP_FILE=/path/daru-2026-11-08.zip ./scripts/restore.sh
#
# WARNING: restore replaces the current Daru database. Back up first if the
# current data matters. The server should be stopped while restoring, or at
# least not ingesting, or rows written during the restore can be lost.
#
# Env vars: same as scripts/backup.sh (DARU_CLICKHOUSE_URL, DARU_CLICKHOUSE_DB,
# DARU_CLICKHOUSE_USER, DARU_CLICKHOUSE_PASSWORD, DARU_CLICKHOUSE_CONTAINER).
# Test a restore on a scratch ClickHouse before relying on it in production.
set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; shift; fi

FILE="${BACKUP_FILE:-${1:-}}"
[ -n "$FILE" ] || { echo "restore: usage: ./scripts/restore.sh <backup-file>" >&2; exit 1; }
[ -f "$FILE" ] || { echo "restore: backup file not found: $FILE" >&2; exit 1; }
[ -s "$FILE" ] || { echo "restore: backup file is empty: $FILE" >&2; exit 1; }
if [ "$DRY_RUN" = 1 ]; then
  if command -v unzip >/dev/null 2>&1; then unzip -t -q "$FILE" || { echo "restore: backup file failed zip test" >&2; exit 1; }; fi
  echo "restore: dry run ok, $FILE exists and is non-empty"
  exit 0
fi

if [ -f "$HOME/.daru/daru.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$HOME/.daru/daru.env"
  set +a
fi

DB="${DARU_CLICKHOUSE_DB:-daru}"
URL="${DARU_CLICKHOUSE_URL:-http://127.0.0.1:8123}"
USER="${DARU_CLICKHOUSE_USER:-daru}"
PASS="${DARU_CLICKHOUSE_PASSWORD:-}"
[ -n "$PASS" ] || { echo "restore: DARU_CLICKHOUSE_PASSWORD is not set" >&2; exit 1; }

echo "restore: this replaces database '$DB'. Press Ctrl-C within 5 seconds to abort."
sleep 5

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${DARU_CLICKHOUSE_CONTAINER:-clickhouse}"; then
  CONTAINER="${DARU_CLICKHOUSE_CONTAINER:-clickhouse}"
  REMOTE="/tmp/daru-restore-$(date +%Y%m%d%H%M%S).zip"
  docker cp "$FILE" "$CONTAINER:$REMOTE"
  docker exec "$CONTAINER" clickhouse-client --user "$USER" --password "$PASS" \
    --query "RESTORE DATABASE $DB FROM File('$REMOTE')"
  docker exec "$CONTAINER" rm -f "$REMOTE"
else
  command -v clickhouse-client >/dev/null 2>&1 || { echo "restore: clickhouse-client not found and no running ClickHouse container" >&2; exit 1; }
  HOST="$(echo "$URL" | sed -E 's#^https?://##; s#/.*##; s#:.*##')"
  PORT="$(echo "$URL" | sed -E 's#^https?://##; s#/.*##' | grep -o ':[0-9]*' | tr -d ':' || true)"
  clickhouse-client --host "${HOST:-127.0.0.1}" --port "${PORT:-8123}" \
    --user "$USER" --password "$PASS" \
    --query "RESTORE DATABASE $DB FROM File('$FILE')"
fi

echo "restore: restored $DB from $FILE"
echo "restore: restart Daru and check Search and Admin to confirm the data is back."
