#!/usr/bin/env bash
# Daru backup: backs up the whole Daru ClickHouse database to a file.
#
# Usage:
#   ./scripts/backup.sh [backup-file]
#   DARU_BACKUP_DIR=/var/backups/daru ./scripts/backup.sh
#   BACKUP_FILE=/var/backups/daru/daru-2026-11-08.zip ./scripts/backup.sh
#
# Env vars (loaded from ~/.daru/daru.env when present):
#   DARU_CLICKHOUSE_URL      default http://127.0.0.1:8123
#   DARU_CLICKHOUSE_DB       default daru
#   DARU_CLICKHOUSE_USER     default daru
#   DARU_CLICKHOUSE_PASSWORD required
#   DARU_BACKUP_DIR          default ~/.daru/backups
#   DARU_CLICKHOUSE_CONTAINER  container name when using Docker, default clickhouse
#
# The backup file is a ClickHouse BACKUP archive. It contains users, sessions,
# ingest tokens, saved searches, dashboards, alerts, notable events, scans,
# findings, and assets. The events table is included too, so large installs
# produce large files. Test restores regularly: see scripts/restore.sh.
#
# Cron example (daily at 03:00, keep 7 days):
#   0 3 * * * /path/to/daru/scripts/backup.sh >> /var/log/daru-backup.log 2>&1
#   0 4 * * * find "$HOME/.daru/backups" -name 'daru-*.zip' -mtime +7 -delete
set -euo pipefail

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
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
OUT_DIR="${DARU_BACKUP_DIR:-$HOME/.daru/backups}"
FILE="${BACKUP_FILE:-${1:-}}"
if [ -z "$FILE" ]; then
  FILE="$OUT_DIR/daru-$(date +%Y-%m-%d-%H%M%S).zip"
fi
mkdir -p "$(dirname "$FILE")"
[ -n "$PASS" ] || { echo "backup: DARU_CLICKHOUSE_PASSWORD is not set" >&2; exit 1; }

# ClickHouse BACKUP writes inside the server container, so when Docker is in
# use the archive is created in the container and then copied out.
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${DARU_CLICKHOUSE_CONTAINER:-clickhouse}"; then
  CONTAINER="${DARU_CLICKHOUSE_CONTAINER:-clickhouse}"
  REMOTE="/tmp/daru-backup-$(date +%Y%m%d%H%M%S).zip"
  docker exec "$CONTAINER" clickhouse-client --user "$USER" --password "$PASS" \
    --query "BACKUP DATABASE $DB TO File('$REMOTE')"
  docker cp "$CONTAINER:$REMOTE" "$FILE"
  docker exec "$CONTAINER" rm -f "$REMOTE"
else
  command -v clickhouse-client >/dev/null 2>&1 || { echo "backup: clickhouse-client not found and no running ClickHouse container" >&2; exit 1; }
  # Strip the scheme and port for the local client.
  HOST="$(echo "$URL" | sed -E 's#^https?://##; s#/.*##; s#:.*##')"
  PORT="$(echo "$URL" | sed -E 's#^https?://##; s#/.*##' | grep -o ':[0-9]*' | tr -d ':' || true)"
  clickhouse-client --host "${HOST:-127.0.0.1}" --port "${PORT:-8123}" \
    --user "$USER" --password "$PASS" \
    --query "BACKUP DATABASE $DB TO File('$FILE')"
fi

test -s "$FILE" || { echo "backup: backup file is missing or empty: $FILE" >&2; exit 1; }
echo "backup: wrote $FILE ($(du -h "$FILE" | cut -f1))"
echo "backup: verify it with: ./scripts/restore.sh --dry-run $FILE"
