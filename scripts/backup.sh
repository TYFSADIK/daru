#!/usr/bin/env bash
# Daru backup: saves the whole Daru ClickHouse database to one file.
#
# Usage:
#   ./scripts/backup.sh [backup-file]
#   DARU_BACKUP_DIR=/var/backups/daru ./scripts/backup.sh
#   BACKUP_FILE=/var/backups/daru/daru-2026-11-08.tar.gz ./scripts/backup.sh
#
# Env vars (loaded from ~/.daru/daru.env when present):
#   DARU_CLICKHOUSE_URL        default http://127.0.0.1:8123
#   DARU_CLICKHOUSE_DB         default daru
#   DARU_CLICKHOUSE_ADMIN_USER / DARU_CLICKHOUSE_ADMIN_PASSWORD  used when set
#   DARU_CLICKHOUSE_USER / DARU_CLICKHOUSE_PASSWORD             otherwise
#   DARU_BACKUP_DIR            default ~/.daru/backups
#
# It talks to ClickHouse over the same HTTP interface Daru uses, so it needs
# only curl and tar: no clickhouse-client, no server side backup path
# configuration, and it works against a ClickHouse in Docker or on another
# host. The file is a tar.gz with each table's CREATE statement and its rows
# in ClickHouse Native format. It contains password hashes, session hashes,
# and ingest token hashes, so it is written readable by its owner only.
# Needs curl and tar. Test restores regularly: see scripts/restore.sh.
#
# Cron example (daily at 03:00, keep 7 days):
#   0 3 * * * /path/to/daru/scripts/backup.sh >> /var/log/daru-backup.log 2>&1
#   0 4 * * * find "$HOME/.daru/backups" -name 'daru-*.tar.gz' -mtime +7 -delete
set -euo pipefail

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
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
URL="${URL%/}"
if [ -n "${DARU_CLICKHOUSE_ADMIN_USER:-}" ]; then
  CHUSER="$DARU_CLICKHOUSE_ADMIN_USER"; CHPASS="${DARU_CLICKHOUSE_ADMIN_PASSWORD:-}"
else
  CHUSER="${DARU_CLICKHOUSE_USER:-default}"; CHPASS="${DARU_CLICKHOUSE_PASSWORD:-}"
fi
OUT_DIR="${DARU_BACKUP_DIR:-$HOME/.daru/backups}"
FILE="${BACKUP_FILE:-${1:-}}"
[ -n "$FILE" ] || FILE="$OUT_DIR/daru-$(date +%Y-%m-%d-%H%M%S).tar.gz"

case "$DB" in *[!A-Za-z0-9_]*|"") echo "backup: invalid database name '$DB'" >&2; exit 1 ;; esac
command -v curl >/dev/null 2>&1 || { echo "backup: curl is required" >&2; exit 1; }

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ch QUERY [OUTFILE]: run a query, fail on any ClickHouse error.
ch() {
  local out="${2:-$WORK/.last}"
  if ! curl -sS --fail-with-body "$URL/?database=$DB" \
      -H "X-ClickHouse-User: $CHUSER" -H "X-ClickHouse-Key: $CHPASS" \
      --data-binary "$1" -o "$out" 2>"$WORK/.err"; then
    echo "backup: ClickHouse refused: $(head -c 400 "$out" 2>/dev/null; cat "$WORK/.err")" >&2
    exit 1
  fi
  [ -n "${2:-}" ] || cat "$out"
}

TABLES="$(ch "SELECT name FROM system.tables WHERE database = '$DB' AND engine NOT LIKE '%View' ORDER BY name FORMAT TSV")"
[ -n "$TABLES" ] || { echo "backup: database '$DB' has no tables" >&2; exit 1; }

mkdir -p "$WORK/daru-backup"
printf 'database=%s\ncreated=%s\nformat=daru-native-v1\n' "$DB" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$WORK/daru-backup/MANIFEST"
for t in $TABLES; do
  case "$t" in *[!A-Za-z0-9_]*) echo "backup: skipping unexpected table name '$t'" >&2; continue ;; esac
  ch "SHOW CREATE TABLE \`$t\` FORMAT TSVRaw" "$WORK/daru-backup/$t.sql"
  ch "SELECT * FROM \`$t\` FORMAT Native" "$WORK/daru-backup/$t.native"
  rows="$(ch "SELECT count() FROM \`$t\` FORMAT TSV")"
  printf 'table=%s rows=%s\n' "$t" "$rows" >> "$WORK/daru-backup/MANIFEST"
done

mkdir -p "$(dirname "$FILE")"
tar -C "$WORK" -czf "$FILE" daru-backup
chmod 600 "$FILE"
test -s "$FILE" || { echo "backup: backup file is missing or empty: $FILE" >&2; exit 1; }
echo "backup: wrote $FILE ($(du -h "$FILE" | cut -f1))"
grep '^table=' "$WORK/daru-backup/MANIFEST" | sed 's/^/backup:   /'
echo "backup: verify it with: ./scripts/restore.sh --dry-run $FILE"
