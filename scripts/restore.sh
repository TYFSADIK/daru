#!/usr/bin/env bash
# Daru restore: restores a backup made by scripts/backup.sh.
#
# Usage:
#   ./scripts/restore.sh <backup-file>
#   ./scripts/restore.sh --dry-run <backup-file>   (checks the archive and lists its tables)
#   BACKUP_FILE=/path/daru-2026-11-08.tar.gz ./scripts/restore.sh
#
# WARNING: restore replaces every table that is in the backup. Back up first
# if the current data matters, and stop Daru while restoring, or rows
# written during the restore are lost.
#
# Env vars: same as scripts/backup.sh. Restoring drops and creates tables,
# so it needs DARU_CLICKHOUSE_ADMIN_USER / DARU_CLICKHOUSE_ADMIN_PASSWORD
# (or a DARU_CLICKHOUSE_USER with schema rights).
# Needs curl 7.87 or newer (for --url-query) and tar.
# Test a restore on a scratch ClickHouse before relying on it in production.
set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; shift; fi
FILE="${BACKUP_FILE:-${1:-}}"
[ -n "$FILE" ] || { echo "restore: usage: ./scripts/restore.sh <backup-file>" >&2; exit 1; }
[ -s "$FILE" ] || { echo "restore: backup file not found or empty: $FILE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
tar -C "$WORK" -xzf "$FILE" || { echo "restore: not a readable backup archive: $FILE" >&2; exit 1; }
B="$WORK/daru-backup"
[ -f "$B/MANIFEST" ] && grep -q '^format=daru-native-v1$' "$B/MANIFEST" \
  || { echo "restore: $FILE is not a Daru backup (missing or unknown MANIFEST)" >&2; exit 1; }
for f in "$B"/*.sql; do
  t="$(basename "$f" .sql)"
  case "$t" in *[!A-Za-z0-9_]*) echo "restore: unexpected table name '$t' in archive" >&2; exit 1 ;; esac
  [ -f "$B/$t.native" ] || { echo "restore: $t has a schema but no data file" >&2; exit 1; }
done

if [ "$DRY_RUN" = 1 ]; then
  echo "restore: dry run ok, $FILE is a valid Daru backup:"
  grep -v '^format=' "$B/MANIFEST" | sed 's/^/restore:   /'
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
case "$DB" in *[!A-Za-z0-9_]*|"") echo "restore: invalid database name '$DB'" >&2; exit 1 ;; esac

# ch QUERY [DATAFILE]: run a statement, with DATAFILE as the INSERT body.
# The statement travels URL-encoded in the query parameter. On a ClickHouse
# error the message is shown and the restore stops.
ch() {
  local data=("--data-binary" "") out
  [ -n "${2:-}" ] && data=("--data-binary" "@$2")
  if ! out="$(curl -sS --fail-with-body "$URL/?database=$DB" --url-query "query=$1" \
      -H "X-ClickHouse-User: $CHUSER" -H "X-ClickHouse-Key: $CHPASS" "${data[@]}" 2>&1)"; then
    echo "restore: ClickHouse refused: ${out:0:400}" >&2
    case "$out" in *ACCESS_DENIED*|*"Not enough privileges"*)
      echo "restore: restoring needs schema rights; set DARU_CLICKHOUSE_ADMIN_USER and DARU_CLICKHOUSE_ADMIN_PASSWORD" >&2 ;;
    esac
    exit 1
  fi
  printf '%s' "$out"
}

echo "restore: this replaces every table in the backup inside database '$DB' on $URL."
if [ "${DARU_RESTORE_YES:-}" != "1" ]; then
  echo "restore: press Ctrl-C within 5 seconds to abort."
  sleep 5
fi

DB_TARGET="$DB"; DB=default
ch "CREATE DATABASE IF NOT EXISTS \`$DB_TARGET\`" >/dev/null
DB="$DB_TARGET"
for f in "$B"/*.sql; do
  t="$(basename "$f" .sql)"
  ch "DROP TABLE IF EXISTS \`$t\` SYNC" >/dev/null
  ch "$(cat "$f")" >/dev/null
  ch "INSERT INTO \`$t\` FORMAT Native" "$B/$t.native" >/dev/null
  rows="$(ch "SELECT count() FROM \`$t\`")"
  echo "restore:   $t: $rows rows"
done
echo "restore: restored $DB from $FILE"
echo "restore: start Daru and check Search and Admin to confirm the data is back."
