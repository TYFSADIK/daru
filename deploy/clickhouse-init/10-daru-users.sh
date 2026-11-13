#!/bin/bash
# Creates the least privilege Daru app user on the first start of the
# ClickHouse container (scripts in /docker-entrypoint-initdb.d run only when
# the data volume is empty). The compose admin user (CLICKHOUSE_USER) keeps
# schema rights and is passed to Daru as DARU_CLICKHOUSE_ADMIN_USER.
#
# The password is passed as a SHA-256 hash, so no user supplied text is ever
# spliced into SQL.
set -euo pipefail

: "${CLICKHOUSE_USER:?}"
: "${CLICKHOUSE_PASSWORD:?}"
: "${CLICKHOUSE_DB:=daru}"
: "${DARU_APP_USER:=daru_app}"
: "${DARU_APP_PASSWORD:?DARU_APP_PASSWORD must be set for the ClickHouse container}"

case "$DARU_APP_USER" in
  *[!A-Za-z0-9_]*|"") echo "DARU_APP_USER must be letters, digits and underscore" >&2; exit 1 ;;
esac
case "$CLICKHOUSE_DB" in
  *[!A-Za-z0-9_]*|"") echo "CLICKHOUSE_DB must be letters, digits and underscore" >&2; exit 1 ;;
esac

hash=$(printf '%s' "$DARU_APP_PASSWORD" | sha256sum | awk '{print $1}')

clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery <<SQL
CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DB};
CREATE USER IF NOT EXISTS ${DARU_APP_USER} IDENTIFIED WITH sha256_hash BY '${hash}';
GRANT SELECT, INSERT, ALTER DELETE, ALTER UPDATE ON ${CLICKHOUSE_DB}.* TO ${DARU_APP_USER};
SQL
echo "created least privilege ClickHouse user ${DARU_APP_USER}"
