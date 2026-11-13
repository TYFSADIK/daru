#!/bin/bash
# check-clickhouse-privileges.sh URL ADMIN_USER ADMIN_PASSWORD
#
# Creates a throwaway least privilege user with the same grants as
# deploy/clickhouse-users.sql and checks that it can do what Daru needs
# (insert, select, lightweight delete) and nothing more (no DDL, no writes
# under readonly=2). Used by CI; safe to run against a scratch ClickHouse.
set -euo pipefail

if [ "${1:-}" = "--help" ] || [ $# -ne 3 ]; then
  echo "usage: $0 CLICKHOUSE_URL ADMIN_USER ADMIN_PASSWORD"; exit 0
fi
url=$1 admin=$2 adminpw=$3
db=daru_privcheck user=daru_privcheck_app pw=privcheck-$RANDOM-$RANDOM

as_admin() { curl -sS "$url/" -H "X-ClickHouse-User: $admin" -H "X-ClickHouse-Key: $adminpw" --data-binary "$1"; }
as_app() { curl -sS "$url/?database=$db${2:-}" -H "X-ClickHouse-User: $user" -H "X-ClickHouse-Key: $pw" --data-binary "$1"; }
expect_ok() { local out; out=$(as_app "$1" "${2:-}"); case "$out" in *Exception*) echo "FAIL (should succeed): $1: $out"; exit 1;; esac; }
expect_err() { local out; out=$(as_app "$1" "${3:-}"); case "$out" in *"$2"*) ;; *) echo "FAIL (want $2): $1: $out"; exit 1;; esac; }

cleanup() { as_admin "DROP USER IF EXISTS $user" >/dev/null || true; as_admin "DROP DATABASE IF EXISTS $db" >/dev/null || true; }
trap cleanup EXIT

as_admin "CREATE DATABASE IF NOT EXISTS $db" >/dev/null
as_admin "CREATE USER IF NOT EXISTS $user IDENTIFIED WITH sha256_password BY '$pw'" >/dev/null
as_admin "GRANT SELECT, INSERT, ALTER DELETE, ALTER UPDATE ON $db.* TO $user" >/dev/null
as_admin "REVOKE ALTER DELETE, ALTER UPDATE ON $db.audit_log FROM $user" >/dev/null
as_admin "CREATE TABLE $db.audit_log (x UInt8) ENGINE = MergeTree ORDER BY x" >/dev/null
as_admin "CREATE TABLE $db.t (x UInt8) ENGINE = MergeTree ORDER BY x" >/dev/null

expect_ok  "INSERT INTO t VALUES (1), (2)"
expect_ok  "SELECT count() FROM t"
expect_ok  "DELETE FROM t WHERE x = 1"
expect_ok  "SELECT count() FROM t" "&readonly=2&max_execution_time=30"
# The audit trail is append-only: insert works, delete, update and truncate do not.
expect_ok  "INSERT INTO audit_log VALUES (1)"
expect_err "DELETE FROM audit_log WHERE x = 1" ACCESS_DENIED
expect_err "ALTER TABLE audit_log UPDATE x = 2 WHERE 1" ACCESS_DENIED
expect_err "TRUNCATE TABLE audit_log" ACCESS_DENIED
expect_err "CREATE TABLE u (x UInt8) ENGINE = Memory" ACCESS_DENIED
expect_err "ALTER TABLE t ADD COLUMN y UInt8" ACCESS_DENIED
expect_err "DROP TABLE t" ACCESS_DENIED
expect_err "INSERT INTO t VALUES (3)" READONLY "&readonly=2"
expect_err "SELECT 1 SETTINGS readonly = 0" READONLY "&readonly=2"
echo "clickhouse privilege split verified"
