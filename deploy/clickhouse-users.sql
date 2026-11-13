-- Least privilege ClickHouse users for Daru.
--
-- Daru runs as two ClickHouse users:
--   daru_admin  schema changes: CREATE DATABASE/TABLE, ALTER ADD COLUMN,
--               ALTER DROP PARTITION (per index retention). Set it as
--               DARU_CLICKHOUSE_ADMIN_USER / DARU_CLICKHOUSE_ADMIN_PASSWORD.
--   daru_app    everything at runtime: SELECT, INSERT, ALTER DELETE and
--               ALTER UPDATE. The ALTER rights are row level, not schema:
--               lightweight DELETE of saved searches, dashboards, sessions,
--               and schedules needs both on ClickHouse 25.x (it rewrites
--               the hidden _row_exists column). Note that in ClickHouse
--               ALTER DELETE also permits ALTER DROP PARTITION, so the app
--               user can delete data, as Daru's own delete features must.
--               It cannot create, alter the schema of, or drop tables, and
--               cannot read files or other databases. Set it as DARU_CLICKHOUSE_USER /
--               DARU_CLICKHOUSE_PASSWORD.
-- User written searches additionally run with readonly=2, so even the
-- app user's INSERT and DELETE rights are not reachable from a search.
--
-- Run this once as a ClickHouse user with access management, replacing
-- both passwords:
--   clickhouse client --user default --password --multiquery < deploy/clickhouse-users.sql
-- The docker compose setup does this automatically on first start, see
-- deploy/clickhouse-init/10-daru-users.sh.

CREATE DATABASE IF NOT EXISTS daru;

CREATE USER IF NOT EXISTS daru_admin IDENTIFIED WITH sha256_password BY 'REPLACE-WITH-ADMIN-PASSWORD';
GRANT CREATE DATABASE ON daru.* TO daru_admin;
GRANT CREATE TABLE, ALTER, SELECT, INSERT ON daru.* TO daru_admin;

CREATE USER IF NOT EXISTS daru_app IDENTIFIED WITH sha256_password BY 'REPLACE-WITH-APP-PASSWORD';
GRANT SELECT, INSERT, ALTER DELETE, ALTER UPDATE ON daru.* TO daru_app;
-- The audit trail is append-only for the app: it can add records but not
-- change or delete them. Run this line on existing installs too.
REVOKE ALTER DELETE, ALTER UPDATE ON daru.audit_log FROM daru_app;
