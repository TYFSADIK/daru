package store

import (
	"context"
	"fmt"
	"strings"
)

// validDBName allows only a safe database name. The name comes from the
// environment, so it is validated before it is ever interpolated into SQL.
func validDBName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// Migrate creates the database and all tables if they do not exist.
func (s *Store) Migrate(ctx context.Context) error {
	if !validDBName(s.db) {
		return fmt.Errorf("invalid clickhouse database name %q", s.db)
	}
	// The database itself is created without a database context.
	if err := s.ddl(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", ident(s.db)), ""); err != nil {
		return err
	}
	for _, stmt := range schemaStatements {
		if err := s.ddl(ctx, stmt, s.db); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// Columns added after the first release. IF NOT EXISTS keeps this a
	// no-op on fresh installs and an upgrade on existing ones.
	for _, stmt := range schemaAlterations {
		if err := s.ddl(ctx, stmt, s.db); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// ident quotes a ClickHouse identifier. Backslash is escaped first, then
// backtick as backslash backtick, which is how ClickHouse escapes quoted
// identifiers. Doubling a backtick, as the old code did, is not an escape.
func ident(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, "`", "\\`")
	return "`" + escaped + "`"
}

var schemaAlterations = []string{
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret String DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled UInt8 DEFAULT 0`,
	// index_access: "*" is every index (the default, so upgrades keep the
	// old behaviour), otherwise a comma list; empty means no index.
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS index_access String DEFAULT '*'`,
	// auth_source: local, ldap, oidc, or saml. Existing rows are local.
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source LowCardinality(String) DEFAULT 'local'`,
	`ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS authorization_ref String DEFAULT ''`,
	// Installs before the retention sweep ran independently had a 90 day
	// TTL, which silently capped every index at 90 days. Raise it to the
	// backstop. materialize_ttl_after_modify = 0 makes this a metadata only
	// change (verified on ClickHouse 25.8: no mutation, no rewrite), so it
	// is cheap to repeat on every start.
	`ALTER TABLE events MODIFY TTL toDateTime(_time) + INTERVAL 3650 DAY SETTINGS materialize_ttl_after_modify = 0`,
	`ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS allow_external UInt8 DEFAULT 0`,
}

var schemaStatements = []string{
	// events is the main log store. _time is the sort key and the partition is
	// by day so retention can drop whole partitions cheaply. Per index
	// retention is enforced by the RunRetention sweep; the table TTL is only
	// a backstop at MaxRetentionDays, so it never cuts an index short.
	`CREATE TABLE IF NOT EXISTS events (
		_id         UUID DEFAULT generateUUIDv4(),
		_time       DateTime64(3, 'UTC'),
		_received   DateTime64(3, 'UTC') DEFAULT now64(3),
		"index"     LowCardinality(String),
		host        String,
		source      String,
		sourcetype  LowCardinality(String),
		_raw        String,
		fields      Map(String, String),
		INDEX idx_raw _raw TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
		INDEX idx_host host TYPE bloom_filter GRANULARITY 4
	) ENGINE = MergeTree
	PARTITION BY ("index", toYYYYMMDD(_time))
	ORDER BY ("index", sourcetype, _time)
	TTL toDateTime(_time) + INTERVAL 3650 DAY
	SETTINGS index_granularity = 8192`,

	// indexes holds per-index settings such as retention.
	`CREATE TABLE IF NOT EXISTS indexes (
		name          String,
		retention_days UInt32 DEFAULT 90,
		max_bytes     UInt64 DEFAULT 0,
		created_at    DateTime64(3, 'UTC') DEFAULT now64(3),
		updated_at    DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY name`,

	// users for built-in authentication. No external identity provider needed.
	// totp_secret and totp_enabled hold TOTP second factor enrolment; the
	// secret is never returned to a client except at enrolment time.
	// index_access is the per user index ACL, see auth.User.IndexAccess.
	`CREATE TABLE IF NOT EXISTS users (
		id          UUID DEFAULT generateUUIDv4(),
		username    String,
		password_hash String,
		role        LowCardinality(String) DEFAULT 'user',
		email       String DEFAULT '',
		disabled    UInt8 DEFAULT 0,
		totp_secret String DEFAULT '',
		totp_enabled UInt8 DEFAULT 0,
		index_access String DEFAULT '*',
		auth_source LowCardinality(String) DEFAULT 'local',
		created_at  DateTime64(3, 'UTC') DEFAULT now64(3),
		updated_at  DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY username`,

	// sessions are server-side so they can be revoked, unlike a stateless JWT.
	`CREATE TABLE IF NOT EXISTS sessions (
		token_hash  String,
		username    String,
		role        LowCardinality(String),
		created_at  DateTime64(3, 'UTC') DEFAULT now64(3),
		expires_at  DateTime64(3, 'UTC'),
		revoked     UInt8 DEFAULT 0,
		revoked_at  DateTime64(3, 'UTC') DEFAULT toDateTime64(0, 3)
	) ENGINE = ReplacingMergeTree(revoked_at) ORDER BY token_hash`,

	// ingest_tokens authenticate forwarders and HEC senders.
	`CREATE TABLE IF NOT EXISTS ingest_tokens (
		token_hash  String,
		name        String,
		default_index String DEFAULT 'main',
		disabled    UInt8 DEFAULT 0,
		created_by  String,
		created_at  DateTime64(3, 'UTC') DEFAULT now64(3),
		updated_at  DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY token_hash`,

	// saved_searches store reusable queries, scheduled searches, and alerts.
	`CREATE TABLE IF NOT EXISTS saved_searches (
		id          UUID DEFAULT generateUUIDv4(),
		name        String,
		query       String,
		earliest    String DEFAULT '-24h',
		latest      String DEFAULT 'now',
		owner       String,
		is_alert    UInt8 DEFAULT 0,
		cron        String DEFAULT '',
		condition   String DEFAULT '',
		actions     String DEFAULT '',
		disabled    UInt8 DEFAULT 0,
		created_at  DateTime64(3, 'UTC') DEFAULT now64(3),
		updated_at  DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id`,

	// dashboards store panel definitions as JSON.
	`CREATE TABLE IF NOT EXISTS dashboards (
		id          UUID DEFAULT generateUUIDv4(),
		name        String,
		definition  String,
		owner       String,
		created_at  DateTime64(3, 'UTC') DEFAULT now64(3),
		updated_at  DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id`,

	// alert_history records each time a scheduled alert fired.
	`CREATE TABLE IF NOT EXISTS alert_history (
		id          UUID DEFAULT generateUUIDv4(),
		search_id   String,
		search_name String,
		fired_at    DateTime64(3, 'UTC') DEFAULT now64(3),
		result_count UInt64,
		severity    LowCardinality(String) DEFAULT 'medium',
		delivered   UInt8 DEFAULT 0,
		detail      String DEFAULT ''
	) ENGINE = MergeTree ORDER BY fired_at`,

	// assets is the discovered device/host inventory.
	`CREATE TABLE IF NOT EXISTS assets (
		ip          String,
		mac         String DEFAULT '',
		vendor      String DEFAULT '',
		hostname    String DEFAULT '',
		os          String DEFAULT '',
		open_ports  String DEFAULT '',
		status      LowCardinality(String) DEFAULT 'up',
		source      String DEFAULT '',
		first_seen  DateTime64(3, 'UTC') DEFAULT now64(3),
		last_seen   DateTime64(3, 'UTC') DEFAULT now64(3),
		updated_at  DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY ip`,

	// scans records security tool runs from the recon subsystem.
	`CREATE TABLE IF NOT EXISTS scans (
		id          UUID,
		connector   LowCardinality(String),
		target      String,
		profile     String,
		authorization_ref String,
		status      LowCardinality(String) DEFAULT 'running',
		command     String,
		finding_count UInt32 DEFAULT 0,
		error       String DEFAULT '',
		created_by  String,
		started_at  DateTime64(3, 'UTC'),
		finished_at DateTime64(3, 'UTC') DEFAULT toDateTime64(0, 3),
		updated_at  DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id`,

	// scheduled_scans holds recurring recon scans driven by a cron expression.
	`CREATE TABLE IF NOT EXISTS scheduled_scans (
		id          UUID DEFAULT generateUUIDv4(),
		connector   LowCardinality(String),
		target      String,
		profile     String DEFAULT '',
		ports       String DEFAULT '',
		cron        String,
		enabled     UInt8 DEFAULT 1,
		created_by  String DEFAULT '',
		authorization_ref String DEFAULT '',
		allow_external UInt8 DEFAULT 0,
		last_run    DateTime64(3, 'UTC') DEFAULT toDateTime64(0, 3),
		created_at  DateTime64(3, 'UTC') DEFAULT now64(3),
		updated_at  DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id`,

	// scan_findings holds structured results from each scan.
	`CREATE TABLE IF NOT EXISTS scan_findings (
		id          UUID,
		scan_id     String,
		created_at  DateTime64(3, 'UTC') DEFAULT now64(3),
		connector   LowCardinality(String),
		target      String,
		title       String,
		severity    LowCardinality(String) DEFAULT 'info',
		port        String DEFAULT '',
		service     String DEFAULT '',
		detail      String DEFAULT '',
		fields      Map(String, String)
	) ENGINE = MergeTree ORDER BY (scan_id, severity)`,

	// notable_events is the security incident queue (ES equivalent).
	`CREATE TABLE IF NOT EXISTS notable_events (
		id          UUID DEFAULT generateUUIDv4(),
		created_at  DateTime64(3, 'UTC') DEFAULT now64(3),
		rule_name   String,
		severity    LowCardinality(String) DEFAULT 'medium',
		status      LowCardinality(String) DEFAULT 'new',
		owner       String DEFAULT '',
		mitre       String DEFAULT '',
		entity      String DEFAULT '',
		detail      String DEFAULT '',
		raw         String DEFAULT '',
		updated_at  DateTime64(3, 'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id`,
}
