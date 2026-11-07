package store

import (
	"context"
	"fmt"
)

// Migrate creates the database and all tables if they do not exist.
func (s *Store) Migrate(ctx context.Context) error {
	// The database itself is created without a database context.
	if _, err := s.do(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", ident(s.db)), ""); err != nil {
		return err
	}
	for _, stmt := range schemaStatements {
		if err := s.exec(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

func ident(s string) string { return "`" + s + "`" }

var schemaStatements = []string{
	// events is the main log store. _time is the sort key and the partition is
	// by day so retention can drop whole partitions cheaply.
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
	TTL toDateTime(_time) + INTERVAL 90 DAY
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
	`CREATE TABLE IF NOT EXISTS users (
		id          UUID DEFAULT generateUUIDv4(),
		username    String,
		password_hash String,
		role        LowCardinality(String) DEFAULT 'user',
		email       String DEFAULT '',
		disabled    UInt8 DEFAULT 0,
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
