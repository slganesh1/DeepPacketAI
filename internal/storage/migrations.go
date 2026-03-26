package storage

import (
	"database/sql"
	"fmt"
	"log"
)

// migration represents a single schema migration with a version and SQL to execute.
type migration struct {
	version int
	sql     string
}

// migrations is the ordered list of schema migrations.
// Append new migrations at the end with incrementing version numbers.
var migrations = []migration{
	{
		version: 1,
		sql: `
		-- ---- jobs table ----
		CREATE TABLE IF NOT EXISTS jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed', 'pending')),
			pcap_path TEXT,
			error TEXT,
			started_at TEXT,
			completed_at TEXT
		);

		-- ---- flows table ----
		CREATE TABLE IF NOT EXISTS flows (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER NOT NULL,
			flow_id TEXT,
			type TEXT,
			src_ip TEXT,
			src_port INTEGER,
			dst_ip TEXT,
			dst_port INTEGER,
			start_time TEXT,
			end_time TEXT,
			metrics TEXT,
			FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
		);

		-- ---- calls table ----
		CREATE TABLE IF NOT EXISTS calls (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER NOT NULL,
			call_id TEXT NOT NULL,
			from_uri TEXT,
			to_uri TEXT,
			start_time TEXT,
			end_time TEXT,
			duration_sec INTEGER,
			packet_count INTEGER,
			jitter_ms INTEGER,
			max_seq_gap INTEGER,
			mos REAL,
			quality TEXT,
			is_on_hold BOOLEAN,
			end_type TEXT,
			root_cause TEXT,
			confidence REAL,
			UNIQUE(job_id, call_id),
			FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
		);

		-- ---- RTP legs table ----
		CREATE TABLE IF NOT EXISTS rtp_legs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER NOT NULL,
			call_id TEXT NOT NULL,
			src_ip TEXT,
			src_port INTEGER,
			dst_ip TEXT,
			dst_port INTEGER,
			ssrc INTEGER,
			packet_count INTEGER,
			jitter_ms INTEGER,
			max_seq_gap INTEGER,
			start_time TEXT,
			end_time TEXT,
			FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
		);

		-- ---- packets table ----
		CREATE TABLE IF NOT EXISTS packets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER NOT NULL,
			session_id TEXT,
			frame_number INTEGER,
			timestamp TEXT NOT NULL,
			src_ip TEXT,
			dst_ip TEXT,
			src_port INTEGER,
			dst_port INTEGER,
			protocol TEXT,
			app_protocol TEXT,
			length INTEGER,
			summary TEXT,
			metadata_json TEXT,
			errors_json TEXT,
			FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
		);

		-- ---- protocol_events table ----
		CREATE TABLE IF NOT EXISTS protocol_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER,
			session_id TEXT,
			packet_id INTEGER,
			timestamp TEXT NOT NULL,
			severity TEXT NOT NULL CHECK(severity IN ('critical', 'error', 'warning', 'info')),
			protocol TEXT,
			title TEXT NOT NULL,
			description TEXT,
			metadata_json TEXT,
			FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
		);

		-- ---- capture_sessions table ----
		CREATE TABLE IF NOT EXISTS capture_sessions (
			id TEXT PRIMARY KEY,
			interface_name TEXT NOT NULL,
			bpf_filter TEXT,
			status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running', 'stopped', 'error')),
			started_at TEXT NOT NULL,
			stopped_at TEXT,
			packet_count INTEGER DEFAULT 0,
			byte_count INTEGER DEFAULT 0
		);

		-- ---- traffic_stats table ----
		CREATE TABLE IF NOT EXISTS traffic_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER,
			session_id TEXT,
			timestamp TEXT NOT NULL,
			interval_sec INTEGER DEFAULT 1,
			packets_per_sec INTEGER,
			bytes_per_sec INTEGER,
			protocol_counts_json TEXT,
			FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
		);

		-- ---- conversations table ----
		CREATE TABLE IF NOT EXISTS conversations (
			id TEXT PRIMARY KEY,
			title TEXT,
			provider TEXT,
			model TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);

		-- ---- chat_messages table ----
		CREATE TABLE IF NOT EXISTS chat_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			conversation_id TEXT NOT NULL,
			role TEXT NOT NULL,
			content TEXT NOT NULL,
			packet_context_json TEXT,
			created_at TEXT NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		);

		-- ---- Indexes ----
		CREATE INDEX IF NOT EXISTS idx_packets_job_id ON packets(job_id);
		CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
		CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(app_protocol);
		CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
		CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
		CREATE INDEX IF NOT EXISTS idx_packets_session_id ON packets(session_id);
		CREATE INDEX IF NOT EXISTS idx_protocol_events_job_id ON protocol_events(job_id);
		CREATE INDEX IF NOT EXISTS idx_protocol_events_severity ON protocol_events(severity);
		CREATE INDEX IF NOT EXISTS idx_protocol_events_session_id ON protocol_events(session_id);
		CREATE INDEX IF NOT EXISTS idx_protocol_events_timestamp ON protocol_events(timestamp);
		CREATE INDEX IF NOT EXISTS idx_traffic_stats_timestamp ON traffic_stats(timestamp);
		CREATE INDEX IF NOT EXISTS idx_traffic_stats_session_id ON traffic_stats(session_id);
		CREATE INDEX IF NOT EXISTS idx_flows_job_id ON flows(job_id);
		CREATE INDEX IF NOT EXISTS idx_flows_flow_id ON flows(flow_id);
		CREATE INDEX IF NOT EXISTS idx_calls_job_id ON calls(job_id);
		CREATE INDEX IF NOT EXISTS idx_calls_call_id ON calls(call_id);
		CREATE INDEX IF NOT EXISTS idx_rtp_legs_call_id ON rtp_legs(call_id);
		CREATE INDEX IF NOT EXISTS idx_rtp_legs_job_id ON rtp_legs(job_id);
		CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation ON chat_messages(conversation_id);
		`,
	},
	{
		version: 2,
		sql: `
		-- ---- telecom_sessions table ----
		CREATE TABLE IF NOT EXISTS telecom_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER NOT NULL,
			session_id TEXT NOT NULL,
			imsi TEXT,
			msisdn TEXT,
			apn TEXT,
			ue_ip TEXT,
			sip_call_id TEXT,
			sip_from TEXT,
			sip_to TEXT,
			start_time TEXT,
			end_time TEXT,
			mos REAL,
			quality TEXT,
			has_ngap BOOLEAN DEFAULT 0,
			has_gtpc BOOLEAN DEFAULT 0,
			has_pfcp BOOLEAN DEFAULT 0,
			has_gtpu BOOLEAN DEFAULT 0,
			has_sip BOOLEAN DEFAULT 0,
			has_rtp BOOLEAN DEFAULT 0,
			has_diameter BOOLEAN DEFAULT 0,
			is_complete BOOLEAN DEFAULT 0,
			layers_json TEXT,
			events_json TEXT,
			UNIQUE(job_id, session_id),
			FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
		);

		CREATE INDEX IF NOT EXISTS idx_telecom_sessions_job_id ON telecom_sessions(job_id);
		CREATE INDEX IF NOT EXISTS idx_telecom_sessions_imsi ON telecom_sessions(imsi);
		CREATE INDEX IF NOT EXISTS idx_telecom_sessions_sip_call_id ON telecom_sessions(sip_call_id);
		`,
	},
	{
		version: 3,
		sql: `
		-- Add telecom subscriber context and lifecycle columns (version 3)
		ALTER TABLE telecom_sessions ADD COLUMN rat_type TEXT;
		ALTER TABLE telecom_sessions ADD COLUMN serving_network TEXT;
		ALTER TABLE telecom_sessions ADD COLUMN location TEXT;
		ALTER TABLE telecom_sessions ADD COLUMN pdn_type TEXT;
		ALTER TABLE telecom_sessions ADD COLUMN ue_state TEXT;
		ALTER TABLE telecom_sessions ADD COLUMN teids_json TEXT;
		ALTER TABLE telecom_sessions ADD COLUMN bearer_teids_json TEXT;
		ALTER TABLE telecom_sessions ADD COLUMN lifecycle_json TEXT;

		CREATE INDEX IF NOT EXISTS idx_telecom_sessions_ue_ip ON telecom_sessions(ue_ip);
		`,
	},
	{
		version: 4,
		sql: `
		-- Add raw_packet BLOB for Wireshark-grade hex inspection (version 4)
		ALTER TABLE packets ADD COLUMN raw_packet BLOB;
		`,
	},
	{
		version: 5,
		sql: `
		-- Alert targets for webhook/Slack/email notifications (version 5)
		CREATE TABLE IF NOT EXISTS alert_targets (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT NOT NULL,
			type        TEXT NOT NULL CHECK(type IN ('slack', 'webhook', 'email')),
			url         TEXT NOT NULL DEFAULT '',
			config_json TEXT NOT NULL DEFAULT '{}',
			enabled     INTEGER NOT NULL DEFAULT 1,
			min_severity TEXT NOT NULL DEFAULT 'warning' CHECK(min_severity IN ('info', 'warning', 'critical')),
			created_at  TEXT NOT NULL DEFAULT (datetime('now'))
		);
		`,
	},
	{
		version: 6,
		sql: `
		-- User-defined detection rules (version 6)
		CREATE TABLE IF NOT EXISTS user_detection_rules (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			name           TEXT NOT NULL,
			description    TEXT NOT NULL DEFAULT '',
			protocol       TEXT NOT NULL DEFAULT 'ANY',
			severity       TEXT NOT NULL DEFAULT 'warning' CHECK(severity IN ('info', 'warning', 'error', 'critical')),
			condition_json TEXT NOT NULL DEFAULT '{}',
			enabled        INTEGER NOT NULL DEFAULT 1,
			created_at     TEXT NOT NULL DEFAULT (datetime('now'))
		);
		`,
	},
	{
		version: 7,
		sql: `
		-- IP geo + reputation enrichment cache (version 7)
		CREATE TABLE IF NOT EXISTS ip_enrichments (
			ip           TEXT PRIMARY KEY,
			country_code TEXT NOT NULL DEFAULT '',
			country      TEXT NOT NULL DEFAULT '',
			city         TEXT NOT NULL DEFAULT '',
			isp          TEXT NOT NULL DEFAULT '',
			org          TEXT NOT NULL DEFAULT '',
			lat          REAL NOT NULL DEFAULT 0,
			lon          REAL NOT NULL DEFAULT 0,
			is_hosting   INTEGER NOT NULL DEFAULT 0,
			is_tor       INTEGER NOT NULL DEFAULT 0,
			is_proxy     INTEGER NOT NULL DEFAULT 0,
			abuse_score  INTEGER NOT NULL DEFAULT 0,
			is_abusive   INTEGER NOT NULL DEFAULT 0,
			last_checked TEXT NOT NULL DEFAULT (datetime('now'))
		);
		CREATE INDEX IF NOT EXISTS idx_ip_enrichments_country ON ip_enrichments(country_code);
		`,
	},
}

// runMigrations creates the schema_version table if needed, then applies
// any migrations whose version is greater than the current version.
func runMigrations(db *sql.DB) error {
	// Create schema_version table to track applied migrations
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT (datetime('now'))
		)
	`); err != nil {
		return fmt.Errorf("create schema_version table: %w", err)
	}

	// Get current version
	var currentVersion int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("get current schema version: %w", err)
	}

	// Apply pending migrations
	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}

		log.Printf("Applying migration v%d...", m.version)

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", m.version, err)
		}

		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration v%d failed: %w", m.version, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", m.version); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d: %w", m.version, err)
		}

		log.Printf("Migration v%d applied successfully", m.version)
	}

	return nil
}
