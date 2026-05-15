package postgres

import (
	"context"
	"fmt"
	"log"
)

type migration struct {
	version int
	sql     string
}

var migrations = []migration{
	{
		version: 1,
		sql: `
        CREATE TABLE IF NOT EXISTS jobs (
            id BIGINT PRIMARY KEY,
            status TEXT NOT NULL CHECK(status IN ('running','completed','failed','pending')),
            pcap_path TEXT,
            error TEXT,
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS flows (
            id BIGSERIAL PRIMARY KEY,
            job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            flow_id TEXT,
            type TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            start_time TIMESTAMPTZ,
            end_time TIMESTAMPTZ,
            metrics JSONB
        );

        CREATE TABLE IF NOT EXISTS calls (
            id BIGSERIAL PRIMARY KEY,
            job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            call_id TEXT NOT NULL,
            from_uri TEXT,
            to_uri TEXT,
            start_time TIMESTAMPTZ,
            end_time TIMESTAMPTZ,
            duration_sec INTEGER,
            packet_count INTEGER DEFAULT 0,
            jitter_ms INTEGER DEFAULT 0,
            max_seq_gap INTEGER DEFAULT 0,
            mos REAL DEFAULT 0,
            quality TEXT,
            is_on_hold BOOLEAN DEFAULT FALSE,
            end_type TEXT,
            root_cause TEXT,
            confidence REAL DEFAULT 0,
            UNIQUE(job_id, call_id)
        );

        CREATE TABLE IF NOT EXISTS rtp_legs (
            id BIGSERIAL PRIMARY KEY,
            job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            call_id TEXT NOT NULL,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            ssrc BIGINT,
            packet_count INTEGER DEFAULT 0,
            jitter_ms INTEGER DEFAULT 0,
            max_seq_gap INTEGER DEFAULT 0,
            start_time TIMESTAMPTZ,
            end_time TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS packets (
            id BIGSERIAL PRIMARY KEY,
            job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            session_id TEXT,
            frame_number BIGINT,
            timestamp TIMESTAMPTZ NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            app_protocol TEXT,
            length INTEGER,
            summary TEXT,
            metadata_json JSONB,
            errors_json JSONB
        );

        CREATE TABLE IF NOT EXISTS protocol_events (
            id BIGSERIAL PRIMARY KEY,
            job_id BIGINT REFERENCES jobs(id) ON DELETE CASCADE,
            session_id TEXT,
            packet_id BIGINT,
            timestamp TIMESTAMPTZ NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('critical','error','warning','info')),
            protocol TEXT,
            title TEXT NOT NULL,
            description TEXT,
            metadata_json JSONB
        );

        CREATE TABLE IF NOT EXISTS capture_sessions (
            id TEXT PRIMARY KEY,
            interface_name TEXT NOT NULL,
            bpf_filter TEXT,
            status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running','stopped','error')),
            started_at TIMESTAMPTZ NOT NULL,
            stopped_at TIMESTAMPTZ,
            packet_count BIGINT DEFAULT 0,
            byte_count BIGINT DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS traffic_stats (
            id BIGSERIAL PRIMARY KEY,
            job_id BIGINT REFERENCES jobs(id) ON DELETE CASCADE,
            session_id TEXT,
            timestamp TIMESTAMPTZ NOT NULL,
            interval_sec INTEGER DEFAULT 1,
            packets_per_sec INTEGER DEFAULT 0,
            bytes_per_sec INTEGER DEFAULT 0,
            protocol_counts_json JSONB
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            title TEXT,
            provider TEXT,
            model TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
            id BIGSERIAL PRIMARY KEY,
            conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            packet_context_json JSONB,
            created_at TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE IF NOT EXISTS telecom_sessions (
            id BIGSERIAL PRIMARY KEY,
            job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            session_id TEXT NOT NULL,
            imsi TEXT,
            msisdn TEXT,
            apn TEXT,
            ue_ip TEXT,
            sip_call_id TEXT,
            sip_from TEXT,
            sip_to TEXT,
            start_time TIMESTAMPTZ,
            end_time TIMESTAMPTZ,
            mos REAL DEFAULT 0,
            quality TEXT,
            has_ngap BOOLEAN DEFAULT FALSE,
            has_gtpc BOOLEAN DEFAULT FALSE,
            has_pfcp BOOLEAN DEFAULT FALSE,
            has_gtpu BOOLEAN DEFAULT FALSE,
            has_sip BOOLEAN DEFAULT FALSE,
            has_rtp BOOLEAN DEFAULT FALSE,
            has_diameter BOOLEAN DEFAULT FALSE,
            is_complete BOOLEAN DEFAULT FALSE,
            layers JSONB,
            events JSONB,
            UNIQUE(job_id, session_id)
        );

        CREATE INDEX IF NOT EXISTS idx_packets_job_id ON packets(job_id);
        CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
        CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(app_protocol);
        CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_session_id ON packets(session_id);
        CREATE INDEX IF NOT EXISTS idx_flows_job_id ON flows(job_id);
        CREATE INDEX IF NOT EXISTS idx_flows_flow_id ON flows(flow_id);
        CREATE INDEX IF NOT EXISTS idx_calls_job_id ON calls(job_id);
        CREATE INDEX IF NOT EXISTS idx_calls_call_id ON calls(call_id);
        CREATE INDEX IF NOT EXISTS idx_rtp_legs_call_id ON rtp_legs(call_id);
        CREATE INDEX IF NOT EXISTS idx_rtp_legs_job_id ON rtp_legs(job_id);
        CREATE INDEX IF NOT EXISTS idx_protocol_events_job_id ON protocol_events(job_id);
        CREATE INDEX IF NOT EXISTS idx_protocol_events_severity ON protocol_events(severity);
        CREATE INDEX IF NOT EXISTS idx_protocol_events_timestamp ON protocol_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_traffic_stats_timestamp ON traffic_stats(timestamp);
        CREATE INDEX IF NOT EXISTS idx_traffic_stats_session_id ON traffic_stats(session_id);
        CREATE INDEX IF NOT EXISTS idx_telecom_sessions_job_id ON telecom_sessions(job_id);
        CREATE INDEX IF NOT EXISTS idx_telecom_sessions_imsi ON telecom_sessions(imsi);
        CREATE INDEX IF NOT EXISTS idx_telecom_sessions_sip_call_id ON telecom_sessions(sip_call_id);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation ON chat_messages(conversation_id);
        `,
	},
	{
		version: 2,
		sql: `
        CREATE TABLE IF NOT EXISTS alert_targets (
            id          BIGSERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            type        TEXT NOT NULL CHECK(type IN ('slack','webhook','email')),
            url         TEXT NOT NULL DEFAULT '',
            config_json TEXT NOT NULL DEFAULT '{}',
            enabled     BOOLEAN NOT NULL DEFAULT TRUE,
            min_severity TEXT NOT NULL DEFAULT 'warning' CHECK(min_severity IN ('info','warning','critical')),
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        `,
	},
	{
		version: 3,
		sql: `
        CREATE TABLE IF NOT EXISTS user_detection_rules (
            id             BIGSERIAL PRIMARY KEY,
            name           TEXT NOT NULL,
            description    TEXT NOT NULL DEFAULT '',
            protocol       TEXT NOT NULL DEFAULT 'ANY',
            severity       TEXT NOT NULL DEFAULT 'warning' CHECK(severity IN ('info','warning','error','critical')),
            condition_json TEXT NOT NULL DEFAULT '{}',
            enabled        BOOLEAN NOT NULL DEFAULT TRUE,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        `,
	},
	{
		version: 4,
		sql: `
        CREATE TABLE IF NOT EXISTS ip_enrichments (
            ip           TEXT PRIMARY KEY,
            country_code TEXT NOT NULL DEFAULT '',
            country      TEXT NOT NULL DEFAULT '',
            city         TEXT NOT NULL DEFAULT '',
            isp          TEXT NOT NULL DEFAULT '',
            org          TEXT NOT NULL DEFAULT '',
            lat          DOUBLE PRECISION NOT NULL DEFAULT 0,
            lon          DOUBLE PRECISION NOT NULL DEFAULT 0,
            is_hosting   BOOLEAN NOT NULL DEFAULT FALSE,
            is_tor       BOOLEAN NOT NULL DEFAULT FALSE,
            is_proxy     BOOLEAN NOT NULL DEFAULT FALSE,
            abuse_score  INTEGER NOT NULL DEFAULT 0,
            is_abusive   BOOLEAN NOT NULL DEFAULT FALSE,
            last_checked TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_ip_enrichments_country ON ip_enrichments(country_code);
        `,
	},
	{
		version: 5,
		sql: `
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            username   TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
        `,
	},
}


func (s *PostgresStore) runMigrations(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	var current int
	_ = s.pool.QueryRow(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&current)

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		log.Printf("postgres: applying migration v%d", m.version)
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migration v%d: %w", m.version, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", m.version); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		log.Printf("postgres: migration v%d applied", m.version)
	}
	return nil
}
