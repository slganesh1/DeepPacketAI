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

    FOREIGN KEY (call_id) REFERENCES calls(call_id)
);
