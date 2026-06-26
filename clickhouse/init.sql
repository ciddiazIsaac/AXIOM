CREATE TABLE IF NOT EXISTS audit_events (
    timestamp_ns UInt64,
    session_id String,
    user_did String,
    resource_hash String,
    decision String,
    risk_score Float32,
    context_snapshot String,
    latency_ms Float64,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (user_did, timestamp_ns);
