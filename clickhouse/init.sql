-- Tabla de auditoría con MergeTree.
-- context_snapshot es Map(String, String) para alta cardinalidad sin arrays anidados.
CREATE TABLE IF NOT EXISTS audit_events (
    timestamp_ns  UInt64                        COMMENT 'Unix epoch en nanosegundos',
    session_id    String                         COMMENT 'ID único de la sesión',
    user_did      String                         COMMENT 'Identidad descentralizada del usuario',
    resource_hash String                         COMMENT 'Hash del recurso solicitado',
    decision      LowCardinality(String)         COMMENT 'ALLOW | DENY | CHALLENGE',
    risk_score    Float32                        COMMENT 'Score de riesgo calculado por el PDP',
    context       Map(String, String)            COMMENT 'Snapshot de contexto: geo, device_id, hour, etc.',
    latency_ms    Float64                        COMMENT 'Latencia del motor PDP en ms',
    created_at    DateTime DEFAULT now()         COMMENT 'Momento de inserción en ClickHouse'
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (user_did, timestamp_ns);
