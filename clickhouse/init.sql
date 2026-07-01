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

-- Tabla agregada para métricas por minuto por usuario
CREATE TABLE IF NOT EXISTS audit_events_1m (
    user_did      String,
    window_start  DateTime,
    latency_avg   AggregateFunction(avg, Float64),
    latency_var   AggregateFunction(varSamp, Float64),
    distance_p99  AggregateFunction(quantile(0.99), Float64)
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (user_did, window_start);

-- Vista Materializada que puebla la tabla agregada
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_audit_events_1m
TO audit_events_1m
AS SELECT
    user_did,
    toStartOfMinute(created_at) AS window_start,
    avgState(latency_ms) AS latency_avg,
    varSampState(latency_ms) AS latency_var,
    quantileState(0.99)(JSONExtractFloat(context['env'], 'distance_km')) AS distance_p99
FROM audit_events
GROUP BY user_did, window_start;

