-- Consulta Maestra para ClickHouse
-- Extrae las características de los eventos de auditoría y los exporta a CSV.
-- Puedes ejecutar esto desde el cliente de ClickHouse (clickhouse-client).

SELECT
    latency_ms,
    risk_score,
    distance_km,
    toHour(timestamp) AS hour_of_day,
    multiIf(
        decision = 'ALLOW', 0,
        decision = 'DENY', 1,
        decision = 'CHALLENGE', 2,
        0 -- Valor por defecto
    ) AS decision,
    device_trust_score
FROM audit_logs
-- Recomendación: Usar un límite razonable para el primer modelo
-- WHERE timestamp >= now() - INTERVAL 30 DAY
LIMIT 100000
INTO OUTFILE 'dataset_features.csv' FORMAT CSVWithNames;
