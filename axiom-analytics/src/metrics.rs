//! metrics.rs — Lógica estadística del endpoint /anomaly_score
//!
//! Implementa tres métricas:
//!   - `avg_latency`  : latencia media en la ventana vs baseline histórico (7d)
//!   - `deny_rate`    : tasa de decisiones DENY en la ventana vs baseline
//!   - `geo_velocity` : número de geos distintas / total eventos en la ventana
//!
//! La "anomalía" se mide con un z-score simple:
//!   z = (valor_ventana − mean_baseline) / max(stddev_baseline, ε)
//!   anomaly_score = clamp(|z| / THRESHOLD, 0.0, 1.0)
//!   is_anomaly = |z| > THRESHOLD

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::clickhouse::ClickHouseClient;

/// Umbral de z-score por encima del cual se considera anomalía.
const Z_THRESHOLD: f64 = 2.5;

/// Epsilon para evitar división por cero en la desviación estándar.
const STDDEV_EPSILON: f64 = 1e-9;

// ─── Tipos públicos ───────────────────────────────────────────────────────────

/// Métrica a calcular. Se deserializa desde el parámetro de query `metric`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    AvgLatency,
    DenyRate,
    GeoVelocity,
}

impl std::fmt::Display for Metric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Metric::AvgLatency => write!(f, "avg_latency"),
            Metric::DenyRate => write!(f, "deny_rate"),
            Metric::GeoVelocity => write!(f, "geo_velocity"),
        }
    }
}

impl std::str::FromStr for Metric {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "avg_latency" => Ok(Metric::AvgLatency),
            "deny_rate" => Ok(Metric::DenyRate),
            "geo_velocity" => Ok(Metric::GeoVelocity),
            other => anyhow::bail!("Métrica desconocida: '{other}'. Usa: avg_latency | deny_rate | geo_velocity"),
        }
    }
}

/// Resultado completo del cálculo de anomalía.
#[derive(Debug, Serialize)]
pub struct AnomalyResult {
    pub user_did: String,
    pub window_seconds: u32,
    pub metric: String,
    /// Número de eventos en la ventana temporal.
    pub event_count: u64,
    /// Valor crudo de la métrica en la ventana.
    pub raw_value: f64,
    /// Media de la métrica en el baseline histórico (7 días).
    pub mean_baseline: f64,
    /// Desviación estándar en el baseline histórico.
    pub stddev_baseline: f64,
    /// z-score: (raw_value − mean_baseline) / stddev_baseline
    pub z_score: f64,
    /// Score normalizado en [0, 1]: min(|z| / threshold, 1.0)
    pub anomaly_score: f64,
    /// true si |z| > threshold (2.5)
    pub is_anomaly: bool,
    /// Umbral z-score utilizado
    pub threshold: f64,
}

// ─── Funciones de métricas ───────────────────────────────────────────────────

/// Obtiene el valor de la métrica en la ventana temporal y el baseline histórico.
/// Devuelve `(raw_value, event_count, mean_baseline, stddev_baseline)`.
async fn fetch_metric_values(
    ch: &ClickHouseClient,
    user_did: &str,
    window_seconds: u32,
    metric: &Metric,
) -> anyhow::Result<(f64, u64, f64, f64)> {
    match metric {
        Metric::AvgLatency => fetch_avg_latency(ch, user_did, window_seconds).await,
        Metric::DenyRate => fetch_deny_rate(ch, user_did, window_seconds).await,
        Metric::GeoVelocity => fetch_geo_velocity(ch, user_did, window_seconds).await,
    }
}

/// avg_latency: latencia media en la ventana y baseline de 7 días.
async fn fetch_avg_latency(
    ch: &ClickHouseClient,
    user_did: &str,
    window_seconds: u32,
) -> anyhow::Result<(f64, u64, f64, f64)> {
    let window_sql = format!(
        "SELECT
            count() AS event_count,
            AVG(latency_ms) AS raw_value
         FROM audit_events
         WHERE user_did = '{user_did}'
           AND timestamp_ns >= (now() - INTERVAL {window_seconds} SECOND) * 1000000000",
    );

    let baseline_sql = format!(
        "SELECT
            AVG(latency_ms) AS mean_val,
            stddevPop(latency_ms) AS stddev_val
         FROM audit_events
         WHERE user_did = '{user_did}'
           AND timestamp_ns >= (now() - INTERVAL 7 DAY) * 1000000000",
    );

    let (raw, count) = run_window_query(ch, &window_sql).await?;
    let (mean, stddev) = run_baseline_query(ch, &baseline_sql).await?;

    Ok((raw, count, mean, stddev))
}

/// deny_rate: proporción de DENY en la ventana y baseline de 7 días.
async fn fetch_deny_rate(
    ch: &ClickHouseClient,
    user_did: &str,
    window_seconds: u32,
) -> anyhow::Result<(f64, u64, f64, f64)> {
    let window_sql = format!(
        "SELECT
            count() AS event_count,
            countIf(decision = 'DENY') / count() AS raw_value
         FROM audit_events
         WHERE user_did = '{user_did}'
           AND timestamp_ns >= (now() - INTERVAL {window_seconds} SECOND) * 1000000000",
    );

    // Para el baseline de deny_rate, calculamos la media y desviación de la proporción
    // por ventanas de 5 minutos durante los últimos 7 días (estadística de proporciones).
    let baseline_sql = format!(
        "SELECT
            AVG(deny_rate) AS mean_val,
            stddevPop(deny_rate) AS stddev_val
         FROM (
             SELECT
                 toStartOfInterval(fromUnixTimestamp64Nano(timestamp_ns), INTERVAL 5 MINUTE) AS bucket,
                 countIf(decision = 'DENY') / count() AS deny_rate
             FROM audit_events
             WHERE user_did = '{user_did}'
               AND timestamp_ns >= (now() - INTERVAL 7 DAY) * 1000000000
             GROUP BY bucket
         )",
    );

    let (raw, count) = run_window_query(ch, &window_sql).await?;
    let (mean, stddev) = run_baseline_query(ch, &baseline_sql).await?;

    Ok((raw, count, mean, stddev))
}

/// geo_velocity: ratio geos_distintas / total_eventos en la ventana.
/// Usa context['geo'] si está disponible; si no hay datos de geo, usa context['device_id'].
async fn fetch_geo_velocity(
    ch: &ClickHouseClient,
    user_did: &str,
    window_seconds: u32,
) -> anyhow::Result<(f64, u64, f64, f64)> {
    let window_sql = format!(
        "SELECT
            count() AS event_count,
            toFloat64(uniqExact(context['geo'])) / count() AS raw_value
         FROM audit_events
         WHERE user_did = '{user_did}'
           AND timestamp_ns >= (now() - INTERVAL {window_seconds} SECOND) * 1000000000",
    );

    // Baseline: media y desviación de geo_velocity por ventanas de 5 min en 7 días
    let baseline_sql = format!(
        "SELECT
            AVG(geo_vel) AS mean_val,
            stddevPop(geo_vel) AS stddev_val
         FROM (
             SELECT
                 toStartOfInterval(fromUnixTimestamp64Nano(timestamp_ns), INTERVAL 5 MINUTE) AS bucket,
                 toFloat64(uniqExact(context['geo'])) / count() AS geo_vel
             FROM audit_events
             WHERE user_did = '{user_did}'
               AND timestamp_ns >= (now() - INTERVAL 7 DAY) * 1000000000
             GROUP BY bucket
         )",
    );

    let (raw, count) = run_window_query(ch, &window_sql).await?;
    let (mean, stddev) = run_baseline_query(ch, &baseline_sql).await?;

    Ok((raw, count, mean, stddev))
}

// ─── Helpers de queries ───────────────────────────────────────────────────────

/// Ejecuta la query de ventana y extrae (raw_value, event_count).
async fn run_window_query(ch: &ClickHouseClient, sql: &str) -> anyhow::Result<(f64, u64)> {
    let row = ch
        .query_single_row(sql)
        .await
        .context("Error en query de ventana")?
        .unwrap_or(serde_json::json!({"event_count": 0, "raw_value": 0.0}));

    let count = row["event_count"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| row["event_count"].as_u64())
        .unwrap_or(0);

    let raw = row["raw_value"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .or_else(|| row["raw_value"].as_f64())
        .unwrap_or(0.0);

    Ok((raw, count))
}

/// Ejecuta la query de baseline y extrae (mean, stddev).
async fn run_baseline_query(ch: &ClickHouseClient, sql: &str) -> anyhow::Result<(f64, f64)> {
    let row = ch
        .query_single_row(sql)
        .await
        .context("Error en query de baseline")?
        .unwrap_or(serde_json::json!({"mean_val": 0.0, "stddev_val": 0.0}));

    let mean = row["mean_val"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .or_else(|| row["mean_val"].as_f64())
        .unwrap_or(0.0);

    let stddev = row["stddev_val"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .or_else(|| row["stddev_val"].as_f64())
        .unwrap_or(0.0);

    Ok((mean, stddev))
}

// ─── Punto de entrada principal ───────────────────────────────────────────────

/// Calcula el AnomalyResult completo para un usuario, ventana y métrica dados.
pub async fn compute_anomaly(
    ch: &ClickHouseClient,
    user_did: &str,
    window_seconds: u32,
    metric: &Metric,
) -> anyhow::Result<AnomalyResult> {
    let (raw_value, event_count, mean_baseline, stddev_baseline) =
        fetch_metric_values(ch, user_did, window_seconds, metric).await?;

    // z-score con clamping de stddev para evitar división por cero
    let effective_stddev = f64::max(stddev_baseline, STDDEV_EPSILON);
    let z_score = (raw_value - mean_baseline) / effective_stddev;
    let anomaly_score = (z_score.abs() / Z_THRESHOLD).min(1.0);
    let is_anomaly = z_score.abs() > Z_THRESHOLD;

    Ok(AnomalyResult {
        user_did: user_did.to_string(),
        window_seconds,
        metric: metric.to_string(),
        event_count,
        raw_value,
        mean_baseline,
        stddev_baseline,
        z_score,
        anomaly_score,
        is_anomaly,
        threshold: Z_THRESHOLD,
    })
}
