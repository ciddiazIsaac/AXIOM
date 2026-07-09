use axum::{
    extract::{State, Query},
    Json,
};
use serde::{Deserialize, Serialize};
use axiom_core::pdp::{Decision, ZeroTrustEngine, ZeroTrustRequest, AuditSpooler};
use std::sync::Arc;
use std::time::Instant;

use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::counter::Counter;

// ─── Métricas de IA ──────────────────────────────────────────────────────────

/// Contenedor de las 3 métricas Prometheus de la capa de IA.
/// Se crea en axiom-node, se registra en el Registry global y se pasa
/// a build_app_state para que los handlers puedan emitirlas.
#[derive(Clone)]
pub struct AiMetrics {
    pub pdp_decision_total: Family<Vec<(String, String)>, Counter>,
    pub pdp_latency_seconds: Histogram,
}

// ─── Estado del servidor ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ZeroTrustEngine>,
    pub http_client: reqwest::Client,
    pub clickhouse_url: String,
    pub ai_metrics: AiMetrics,
}

// ─── Constructor ─────────────────────────────────────────────────────────────

pub async fn build_app_state(ai_metrics: AiMetrics) -> AppState {
    let policy = std::fs::read_to_string("../axiom-core/policies/zero_trust.rego")
        .expect("Failed to read zero_trust.rego policy file");
        
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    
    // Iniciar el Spooler en segundo plano con Redis como broker
    let log_path = std::path::PathBuf::from("./logs/audit.ndjson");
    let redis_url = "redis://redis:6379/".to_string();
    AuditSpooler::spawn(rx, redis_url, log_path);

    let engine = ZeroTrustEngine::new(&policy)
        .expect("Failed to initialize PDP Engine")
        .with_audit(tx);
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    let clickhouse_url = "http://clickhouse:8123/".to_string();
    
    AppState {
        engine: Arc::new(engine),
        http_client,
        clickhouse_url,
        ai_metrics,
    }
}

// ─── Handler: /v1/evaluate ───────────────────────────────────────────────────

pub async fn verify_request(
    State(state): State<AppState>,
    Json(payload): Json<ZeroTrustRequest>,
) -> Json<Decision> {
    let t_start = Instant::now();
    let final_decision = match state.engine.evaluate(&payload) {
        Ok(decision) => decision,
        Err(e) => {
            eprintln!("Evaluation error: {}", e);
            Decision {
                allow: false,
                requires_2fa: true,
                requires_biometric: true,
                block: true,
                alert: true,
            }
        }
    };

    // Registrar decisión de Rego en métricas
    let rego_decision = if !final_decision.allow {
        "DENY"
    } else if final_decision.requires_2fa {
        "CHALLENGE"
    } else {
        "ALLOW"
    };
    
    // Usamos pdp_decision_total como lo espera Grafana
    state.ai_metrics.pdp_decision_total
        .get_or_create(&vec![
            ("decision".to_string(), rego_decision.to_string()),
        ])
        .inc();
        
    // También registramos la latencia del PDP
    let latency_secs = t_start.elapsed().as_secs_f64();
    state.ai_metrics.pdp_latency_seconds.observe(latency_secs);
    
    // Además podemos mantener el de AI (que usa tags source=rego) si el dashboard lo usa
    // ya no lo mantenemos porque borramos decision_total

    Json(final_decision)
}

// ─── Tipos para anomaly_score_handler ────────────────────────────────────────

#[derive(Deserialize)]
pub struct AnomalyQuery {
    pub user: String,
}

#[derive(Serialize)]
pub struct AnomalyScore {
    pub anomaly_score: f64,
    pub baseline_mean: f64,
    pub std_dev: f64,
    pub is_outlier: bool,
    pub threshold: f64,
}

#[derive(Deserialize)]
struct ChStatsResponse {
    data: Vec<ChStatsRow>,
}

#[derive(Deserialize)]
struct ChStatsRow {
    mean: f64,
    var: f64,
    p99: f64,
}

#[derive(Deserialize)]
struct ChLatestResponse {
    data: Vec<ChLatestRow>,
}

#[derive(Deserialize)]
struct ChLatestRow {
    latency_ms: f64,
    distance_km: f64,
}

// ─── Handler: /v1/anomaly_score (estadístico) ────────────────────────────────

pub async fn anomaly_score_handler(
    State(state): State<AppState>,
    Query(query): Query<AnomalyQuery>,
) -> Json<AnomalyScore> {
    let user_did = query.user;
    
    // 1. Fetch baseline from MV
    let query_baseline = format!(
        "SELECT \
            avgMerge(latency_avg) as mean, \
            varSampMerge(latency_var) as var, \
            quantileMerge(0.99)(distance_p99) as p99 \
         FROM audit_events_1m \
         WHERE user_did = '{}' FORMAT JSON",
        user_did.replace('\'', "\\'")
    );

    let baseline_res = state.http_client.post(&state.clickhouse_url)
        .body(query_baseline)
        .send().await;
        
    let mut mean = 0.0;
    let mut std_dev = 0.0;
    let mut p99 = 0.0;
    
    if let Ok(res) = baseline_res {
        if let Ok(stats) = res.json::<ChStatsResponse>().await {
            if let Some(row) = stats.data.first() {
                mean = row.mean;
                std_dev = if row.var > 0.0 { row.var.sqrt() } else { 0.0 };
                p99 = row.p99;
            }
        }
    }

    // 2. Fetch latest event
    let query_latest = format!(
        "SELECT \
            latency_ms, \
            toFloat64OrZero(JSONExtractString(context['env'], 'distance_km')) as distance_km \
         FROM audit_events \
         WHERE user_did = '{}' \
         ORDER BY timestamp_ns DESC LIMIT 1 FORMAT JSON",
         user_did.replace('\'', "\\'")
    );

    let latest_res = state.http_client.post(&state.clickhouse_url)
        .body(query_latest)
        .send().await;

    let mut current_latency = 0.0;
    let mut current_distance = 0.0;

    if let Ok(res) = latest_res {
        if let Ok(latest) = res.json::<ChLatestResponse>().await {
            if let Some(row) = latest.data.first() {
                current_latency = row.latency_ms;
                current_distance = row.distance_km;
            }
        }
    }

    // 3. Compute Outlier logic
    let is_latency_outlier = std_dev > 0.0 && current_latency > (mean + 3.0 * std_dev);
    let is_distance_outlier = p99 > 0.0 && current_distance > p99;
    let is_outlier = is_latency_outlier || is_distance_outlier;
    
    let z_score = if std_dev > 0.0 { (current_latency - mean) / std_dev } else { 0.0 };
    let mut anomaly_score = if z_score > 0.0 { 1.0 - (1.0 / (1.0 + z_score)) } else { 0.0 };
    if is_distance_outlier { anomaly_score = 0.99; }

    Json(AnomalyScore {
        anomaly_score,
        baseline_mean: mean,
        std_dev,
        is_outlier,
        threshold: 0.7,
    })
}
