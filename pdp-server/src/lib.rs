use axum::{
    extract::{State, Query},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use axiom_core::pdp::{Decision, ZeroTrustEngine, ZeroTrustRequest, AuditSpooler};
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ZeroTrustEngine>,
    pub http_client: reqwest::Client,
    pub clickhouse_url: String,
}

pub async fn build_app_state() -> AppState {
    let policy = std::fs::read_to_string("../axiom-core/policies/zero_trust.rego")
        .expect("Failed to read zero_trust.rego policy file");
        
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    
    // Iniciar el Spooler en segundo plano con Redis como broker
    let log_path = std::path::PathBuf::from("./logs/audit.ndjson");
    let redis_url = "redis://redis:6379/".to_string(); // updated to docker dns
    AuditSpooler::spawn(rx, redis_url, log_path);

    let engine = ZeroTrustEngine::new(&policy)
        .expect("Failed to initialize PDP Engine")
        .with_audit(tx);
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    let clickhouse_url = "http://clickhouse:8123/".to_string(); // updated to docker dns

    AppState {
        engine: Arc::new(engine),
        http_client,
        clickhouse_url,
    }
}

pub async fn verify_request(
    State(state): State<AppState>,
    Json(payload): Json<ZeroTrustRequest>,
) -> Json<Decision> {
    // In a real scenario we'd handle errors properly and maybe return 403 or 400
    // But for fast evaluation we just unwrap or handle the error gracefully
    match state.engine.evaluate(&payload) {
        Ok(decision) => Json(decision),
        Err(e) => {
            eprintln!("Evaluation error: {}", e);
            // Default deny on error
            Json(Decision {
                allow: false,
                requires_2fa: true,
                requires_biometric: true,
                block: true,
                alert: true,
            })
        }
    }
}

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
                // stddev is sqrt of variance
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
    // Calculation 1: Latency > mean + 3*std_dev
    let is_latency_outlier = std_dev > 0.0 && current_latency > (mean + 3.0 * std_dev);
    // Calculation 2: Distance > p99
    let is_distance_outlier = p99 > 0.0 && current_distance > p99;

    let is_outlier = is_latency_outlier || is_distance_outlier;
    
    // An arbitrary anomaly_score calculation just to return a float between 0 and 1
    // Using sigmoid-like over the Z-score for latency, or 1.0 if distance outlier
    let z_score = if std_dev > 0.0 { (current_latency - mean) / std_dev } else { 0.0 };
    let mut anomaly_score = if z_score > 0.0 { 1.0 - (1.0 / (1.0 + z_score)) } else { 0.0 };
    if is_distance_outlier {
        anomaly_score = 0.99; // Cap at 0.99 for distance outlier if not captured by Z-score
    }

    Json(AnomalyScore {
        anomaly_score,
        baseline_mean: mean,
        std_dev,
        is_outlier,
    })
}
