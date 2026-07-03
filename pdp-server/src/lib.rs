use axum::{
    extract::{State, Query},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use axiom_core::pdp::{Decision, ZeroTrustEngine, ZeroTrustRequest, AuditSpooler};
use axiom_core::ml::anomaly::AnomalyDetector;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ZeroTrustEngine>,
    pub http_client: reqwest::Client,
    pub clickhouse_url: String,
    pub anomaly_detector: Option<Arc<AnomalyDetector>>,
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
    
    // Carga de modelo ONNX con fallback inteligente
    let model_path = "../anomaly_model.onnx";
    let anomaly_detector = match AnomalyDetector::new(model_path) {
        Ok(detector) => {
            info!("Modelo ONNX cargado en el PDP.");
            Some(Arc::new(detector))
        }
        Err(e) => {
            warn!("Fallo al cargar el modelo ONNX desde {}: {}. Decadencia a estadísticas clásicas.", model_path, e);
            None
        }
    };

    AppState {
        engine: Arc::new(engine),
        http_client,
        clickhouse_url,
        anomaly_detector,
    }
}

pub async fn verify_request(
    State(state): State<AppState>,
    Json(payload): Json<ZeroTrustRequest>,
) -> Json<Decision> {
    // In a real scenario we'd handle errors properly and maybe return 403 or 400
    // But for fast evaluation we just unwrap or handle the error gracefully
    let mut final_decision = match state.engine.evaluate(&payload) {
        Ok(decision) => decision,
        Err(e) => {
            eprintln!("Evaluation error: {}", e);
            // Default deny on error
            Decision {
                allow: false,
                requires_2fa: true,
                requires_biometric: true,
                block: true,
                alert: true,
            }
        }
    };

    // Shadow Mode: Ejecutar la IA sin bloquear la decisión (Pruebas A/B)
    if let Some(detector) = &state.anomaly_detector {
        // Preparar características para la IA (6 características esperadas)
        // features = [latency_ms, risk_score, distance_km, hour_of_day, decision, device_trust_score]
        
        use chrono::Timelike;
        let hour_of_day = chrono::Utc::now().hour() as f32;
        let risk_score = 100.0 - (payload.device.trust_score * 100.0); // Aproximación
        let distance = payload.context.distance_km;
        
        let features = vec![
            50.0, // latency_ms (podríamos usar el tiempo real si lo medimos aquí)
            risk_score, 
            distance, 
            hour_of_day,
            if final_decision.allow { 0.0 } else { 1.0 }, // 0=ALLOW, 1=DENY
            payload.device.trust_score * 100.0
        ];
        
        if let Some(ai_score) = detector.predict(features) {
            let ai_decision = if ai_score > 0.8 {
                "DENY"
            } else if ai_score > 0.5 {
                "CHALLENGE"
            } else {
                "ALLOW"
            };
            
            let rego_decision = if !final_decision.allow { "DENY" } else if final_decision.requires_2fa { "CHALLENGE" } else { "ALLOW" };
            
            info!("Shadow Mode => Rego says {}, AI says {} (Score: {:.3})", rego_decision, ai_decision, ai_score);
            
            // Lógica híbrida real (COMENTADA HASTA VALIDAR EL SHADOW MODE):
            /*
            if ai_score > 0.8 || !final_decision.allow {
                final_decision.allow = false;
                final_decision.block = true;
            } else if ai_score > 0.5 {
                final_decision.requires_2fa = true;
                final_decision.allow = false;
            }
            */
        }
    }

    Json(final_decision)
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
    pub threshold: f64, // Umbral de decisión retornado
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
    
    let mut anomaly_score = 0.0;
    
    if let Some(detector) = &state.anomaly_detector {
        // Modo Predictivo con IA
        use chrono::Timelike;
        let hour_of_day = chrono::Utc::now().hour() as f32;
        let features = vec![
            current_latency as f32,
            50.0, // risk_score aproximado
            current_distance as f32,
            hour_of_day,
            0.0, // decision aproximada
            80.0, // device_trust_score aproximado
        ];
        
        if let Some(ai_score) = detector.predict(features) {
            anomaly_score = ai_score as f64;
        } else {
            // Fallback en caso de error interno del detector
            let z_score = if std_dev > 0.0 { (current_latency - mean) / std_dev } else { 0.0 };
            anomaly_score = if z_score > 0.0 { 1.0 - (1.0 / (1.0 + z_score)) } else { 0.0 };
            if is_distance_outlier {
                anomaly_score = 0.99;
            }
        }
    } else {
        // Fallback a Modo Estadístico (Z-Score)
        let z_score = if std_dev > 0.0 { (current_latency - mean) / std_dev } else { 0.0 };
        anomaly_score = if z_score > 0.0 { 1.0 - (1.0 / (1.0 + z_score)) } else { 0.0 };
        if is_distance_outlier {
            anomaly_score = 0.99;
        }
    }

    Json(AnomalyScore {
        anomaly_score,
        baseline_mean: mean,
        std_dev,
        is_outlier,
        threshold: 0.7, // Umbral fijo
    })
}
