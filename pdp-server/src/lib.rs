use axum::{
    extract::{State, Query},
    Json,
};
use serde::{Deserialize, Serialize};
use axiom_core::pdp::{Decision, ZeroTrustEngine, ZeroTrustRequest, AuditSpooler};
use axiom_core::ml::anomaly::AnomalyDetector;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::counter::Counter;

// ─── Métricas de IA ──────────────────────────────────────────────────────────

/// Contenedor de las 3 métricas Prometheus de la capa de IA.
/// Se crea en axiom-node, se registra en el Registry global y se pasa
/// a build_app_state para que los handlers puedan emitirlas.
#[derive(Clone)]
pub struct AiMetrics {
    /// Histograma de scores de anomalía [0.0, 1.0]
    pub anomaly_score: Histogram,
    /// Contador de decisiones por fuente (ai/rego) y tipo (ALLOW/DENY/CHALLENGE)
    pub decision_total: Family<Vec<(String, String)>, Counter>,
    /// Duración de inferencia ONNX en segundos (objetivo < 10ms)
    pub inference_duration_seconds: Histogram,
}

// ─── Estado del servidor ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ZeroTrustEngine>,
    pub http_client: reqwest::Client,
    pub clickhouse_url: String,
    pub anomaly_detector: Arc<tokio::sync::RwLock<Option<Arc<AnomalyDetector>>>>,
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
    
    // Carga de modelo ONNX con fallback inteligente
    let model_path = "../anomaly_model.onnx";
    let detector_opt = match AnomalyDetector::new(model_path) {
        Ok(detector) => {
            info!("Modelo ONNX cargado en el PDP.");
            Some(Arc::new(detector))
        }
        Err(e) => {
            warn!("Fallo al cargar el modelo ONNX desde {}: {}. Decadencia a estadísticas clásicas.", model_path, e);
            None
        }
    };
    
    let anomaly_detector = Arc::new(tokio::sync::RwLock::new(detector_opt));
    
    // Spawn watcher para hot-reloading (Zero Downtime)
    let detector_state_clone = anomaly_detector.clone();
    let model_path_str = model_path.to_string();
    tokio::spawn(async move {
        use notify::{Watcher, RecursiveMode, EventKind};
        use std::sync::mpsc::channel;
        
        let (tx, rx) = channel();
        let mut watcher = match notify::recommended_watcher(tx) {
            Ok(w) => w,
            Err(e) => {
                warn!("Fallo al iniciar el observador de archivos (notify): {}", e);
                return;
            }
        };
        
        if let Err(e) = watcher.watch(std::path::Path::new(&model_path_str), RecursiveMode::NonRecursive) {
            warn!("No se pudo observar {}: {}", model_path_str, e);
            return;
        }
        
        info!("Observador de hot-reload iniciado para {}", model_path_str);
        
        tokio::task::spawn_blocking(move || {
            let _w = watcher;
            for res in rx {
                if let Ok(event) = res {
                    if let EventKind::Modify(_) = event.kind {
                        info!("Detectado cambio en {}, preparando hot-reload...", model_path_str);
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        
                        match AnomalyDetector::new(&model_path_str) {
                            Ok(new_detector) => {
                                let mut writer = detector_state_clone.blocking_write();
                                *writer = Some(Arc::new(new_detector));
                                info!("Modelo hot-reloaded exitosamente (Zero Downtime).");
                            }
                            Err(e) => {
                                tracing::error!("Fallo el hot-reload del modelo, manteniendo el anterior: {}", e);
                            }
                        }
                    }
                }
            }
        });
    });

    AppState {
        engine: Arc::new(engine),
        http_client,
        clickhouse_url,
        anomaly_detector,
        ai_metrics,
    }
}

// ─── Handler: /v1/evaluate ───────────────────────────────────────────────────

pub async fn verify_request(
    State(state): State<AppState>,
    Json(payload): Json<ZeroTrustRequest>,
) -> Json<Decision> {
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
    state.ai_metrics.decision_total
        .get_or_create(&vec![
            ("source".to_string(), "rego".to_string()),
            ("decision".to_string(), rego_decision.to_string()),
        ])
        .inc();

    // Shadow Mode: Ejecutar la IA, registrar métricas, no bloquear la decisión
    let detector_opt = state.anomaly_detector.read().await.clone();
    if let Some(detector) = detector_opt {
        use chrono::Timelike;
        let hour_of_day = chrono::Utc::now().hour() as f32;
        let risk_score = 100.0 - (payload.device.trust_score * 100.0);
        let distance = payload.context.distance_km;
        
        let features = vec![
            50.0, // latency_ms
            risk_score, 
            distance, 
            hour_of_day,
            if final_decision.allow { 0.0 } else { 1.0 },
            payload.device.trust_score * 100.0
        ];
        
        // ── Medir latencia de inferencia ──────────────────────────────────
        let t0 = Instant::now();
        if let Some(ai_score) = detector.predict(features).await {
            let inference_secs = t0.elapsed().as_secs_f64();

            // Emitir las 3 métricas de la IA
            state.ai_metrics.inference_duration_seconds.observe(inference_secs);
            state.ai_metrics.anomaly_score.observe(ai_score as f64);

            let ai_decision = if ai_score > 0.8 {
                "DENY"
            } else if ai_score > 0.5 {
                "CHALLENGE"
            } else {
                "ALLOW"
            };
            state.ai_metrics.decision_total
                .get_or_create(&vec![
                    ("source".to_string(), "ai".to_string()),
                    ("decision".to_string(), ai_decision.to_string()),
                ])
                .inc();

            info!(
                "Shadow Mode => Rego: {}, AI: {} (score={:.3}, latency={:.2}ms)",
                rego_decision, ai_decision, ai_score, inference_secs * 1000.0
            );

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
    
    let mut anomaly_score = 0.0;
    
    let detector_opt = state.anomaly_detector.read().await.clone();
    if let Some(detector) = detector_opt {
        use chrono::Timelike;
        let hour_of_day = chrono::Utc::now().hour() as f32;
        let features = vec![
            current_latency as f32,
            50.0,
            current_distance as f32,
            hour_of_day,
            0.0,
            80.0,
        ];
        
        if let Some(ai_score) = detector.predict(features).await {
            anomaly_score = ai_score as f64;
        } else {
            let z_score = if std_dev > 0.0 { (current_latency - mean) / std_dev } else { 0.0 };
            anomaly_score = if z_score > 0.0 { 1.0 - (1.0 / (1.0 + z_score)) } else { 0.0 };
            if is_distance_outlier { anomaly_score = 0.99; }
        }
    } else {
        let z_score = if std_dev > 0.0 { (current_latency - mean) / std_dev } else { 0.0 };
        anomaly_score = if z_score > 0.0 { 1.0 - (1.0 / (1.0 + z_score)) } else { 0.0 };
        if is_distance_outlier { anomaly_score = 0.99; }
    }

    Json(AnomalyScore {
        anomaly_score,
        baseline_mean: mean,
        std_dev,
        is_outlier,
        threshold: 0.7,
    })
}
