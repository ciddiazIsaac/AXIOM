//! axiom-analytics: Servidor HTTP con el endpoint /anomaly_score
//!
//! GET /anomaly_score?user_did=<did>&window=<segundos>&metric=<métrica>
//!
//! Parámetros:
//!   - user_did  (requerido): DID del usuario a analizar
//!   - window    (opcional, default 300): ventana temporal en segundos
//!   - metric    (opcional, default avg_latency): avg_latency | deny_rate | geo_velocity
//!
//! La respuesta incluye el z-score y un anomaly_score normalizado en [0,1].

mod clickhouse;
mod metrics;

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::clickhouse::ClickHouseClient;
use crate::metrics::{compute_anomaly, AnomalyResult, Metric};

// ─── Estado compartido ────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    ch: Arc<ClickHouseClient>,
}

// ─── Parámetros de la query string ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AnomalyParams {
    /// DID del usuario a analizar (requerido)
    user_did: String,
    /// Ventana temporal en segundos (default: 300 = 5 minutos)
    #[serde(default = "default_window")]
    window: u32,
    /// Métrica a calcular (default: avg_latency)
    #[serde(default = "default_metric")]
    metric: String,
}

fn default_window() -> u32 {
    300
}

fn default_metric() -> String {
    "avg_latency".to_string()
}

// ─── Respuesta de error ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ─── Handler ──────────────────────────────────────────────────────────────────

/// GET /anomaly_score
async fn anomaly_score(
    State(state): State<AppState>,
    Query(params): Query<AnomalyParams>,
) -> Result<Json<AnomalyResult>, (StatusCode, Json<ErrorResponse>)> {
    // Validar user_did
    if params.user_did.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "El parámetro 'user_did' es requerido y no puede estar vacío.".into(),
            }),
        ));
    }

    // Validar ventana
    if params.window == 0 || params.window > 86_400 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "El parámetro 'window' debe estar entre 1 y 86400 segundos.".into(),
            }),
        ));
    }

    // Parsear la métrica
    let metric: Metric = params.metric.parse().map_err(|e: anyhow::Error| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    info!(
        user_did = %params.user_did,
        window = params.window,
        metric = %metric,
        "Calculando anomaly_score..."
    );

    // Calcular el score
    match compute_anomaly(&state.ch, &params.user_did, params.window, &metric).await {
        Ok(result) => {
            info!(
                user_did = %result.user_did,
                z_score = result.z_score,
                anomaly_score = result.anomaly_score,
                is_anomaly = result.is_anomaly,
                event_count = result.event_count,
                "anomaly_score calculado."
            );
            Ok(Json(result))
        }
        Err(e) => {
            error!("Error calculando anomaly_score para {}: {e}", params.user_did);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Error interno al calcular anomaly_score: {e}"),
                }),
            ))
        }
    }
}

/// GET /health — health check simple
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "axiom-analytics" }))
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("axiom_analytics=info,warn")
        .init();

    let ch_url = std::env::var("CLICKHOUSE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8123/".to_string());
    let bind_addr = std::env::var("ANALYTICS_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_string());

    info!("Iniciando axiom-analytics...");
    info!("ClickHouse: {ch_url}");
    info!("Bind: {bind_addr}");

    let state = AppState {
        ch: Arc::new(ClickHouseClient::new(ch_url)),
    };

    let app = Router::new()
        .route("/anomaly_score", get(anomaly_score))
        .route("/health", get(health))
        .with_state(state);

    let listener = TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("No se puede escuchar en {bind_addr}: {e}"));

    info!("axiom-analytics en http://{bind_addr}");
    axum::serve(listener, app).await.unwrap();
}
