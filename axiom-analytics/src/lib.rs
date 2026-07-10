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

pub mod clickhouse;
pub mod metrics;

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};

use tracing::{error, info};

use crate::clickhouse::ClickHouseClient;
use crate::metrics::{compute_anomaly, AnomalyResult, Metric};

// ─── Estado compartido ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub ch: Arc<ClickHouseClient>,
}

// ─── Parámetros de la query string ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AnomalyParams {
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
pub struct ErrorResponse {
    pub error: String,
}

// ─── Handler ──────────────────────────────────────────────────────────────────

/// GET /anomaly_score
pub async fn anomaly_score(
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
            error!(
                "Error calculando anomaly_score para {}: {e}",
                params.user_did
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Error interno al calcular anomaly_score: {e}"),
                }),
            ))
        }
    }
}
