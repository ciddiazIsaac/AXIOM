use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use tokio::fs::{create_dir_all, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::UnboundedReceiver;

/// Decisión final del PDP para propósitos de auditoría
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditDecision {
    /// Acceso permitido sin restricciones adicionales
    Allow,
    /// Acceso denegado explícitamente
    Deny,
    /// Se requiere algún tipo de verificación adicional (2FA, biometría, etc.)
    Challenge,
}

/// Esquema Áureo del Evento de Auditoría
/// Diseñado para alta cardinalidad y análisis posterior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Timestamp en nanosegundos (Unix epoch) para alta precisión
    pub timestamp_ns: u128,

    /// Identificador único de la sesión
    pub session_id: String,

    /// Identidad del usuario que realiza la petición (DID)
    pub user_did: String,

    /// Hash del recurso al que se intenta acceder
    pub resource_hash: String,

    /// Decisión final tomada por el motor Zero Trust
    pub decision: AuditDecision,

    /// Puntuación de riesgo calculada numéricamente
    pub risk_score: f32,

    /// Snapshot del contexto en el momento de la decisión (geo, dispositivo, hora)
    pub context_snapshot: Value,

    /// Latencia del motor PDP en milisegundos
    pub latency_ms: f64,
}

/// Construye la URL redis:// interna que el crate usa para el SentinelClient.
/// Soporta tanto `redis+sentinel://` (plano, dev) como
/// `rediss+sentinel://` (TLS, prod).
fn sentinel_node_url(redis_url: &str) -> String {
    // rediss+sentinel://host:port/master/db → rediss://host:port
    // redis+sentinel://host:port/master/db  → redis://host:port
    if redis_url.starts_with("rediss+sentinel://") {
        let stripped = redis_url.trim_start_matches("rediss+sentinel://");
        let host_port = stripped.split('/').next().unwrap_or(stripped);
        format!("rediss://{host_port}")
    } else {
        // redis+sentinel:// o redis+sentinel sin esquema
        let stripped = redis_url
            .trim_start_matches("redis+sentinel://")
            .trim_start_matches("redis://");
        let host_port = stripped.split('/').next().unwrap_or(stripped);
        format!("redis://{host_port}")
    }
}

/// Extrae el nombre del master de la URL Sentinel.
/// `redis+sentinel://host:port/mymaster/0` → `"mymaster"`
fn extract_master_name(redis_url: &str) -> &str {
    // Quitar esquema
    let after_scheme = redis_url
        .trim_start_matches("rediss+sentinel://")
        .trim_start_matches("redis+sentinel://");
    // after_scheme = "host:port/mymaster/0"
    let parts: Vec<&str> = after_scheme.split('/').collect();
    if parts.len() > 1 && !parts[1].is_empty() {
        parts[1]
    } else {
        "mymaster"
    }
}

// ─── Spooler ──────────────────────────────────────────────────────────────────

/// Spooler en segundo plano para persistir eventos de auditoría.
/// Escribe los eventos en Redis Streams (con TLS si REDIS_URL usa rediss://)
/// y cae en disco (NDJSON) si Redis no está disponible.
pub struct AuditSpooler;

impl AuditSpooler {
    /// Inicia el worker en segundo plano.
    /// Toma el receptor del canal asíncrono, la URL de Redis y la ruta base del archivo.
    pub fn spawn(
        mut receiver: UnboundedReceiver<AuditEvent>,
        redis_url: String,
        log_path: PathBuf,
    ) {
        tokio::spawn(async move {
            // 1. Preparar el fallback en disco (archivo NDJSON)
            if let Some(parent) = log_path.parent() {
                let _ = create_dir_all(parent).await;
            }

            let mut file_fallback = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .await
                .ok();

            // 2. Determinar si la URL es Sentinel y si usa TLS
            let is_sentinel = redis_url.starts_with("redis+sentinel://")
                || redis_url.starts_with("rediss+sentinel://");
            let use_tls =
                redis_url.starts_with("rediss://") || redis_url.starts_with("rediss+sentinel://");

            let mut sentinel_client_opt = None;
            let mut redis_client_opt = None;

            let mut redis_con = if is_sentinel {
                let node_url = sentinel_node_url(&redis_url);
                let master_name = extract_master_name(&redis_url).to_string();

                // Configurar TlsMode::Secure si el esquema es TLS
                let tls_params = if use_tls {
                    Some(
                        redis::sentinel::SentinelNodeConnectionInfo::default()
                            .set_tls_mode(redis::TlsMode::Secure),
                    )
                } else {
                    None
                };

                if let Ok(mut sentinel_client) = redis::sentinel::SentinelClient::build(
                    vec![node_url],
                    master_name,
                    tls_params,
                    redis::sentinel::SentinelServerType::Master,
                ) {
                    let con = sentinel_client.get_async_connection().await.ok();
                    sentinel_client_opt = Some(sentinel_client);
                    con
                } else {
                    None
                }
            } else {
                // Conexión directa (dev local sin Sentinel)
                if let Ok(redis_client) = redis::Client::open(redis_url.as_str()) {
                    let con = redis_client.get_multiplexed_async_connection().await.ok();
                    redis_client_opt = Some(redis_client);
                    con
                } else {
                    None
                }
            };

            // 3. Procesar eventos de la cola
            while let Some(event) = receiver.recv().await {
                if let Ok(json_string) = serde_json::to_string(&event) {
                    let mut sent_to_redis = false;

                    // Intentar enviar a Redis Streams
                    if let Some(con) = &mut redis_con {
                        let result: Result<(), redis::RedisError> = con
                            .xadd("axiom:audit:stream", "*", &[("data", &json_string)])
                            .await;

                        if let Err(e) = result {
                            if e.is_connection_dropped() || e.is_io_error() {
                                // Intentar reconectar una vez si la conexión se cae
                                if let Some(sentinel) = sentinel_client_opt.as_mut() {
                                    if let Ok(new_con) = sentinel.get_async_connection().await {
                                        redis_con = Some(new_con);
                                    }
                                } else if let Some(client) = redis_client_opt.as_ref() {
                                    if let Ok(new_con) =
                                        client.get_multiplexed_async_connection().await
                                    {
                                        redis_con = Some(new_con);
                                    }
                                }

                                // Reintentar xadd con la nueva conexión si tuvimos éxito
                                if let Some(new_con) = &mut redis_con {
                                    let retry_result: Result<(), redis::RedisError> = new_con
                                        .xadd("axiom:audit:stream", "*", &[("data", &json_string)])
                                        .await;
                                    if retry_result.is_ok() {
                                        sent_to_redis = true;
                                    }
                                }
                            }
                        } else {
                            sent_to_redis = true;
                        }
                    }

                    // Fallback a disco si Redis falló o no está disponible
                    if !sent_to_redis {
                        if let Some(f) = &mut file_fallback {
                            let log_entry = format!("{json_string}\n");
                            let _ = f.write_all(log_entry.as_bytes()).await;
                        }
                    }
                }
            }
        });
    }
}
