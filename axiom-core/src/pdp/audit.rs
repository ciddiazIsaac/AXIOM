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

use rusqlite::Connection;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Estado de la máquina de estados del Spooler de auditoría
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SpoolerState {
    /// Operación normal, eventos se mandan a Redis
    Normal = 0,
    /// Redis inalcanzable, encolando localmente (Fail-Open)
    Degraded = 1,
    /// Riesgo de agotar buffer, se deniega tráfico (Fail-Closed)
    Panic = 2,
}

// ─── Spooler ──────────────────────────────────────────────────────────────────

/// Spooler en segundo plano para persistir eventos de auditoría.
pub struct AuditSpooler;

impl AuditSpooler {
    /// Inicia el worker en segundo plano.
    pub fn spawn(
        mut receiver: tokio::sync::mpsc::UnboundedReceiver<AuditEvent>,
        redis_url: String,
        db_path: std::path::PathBuf,
    ) -> Arc<AtomicU8> {
        // Inicializar estado asumiendo Degradado, o Pánico si el disco/buffer ya superó los límites.
        // Esto cierra la ventana de vulnerabilidad en el reinicio del pod.
        let mut initial_state = 1; // 1: Degraded (Fail-Open until Redis connection is proven)
        if let Ok(m) = std::fs::metadata(&db_path) {
            if m.len() > 900 * 1024 * 1024 {
                initial_state = 2; // Panic por disco lleno
            } else if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                let count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM audit_buffer", [], |row| row.get(0))
                    .unwrap_or(0);
                if count >= 10_000 {
                    initial_state = 2; // Panic por límite de eventos
                }
            }
        }

        let state = Arc::new(AtomicU8::new(initial_state));
        let state_clone = state.clone();

        tokio::spawn(async move {
            // 1. Preparar SQLite buffer
            if let Some(parent) = db_path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            let conn = Connection::open(&db_path).expect("Failed to open audit buffer");
            conn.execute(
                "CREATE TABLE IF NOT EXISTS audit_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    data TEXT NOT NULL
                )",
                [],
            )
            .expect("Failed to create table");

            let mut redis_con = None;
            let mut sentinel_client_opt = None;
            let mut redis_client_opt = None;

            // 2. Determinar si la URL es Sentinel y TLS
            let is_sentinel = redis_url.starts_with("redis+sentinel://")
                || redis_url.starts_with("rediss+sentinel://");
            let use_tls =
                redis_url.starts_with("rediss://") || redis_url.starts_with("rediss+sentinel://");

            if is_sentinel {
                let node_url = super::audit::sentinel_node_url(&redis_url);
                let master_name = super::audit::extract_master_name(&redis_url);
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
                    redis_con = sentinel_client.get_async_connection().await.ok();
                    sentinel_client_opt = Some(sentinel_client);
                }
            } else {
                if let Ok(redis_client) = redis::Client::open(redis_url.as_str()) {
                    redis_con = redis_client.get_multiplexed_async_connection().await.ok();
                    redis_client_opt = Some(redis_client);
                }
            }

            let mut disconnected_since: Option<Instant> = if redis_con.is_none() {
                Some(Instant::now())
            } else {
                None
            };
            let mut connected_since: Option<Instant> = if redis_con.is_some() {
                Some(Instant::now())
            } else {
                None
            };

            // 3. Loop principal
            while let Some(event) = receiver.recv().await {
                let json_string = match serde_json::to_string(&event) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let mut sent_to_redis = false;

                if let Some(con) = &mut redis_con {
                    let result: Result<(), redis::RedisError> = con
                        .xadd("axiom:audit:stream", "*", &[("data", &json_string)])
                        .await;

                    if let Err(e) = result {
                        if e.is_connection_dropped() || e.is_io_error() {
                            let mut new_con_opt = None;
                            if let Some(sentinel) = sentinel_client_opt.as_mut() {
                                new_con_opt = sentinel.get_async_connection().await.ok();
                            } else if let Some(client) = redis_client_opt.as_ref() {
                                new_con_opt = client.get_multiplexed_async_connection().await.ok();
                            }

                            redis_con = new_con_opt;

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

                if sent_to_redis {
                    if connected_since.is_none() {
                        connected_since = Some(Instant::now());
                    }
                    disconnected_since = None;
                } else {
                    if disconnected_since.is_none() {
                        disconnected_since = Some(Instant::now());
                    }
                    connected_since = None;
                }

                if !sent_to_redis {
                    let is_panic = event
                        .context_snapshot
                        .get("denied_by_panic_mode")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if is_panic {
                        let panic_log_path = db_path.with_file_name("panic_denials.ndjson");
                        if let Ok(mut file) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&panic_log_path)
                        {
                            // Límite duro de 50MB para el log de rescate. Si se llena, perdemos el registro detallado
                            // pero el pod no crashea (las métricas pdp_decision_total = DENY seguirán subiendo).
                            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
                            if size < 50 * 1024 * 1024 {
                                use std::io::Write;
                                let _ = writeln!(file, "{}", json_string);
                            }
                        }
                    } else {
                        let _ = conn.execute(
                            "INSERT INTO audit_buffer (data) VALUES (?1)",
                            rusqlite::params![json_string],
                        );
                    }
                }

                // Evaluar la Máquina de Estados
                let count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM audit_buffer", [], |row| row.get(0))
                    .unwrap_or(0);
                let current_state = state_clone.load(Ordering::SeqCst);

                let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
                let disk_full = db_size > 900 * 1024 * 1024; // Limite seguro antes de agotar 1Gi

                if current_state == 2 {
                    let is_stable = connected_since
                        .map(|t| t.elapsed() >= Duration::from_secs(30))
                        .unwrap_or(false);
                    if count < 2000 && is_stable && !disk_full {
                        state_clone.store(if count > 0 { 1 } else { 0 }, Ordering::SeqCst);
                    }
                } else {
                    let time_exceeded = disconnected_since
                        .map(|t| t.elapsed() >= Duration::from_secs(300))
                        .unwrap_or(false);
                    if count >= 10_000 || time_exceeded || disk_full {
                        state_clone.store(2, Ordering::SeqCst);
                    } else if count > 0 || disconnected_since.is_some() {
                        state_clone.store(1, Ordering::SeqCst);
                    } else {
                        state_clone.store(0, Ordering::SeqCst);
                    }
                }

                // Flush pending events if connected
                if sent_to_redis && count > 0 {
                    let pending: Vec<(i64, String)> = {
                        let mut stmt = conn
                            .prepare("SELECT id, data FROM audit_buffer ORDER BY id ASC LIMIT 50")
                            .unwrap_or_else(|_| panic!("Failed to prepare"));
                        let rows = stmt
                            .query_map([], |row| {
                                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                            })
                            .unwrap_or_else(|_| panic!("Failed to query_map"));
                        rows.filter_map(Result::ok).collect()
                    };

                    for (id, data) in pending {
                        if let Some(con) = &mut redis_con {
                            let result: Result<(), redis::RedisError> = con
                                .xadd("axiom:audit:stream", "*", &[("data", &data)])
                                .await;

                            if result.is_ok() {
                                let _ = conn.execute(
                                    "DELETE FROM audit_buffer WHERE id = ?1",
                                    rusqlite::params![id],
                                );
                            } else {
                                break; // Paramos el flush si vuelve a fallar
                            }
                        }
                    }
                }
            }
        });

        state
    }
}
