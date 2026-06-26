use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use tokio::fs::{OpenOptions, create_dir_all};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::UnboundedReceiver;
use redis::AsyncCommands;

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

/// Spooler en segundo plano para persistir eventos de auditoría
/// Escribe los eventos en un archivo rotativo (NDJSON) sin bloquear el hilo principal.
pub struct AuditSpooler;

impl AuditSpooler {
    /// Inicia el worker en segundo plano.
    /// Toma el receptor del canal asíncrono, la URL de Redis y la ruta base del archivo.
    pub fn spawn(mut receiver: UnboundedReceiver<AuditEvent>, redis_url: String, log_path: PathBuf) {
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

            // 2. Preparar el cliente de Redis
            let client = redis::Client::open(redis_url).ok();
            let mut redis_con = if let Some(ref c) = client {
                c.get_multiplexed_async_connection().await.ok()
            } else {
                None
            };

            // 3. Procesar eventos de la cola
            while let Some(event) = receiver.recv().await {
                if let Ok(json_string) = serde_json::to_string(&event) {
                    let mut sent_to_redis = false;

                    // Intentar enviar a Redis Streams
                    if let Some(con) = &mut redis_con {
                        let result: Result<(), redis::RedisError> = con.xadd(
                            "axiom:audit:stream",
                            "*",
                            &[("data", &json_string)]
                        ).await;

                        if result.is_ok() {
                            sent_to_redis = true;
                        } else {
                            // Intentar reconectar si hubo un error (broker caído temporalmente)
                            if let Some(client) = &client {
                                if let Ok(new_con) = client.get_multiplexed_async_connection().await {
                                    *con = new_con;
                                    let retry: Result<(), redis::RedisError> = con.xadd(
                                        "axiom:audit:stream",
                                        "*",
                                        &[("data", &json_string)]
                                    ).await;
                                    
                                    if retry.is_ok() {
                                        sent_to_redis = true;
                                    }
                                }
                            }
                        }
                    }

                    // Fallback a disco si Redis falló o no está disponible
                    if !sent_to_redis {
                        if let Some(f) = &mut file_fallback {
                            let log_entry = format!("{}\n", json_string);
                            let _ = f.write_all(log_entry.as_bytes()).await;
                        }
                    }
                }
            }
        });
    }
}
