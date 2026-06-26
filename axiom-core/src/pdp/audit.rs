use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use tokio::fs::{OpenOptions, create_dir_all};
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

/// Spooler en segundo plano para persistir eventos de auditoría
/// Escribe los eventos en un archivo rotativo (NDJSON) sin bloquear el hilo principal.
pub struct AuditSpooler;

impl AuditSpooler {
    /// Inicia el worker en segundo plano.
    /// Toma el receptor del canal asíncrono y la ruta base del archivo.
    pub fn spawn(mut receiver: UnboundedReceiver<AuditEvent>, log_path: PathBuf) {
        tokio::spawn(async move {
            // Asegurarse de que el directorio padre exista
            if let Some(parent) = log_path.parent() {
                if let Err(e) = create_dir_all(parent).await {
                    eprintln!("AuditSpooler: Fallo al crear el directorio de logs {:?}: {}", parent, e);
                    return;
                }
            }

            let mut file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("AuditSpooler: Fallo al abrir el archivo de logs {:?}: {}", log_path, e);
                    return;
                }
            };

            while let Some(event) = receiver.recv().await {
                // Formatear el evento como NDJSON (Newline Delimited JSON)
                if let Ok(json_string) = serde_json::to_string(&event) {
                    let log_entry = format!("{}\n", json_string);
                    if let Err(e) = file.write_all(log_entry.as_bytes()).await {
                        eprintln!("AuditSpooler: Error al escribir el evento en disco: {}", e);
                    }
                }
            }
        });
    }
}
