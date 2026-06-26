use serde::{Deserialize, Serialize};
use serde_json::Value;

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
