use crate::error::AxiomError;
use crate::pdp::audit::{AuditDecision, AuditEvent};
use regorus::Engine;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

/// Estructura de decisión devuelta por el PDP
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Decision {
    /// Indica si se permite el acceso general
    pub allow: bool,
    /// Indica si se requiere verificación en dos pasos (2FA)
    pub requires_2fa: bool,
    /// Indica si se requiere firma biométrica del dispositivo
    pub requires_biometric: bool,
    /// Indica si la petición fue explícitamente bloqueada (ej. imposible travel)
    pub block: bool,
    /// Indica si se debe generar una alerta de seguridad
    pub alert: bool,
}

/// Contexto sobre el dispositivo que origina la petición
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceContext {
    /// Puntuación de confianza del dispositivo (0.0 a 1.0)
    pub trust_score: f32,
    /// Identificador único del dispositivo
    pub id: String,
}

/// Contexto ambiental de la petición (distancia precalculada)
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvContext {
    /// Distancia en kilómetros desde el último login
    pub distance_km: f32,
    /// Diferencia de tiempo en minutos desde el último login
    pub time_delta_mins: f32,
    /// Score de anomalía previamente calculado (opcional)
    pub anomaly_score: Option<f32>,
}

/// Contexto sobre el recurso solicitado
#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceContext {
    /// Nombre o identificador del recurso
    pub name: String,
    /// Hash criptográfico del recurso solicitado
    pub hash: String,
}

/// Solicitud enviada al motor PDP para su evaluación
#[derive(Debug, Serialize, Deserialize)]
pub struct ZeroTrustRequest {
    /// Identificador único de la sesión
    pub session_id: String,
    /// Identidad del usuario que solicita acceso
    pub user_did: String,
    /// Datos del dispositivo
    pub device: DeviceContext,
    /// Datos del entorno / geolocalización
    pub context: EnvContext,
    /// Datos del recurso
    pub resource: ResourceContext,
}

/// Motor Zero Trust embebido
///
/// Se encarga de evaluar las peticiones contra las políticas de Rego.
#[derive(Clone)]
pub struct ZeroTrustEngine {
    base_engine: Engine,
    pool: std::sync::Arc<std::sync::Mutex<Vec<Engine>>>,
    audit_sender: Option<UnboundedSender<AuditEvent>>,
}

impl ZeroTrustEngine {
    /// Inicializa el motor PDP cargando la política Rego.
    pub fn new(rego_policy: &str) -> Result<Self, AxiomError> {
        let mut engine = Engine::new();
        engine
            .add_policy("zero_trust.rego".to_string(), rego_policy.to_string())
            .map_err(|e| {
                AxiomError::InternalError(format!("Failed to compile Rego policy: {e}"))
            })?;
        Ok(Self {
            base_engine: engine,
            pool: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            audit_sender: None,
        })
    }

    /// Configura el canal para emitir eventos de auditoría (no bloqueante)
    #[must_use]
    pub fn with_audit(mut self, sender: UnboundedSender<AuditEvent>) -> Self {
        self.audit_sender = Some(sender);
        self
    }

    /// Evalúa la solicitud contra las políticas de Zero Trust
    pub fn evaluate(&self, request: &ZeroTrustRequest) -> Result<Decision, AxiomError> {
        let start_time = Instant::now();

        let mut engine = {
            let mut pool = self
                .pool
                .lock()
                .map_err(|e| AxiomError::InternalError(format!("Mutex poisoned: {e}")))?;
            pool.pop().unwrap_or_else(|| self.base_engine.clone())
        };

        let input_json = serde_json::to_string(request)
            .map_err(|e| AxiomError::InternalError(format!("Failed to serialize input: {e}")))?;

        let input_val = regorus::Value::from_json_str(&input_json).map_err(|e| {
            AxiomError::InternalError(format!("Failed to parse JSON for Rego: {e}"))
        })?;

        engine.set_input(input_val);

        let results = engine
            .eval_query("data.axiom.pdp".to_string(), false)
            .map_err(|e| AxiomError::InternalError(format!("Query failed: {e}")))?;

        // Regresamos el engine al pool inmediatamente
        {
            let mut pool = self
                .pool
                .lock()
                .map_err(|e| AxiomError::InternalError(format!("Mutex poisoned: {e}")))?;
            pool.push(engine);
        }

        let val = results
            .result
            .first()
            .ok_or_else(|| AxiomError::InternalError("No result for data.axiom.pdp".to_string()))?;

        let exprs = &val.expressions;
        let pdp_obj = if let Some(v) = exprs.first() {
            serde_json::to_value(&v.value).unwrap_or(serde_json::Value::Null)
        } else {
            serde_json::Value::Null
        };

        let allow = pdp_obj
            .get("allow")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let requires_2fa = pdp_obj
            .get("requires_2fa")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let requires_biometric = pdp_obj
            .get("requires_biometric")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let block = pdp_obj
            .get("block")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let alert = pdp_obj
            .get("alert")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let decision_type = if block {
            AuditDecision::Deny
        } else if requires_2fa || requires_biometric {
            AuditDecision::Challenge
        } else if allow {
            AuditDecision::Allow
        } else {
            AuditDecision::Deny
        };

        // Calculamos el riesgo base invertido a partir del trust score
        let mut risk_score = 1.0 - request.device.trust_score;

        // Calculamos la geo-velocidad (km/min)
        let geo_velocity = if request.context.time_delta_mins > 0.0 {
            request.context.distance_km / request.context.time_delta_mins
        } else if request.context.distance_km > 0.0 {
            9999.0 // Viaje instantáneo imposible
        } else {
            0.0
        };

        // Penalización si viaja a más de ~900 km/h (15 km/min)
        if geo_velocity > 15.0 {
            risk_score += 0.5;
        }

        // Incorporar el score de anomalía si está presente
        if let Some(anomaly) = request.context.anomaly_score {
            risk_score += anomaly * 0.3;
        }

        let risk_score = risk_score.clamp(0.0, 1.0);

        let latency = start_time.elapsed();
        let latency_ms = latency.as_secs_f64() * 1000.0;

        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        if let Some(sender) = &self.audit_sender {
            let context_snapshot = serde_json::json!({
                "env": request.context,
                "device": { "id": request.device.id },
            });

            let event = AuditEvent {
                timestamp_ns,
                session_id: request.session_id.clone(),
                user_did: request.user_did.clone(),
                resource_hash: request.resource.hash.clone(),
                decision: decision_type,
                risk_score,
                context_snapshot,
                latency_ms,
            };

            // Fire and forget (sin ralentizar la decisión)
            let _ = sender.send(event);
        }

        Ok(Decision {
            allow,
            requires_2fa,
            requires_biometric,
            block,
            alert,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const REGO_POLICY: &str = include_str!("../../policies/zero_trust.rego");

    fn make_base_request() -> ZeroTrustRequest {
        ZeroTrustRequest {
            session_id: "test_sess".to_string(),
            user_did: "did:axiom:test".to_string(),
            device: DeviceContext {
                trust_score: 0.9,
                id: "dev-1".to_string(),
            },
            context: EnvContext {
                distance_km: 10.0,
                time_delta_mins: 60.0,
                anomaly_score: None,
            },
            resource: ResourceContext {
                name: "Document".to_string(),
                hash: "hash".to_string(),
            },
        }
    }

    #[test]
    fn test_default_allow() {
        let engine = ZeroTrustEngine::new(REGO_POLICY).unwrap();
        let req = make_base_request();
        let dec = engine.evaluate(&req).unwrap();

        assert!(dec.allow);
        assert!(!dec.requires_2fa);
        assert!(!dec.requires_biometric);
        assert!(!dec.block);
        assert!(!dec.alert);
    }

    #[test]
    fn test_low_trust_score_requires_2fa() {
        let engine = ZeroTrustEngine::new(REGO_POLICY).unwrap();
        let mut req = make_base_request();
        req.device.trust_score = 0.5; // < 0.7 triggers Rule 1
        let dec = engine.evaluate(&req).unwrap();

        assert!(dec.allow);
        assert!(dec.requires_2fa);
        assert!(!dec.block);
    }

    #[test]
    fn test_impossible_travel_blocks_and_alerts() {
        let engine = ZeroTrustEngine::new(REGO_POLICY).unwrap();
        let mut req = make_base_request();
        req.context.distance_km = 1500.0; // > 1000
        req.context.time_delta_mins = 5.0; // < 10
        let dec = engine.evaluate(&req).unwrap();

        assert!(!dec.allow); // Block overrides allow in the policy
        assert!(dec.block);
        assert!(dec.alert);
    }

    #[test]
    fn test_admin_resource_requires_biometric() {
        let engine = ZeroTrustEngine::new(REGO_POLICY).unwrap();
        let mut req = make_base_request();
        req.resource.name = "Admin".to_string(); // triggers Rule 3
        let dec = engine.evaluate(&req).unwrap();

        assert!(dec.allow);
        assert!(dec.requires_biometric);
    }
}
