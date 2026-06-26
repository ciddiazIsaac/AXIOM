use crate::error::AxiomError;
use regorus::Engine;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;
use crate::pdp::audit::{AuditEvent, AuditDecision};

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
    audit_sender: Option<UnboundedSender<AuditEvent>>,
}

impl ZeroTrustEngine {
    /// Inicializa el motor PDP cargando la política Rego.
    pub fn new(rego_policy: &str) -> Result<Self, AxiomError> {
        let mut engine = Engine::new();
        engine.add_policy("zero_trust.rego".to_string(), rego_policy.to_string())
            .map_err(|e| AxiomError::InternalError(format!("Failed to compile Rego policy: {}", e)))?;
        Ok(Self { 
            base_engine: engine,
            audit_sender: None,
        })
    }

    /// Configura el canal para emitir eventos de auditoría (no bloqueante)
    pub fn with_audit(mut self, sender: UnboundedSender<AuditEvent>) -> Self {
        self.audit_sender = Some(sender);
        self
    }

    /// Evalúa la solicitud contra las políticas de Zero Trust
    pub fn evaluate(&self, request: &ZeroTrustRequest) -> Result<Decision, AxiomError> {
        let start_time = Instant::now();
        let mut engine = self.base_engine.clone();
        
        let input_json = serde_json::to_string(request)
            .map_err(|e| AxiomError::InternalError(format!("Failed to serialize input: {}", e)))?;
            
        let input_val = regorus::Value::from_json_str(&input_json)
            .map_err(|e| AxiomError::InternalError(format!("Failed to parse JSON for Rego: {}", e)))?;
            
        engine.set_input(input_val);
        
        let allow = Self::eval_bool(&mut engine, "data.axiom.pdp.allow")?;
        let requires_2fa = Self::eval_bool(&mut engine, "data.axiom.pdp.requires_2fa")?;
        let requires_biometric = Self::eval_bool(&mut engine, "data.axiom.pdp.requires_biometric")?;
        let block = Self::eval_bool(&mut engine, "data.axiom.pdp.block")?;
        let alert = Self::eval_bool(&mut engine, "data.axiom.pdp.alert")?;
        
        let decision_type = if block {
            AuditDecision::Deny
        } else if requires_2fa || requires_biometric {
            AuditDecision::Challenge
        } else if allow {
            AuditDecision::Allow
        } else {
            AuditDecision::Deny
        };

        // risk_score is loosely defined; using trust_score as a basis or calculating an arbitrary risk
        // For actual calculation, the policy could return it, but here we estimate it based on inputs
        let risk_score = 1.0 - request.device.trust_score;

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

    fn eval_bool(engine: &mut Engine, query: &str) -> Result<bool, AxiomError> {
        let results = engine.eval_query(query.to_string(), false)
            .map_err(|e| AxiomError::InternalError(format!("Query failed {}: {}", query, e)))?;
            
        let val = results.result.first().ok_or_else(|| {
            AxiomError::InternalError(format!("No result for {}", query))
        })?;
        
        let exprs = &val.expressions;
        if let Some(v) = exprs.first() {
            if let Ok(b) = v.value.as_bool() {
                return Ok(*b);
            }
        }
        
        Ok(false)
    }
}
