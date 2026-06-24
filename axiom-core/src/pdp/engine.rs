use crate::error::AxiomError;
use regorus::Engine;
use serde::{Deserialize, Serialize};

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
}

/// Solicitud enviada al motor PDP para su evaluación
#[derive(Debug, Serialize, Deserialize)]
pub struct ZeroTrustRequest {
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
}

impl ZeroTrustEngine {
    /// Inicializa el motor PDP cargando la política Rego.
    pub fn new(rego_policy: &str) -> Result<Self, AxiomError> {
        let mut engine = Engine::new();
        engine.add_policy("zero_trust.rego".to_string(), rego_policy.to_string())
            .map_err(|e| AxiomError::InternalError(format!("Failed to compile Rego policy: {}", e)))?;
        Ok(Self { base_engine: engine })
    }

    /// Evalúa la solicitud contra las políticas de Zero Trust
    pub fn evaluate(&self, request: &ZeroTrustRequest) -> Result<Decision, AxiomError> {
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
