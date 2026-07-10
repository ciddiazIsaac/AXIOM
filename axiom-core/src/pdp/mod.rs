//! Policy Decision Point (PDP) para el motor Zero Trust.

/// Módulo para la instrumentación y auditoría del PDP
pub mod audit;
/// Motor principal y estructuras de contexto
pub mod engine;

pub use audit::{AuditDecision, AuditEvent, AuditSpooler};
pub use engine::{
    Decision, DeviceContext, EnvContext, ResourceContext, ZeroTrustEngine, ZeroTrustRequest,
};
