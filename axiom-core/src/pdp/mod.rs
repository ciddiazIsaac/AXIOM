//! Policy Decision Point (PDP) para el motor Zero Trust.

/// Motor principal y estructuras de contexto
pub mod engine;
/// Módulo para la instrumentación y auditoría del PDP
pub mod audit;

pub use engine::{ZeroTrustEngine, Decision, ZeroTrustRequest, DeviceContext, ResourceContext, EnvContext};
pub use audit::{AuditEvent, AuditDecision, AuditSpooler};
