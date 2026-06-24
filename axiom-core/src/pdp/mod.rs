//! Policy Decision Point (PDP) para el motor Zero Trust.

/// Motor principal y estructuras de contexto
pub mod engine;

pub use engine::{ZeroTrustEngine, Decision, ZeroTrustRequest, DeviceContext, ResourceContext, EnvContext};
