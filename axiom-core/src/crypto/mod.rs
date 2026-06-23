//! Módulo de criptografía auxiliar.
//!
//! Proporciona utilidades de borrado seguro de memoria para material criptográfico sensible.

pub mod secure_memory;

pub use secure_memory::SecureBytes;
