//! Módulo de gestión de claves criptográficas.
//!
//! Expone tres tipos de claves:
//! - [`Ed25519KeyPair`] — firma digital clásica (ECDSA seguro)
//! - [`KyberKeyPair`] — encapsulamiento poscuántico (ML-KEM-768 / CRYSTALS-Kyber)
//! - [`HybridKeyPair`] — par híbrido Ed25519 + Kyber para identidad AXIOM

pub mod ed25519;
pub mod hybrid;
pub mod kyber;

pub use ed25519::Ed25519KeyPair;
pub use hybrid::HybridKeyPair;
pub use kyber::KyberKeyPair;
