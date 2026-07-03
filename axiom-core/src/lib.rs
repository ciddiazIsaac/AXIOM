//! axiom-core — El Núcleo de Titanio
//!
//! Implementación del DID Method `did:axiom` siguiendo la especificación W3C DID Core 1.0.
//! Usa criptografía híbrida: Ed25519 (firma clásica) + CRYSTALS-Kyber ML-KEM-768 (poscuántico).
//!
//! # Regla de Oro
//! **La clave privada NUNCA abandona el dispositivo del usuario.**
//! - Las claves privadas no implementan `Serialize`
//! - Se zerorizan en memoria al salir de scope (`Zeroize + Drop`)
//! - El resolver es 100% local: solo lee archivos `.json` del filesystem
//!
//! # Uso básico
//! ```rust
//! use axiom_core::keys::HybridKeyPair;
//! use axiom_core::did::AxiomDid;
//!
//! // Generar identidad
//! let keypair = HybridKeyPair::generate();
//! let did = AxiomDid::create(&keypair).unwrap();
//!
//! // El DID Document es serializable — sin ningún material privado
//! let doc_json = serde_json::to_string_pretty(&did.document).unwrap();
//! println!("{}", doc_json);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![warn(clippy::pedantic)]

pub mod crypto;
pub mod did;
pub mod error;
pub mod keys;
pub mod pdp;
/// Módulo de Machine Learning para detección de anomalías
pub mod ml;

pub use error::AxiomError;
pub use keys::HybridKeyPair;
