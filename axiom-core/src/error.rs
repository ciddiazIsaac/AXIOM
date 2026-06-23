//! Errores del crate axiom-core.

use thiserror::Error;

/// Tipo de error unificado para axiom-core.
#[derive(Debug, Error)]
pub enum AxiomError {
    /// Error al generar claves criptográficas.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Error de serialización/deserialización JSON.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Error de I/O al leer/escribir archivos de DID Documents.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// El DID proporcionado no es válido.
    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    /// El DID no fue encontrado en el almacén local.
    #[error("DID not found: {0}")]
    DidNotFound(String),

    /// El DID Document no cumple con la especificación W3C.
    #[error("Invalid DID Document: {0}")]
    InvalidDocument(String),

    /// Error en operación criptográfica.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Error de encoding/decoding (base64, multibase, etc.).
    #[error("Encoding error: {0}")]
    Encoding(String),
}
