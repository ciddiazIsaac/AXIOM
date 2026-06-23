//! DID Document — Estructura W3C DID Core 1.0.
//!
//! Implementa el DID Document en JSON-LD según:
//! <https://www.w3.org/TR/did-core/#did-documents>
//!
//! # Regla de Oro
//! `DidDocument` implementa `Serialize` pero SOLO contiene material público.
//! Ningún campo de este struct puede contener claves privadas.

use serde::{Deserialize, Serialize};

/// Contexto base para todos los DID Documents W3C.
pub const DID_CONTEXT_V1: &str = "https://www.w3.org/ns/did/v1";

/// Contexto W3C para claves de verificación Ed25519.
pub const DID_CONTEXT_ED25519_2020: &str =
    "https://w3id.org/security/suites/ed25519-2020/v1";

/// Contexto W3C para JSON Web Keys (usado para Kyber).
pub const DID_CONTEXT_JWK_2020: &str =
    "https://w3id.org/security/suites/jws-2020/v1";

/// Contexto específico del proyecto AXIOM.
pub const DID_CONTEXT_AXIOM: &str =
    "https://axiom.id/ns/v1";

/// Método de verificación en el DID Document.
///
/// Representa una clave pública asociada al DID, con el tipo y formato
/// especificados por la suite criptográfica usada.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// ID del método de verificación (e.g., `did:axiom:z123...#key-1`).
    pub id: String,

    /// Tipo de clave (e.g., `Ed25519VerificationKey2020`, `JsonWebKey2020`).
    #[serde(rename = "type")]
    pub key_type: String,

    /// DID del controlador de esta clave.
    pub controller: String,

    /// Clave pública en formato Multibase (base58btc para Ed25519).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,

    /// Clave pública en formato JWK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

/// Servicio declarado en el DID Document (endpoints, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// ID del servicio.
    pub id: String,

    /// Tipo de servicio.
    #[serde(rename = "type")]
    pub service_type: String,

    /// Endpoint del servicio.
    pub service_endpoint: serde_json::Value,
}

/// Prueba de integridad del DID Document (firma del creador).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    /// Tipo de prueba (e.g., `Ed25519Signature2020`).
    #[serde(rename = "type")]
    pub proof_type: String,

    /// Timestamp ISO 8601 de creación de la prueba.
    pub created: String,

    /// ID del método de verificación usado para firmar.
    pub verification_method: String,

    /// Propósito de la prueba (e.g., `assertionMethod`).
    pub proof_purpose: String,

    /// Valor de la firma en Multibase.
    pub proof_value: String,
}

/// DID Document completo siguiendo la especificación W3C DID Core 1.0.
///
/// # Invariante de Seguridad
/// Este struct implementa `Serialize` y es seguro de serializar a JSON —
/// todos sus campos son material público o metadatos. Ningún campo
/// puede contener claves privadas (esto es validado por tests).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// Contextos JSON-LD.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// Identificador DID (e.g., `did:axiom:z123...`).
    pub id: String,

    /// Alias para este DID (opcional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,

    /// DID que controla este documento (por defecto, el propio DID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Vec<String>>,

    /// Métodos de verificación (claves públicas).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub verification_method: Vec<VerificationMethod>,

    /// Métodos para autenticación.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<serde_json::Value>,

    /// Métodos para acuerdo de clave (KEM/DH).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub key_agreement: Vec<serde_json::Value>,

    /// Métodos para emission de credenciales verificables.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub assertion_method: Vec<serde_json::Value>,

    /// Servicios registrados (endpoints de comunicación, etc.).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub service: Vec<Service>,

    /// Timestamp de creación (ISO 8601).
    pub created: String,

    /// Timestamp de última actualización (ISO 8601).
    pub updated: String,

    /// Prueba criptográfica de integridad del documento.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl DidDocument {
    /// Valida que el DID Document cumple con los requisitos mínimos de W3C DID Core 1.0.
    ///
    /// # Validaciones
    /// - `id` comienza con `did:axiom:`
    /// - `@context` incluye el contexto base W3C
    /// - Al menos un método de verificación presente
    pub fn validate(&self) -> Result<(), crate::error::AxiomError> {
        if !self.id.starts_with("did:axiom:") {
            return Err(crate::error::AxiomError::InvalidDocument(
                format!("DID debe comenzar con 'did:axiom:', encontrado: '{}'", self.id)
            ));
        }

        if !self.context.contains(&DID_CONTEXT_V1.to_string()) {
            return Err(crate::error::AxiomError::InvalidDocument(
                "El contexto W3C DID v1 es obligatorio".to_string()
            ));
        }

        if self.verification_method.is_empty() {
            return Err(crate::error::AxiomError::InvalidDocument(
                "El DID Document debe tener al menos un método de verificación".to_string()
            ));
        }

        Ok(())
    }

    /// Verifica que el DID Document NO contiene ningún material de clave privada.
    ///
    /// Esta es la implementación runtime de la Regla de Oro.
    /// Se buscan patrones conocidos de claves privadas en la serialización JSON.
    pub fn assert_no_private_key_material(&self) -> Result<(), crate::error::AxiomError> {
        let json_str = serde_json::to_string(self)
            .map_err(|e| crate::error::AxiomError::Serialization(e))?;

        // Patrones que indican presencia de material privado
        let private_key_patterns = [
            "\"d\":",         // JWK campo 'd' = clave privada
            "privateKey",
            "private_key",
            "secretKey",
            "secret_key",
            "signingKey",
            "signing_key",
        ];

        for pattern in &private_key_patterns {
            if json_str.contains(pattern) {
                return Err(crate::error::AxiomError::InvalidDocument(
                    format!(
                        "VIOLACIÓN DE REGLA DE ORO: El DID Document contiene material privado: '{}'",
                        pattern
                    )
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_document() -> DidDocument {
        DidDocument {
            context: vec![DID_CONTEXT_V1.to_string()],
            id: "did:axiom:z123test".to_string(),
            also_known_as: None,
            controller: None,
            verification_method: vec![VerificationMethod {
                id: "did:axiom:z123test#key-1".to_string(),
                key_type: "Ed25519VerificationKey2020".to_string(),
                controller: "did:axiom:z123test".to_string(),
                public_key_multibase: Some("zABCDEF".to_string()),
                public_key_jwk: None,
            }],
            authentication: vec![serde_json::json!("did:axiom:z123test#key-1")],
            key_agreement: vec![],
            assertion_method: vec![],
            service: vec![],
            created: "2024-01-01T00:00:00Z".to_string(),
            updated: "2024-01-01T00:00:00Z".to_string(),
            proof: None,
        }
    }

    #[test]
    fn valid_document_passes_validation() {
        let doc = make_minimal_document();
        assert!(doc.validate().is_ok());
    }

    #[test]
    fn invalid_did_prefix_fails() {
        let mut doc = make_minimal_document();
        doc.id = "did:web:example.com".to_string();
        assert!(doc.validate().is_err());
    }

    #[test]
    fn missing_context_fails() {
        let mut doc = make_minimal_document();
        doc.context = vec!["https://example.com".to_string()];
        assert!(doc.validate().is_err());
    }

    #[test]
    fn document_round_trips_through_json() {
        let doc = make_minimal_document();
        let json = serde_json::to_string(&doc).expect("Serialización debe funcionar");
        let restored: DidDocument = serde_json::from_str(&json).expect("Deserialización debe funcionar");
        assert_eq!(doc, restored);
    }

    #[test]
    fn document_has_no_private_key_material() {
        let doc = make_minimal_document();
        assert!(
            doc.assert_no_private_key_material().is_ok(),
            "El DID Document no debe contener material privado"
        );
    }
}
