//! Método DID `did:axiom` — Creación de identidades AXIOM.
//!
//! Implementa la operación CREATE del DID Method Registry W3C:
//! <https://www.w3.org/TR/did-spec-registries/>
//!
//! # Formato del DID
//! ```text
//! did:axiom:<fingerprint>
//! ```
//! donde `<fingerprint>` = multibase(base58btc, SHA-256(ed25519_public_key))

use chrono::Utc;

use crate::did::document::{
    DidDocument, Proof, Service, VerificationMethod,
    DID_CONTEXT_AXIOM, DID_CONTEXT_ED25519_2020, DID_CONTEXT_JWK_2020, DID_CONTEXT_V1,
};
use crate::error::AxiomError;
use crate::keys::HybridKeyPair;

/// Resultado de crear un DID AXIOM.
///
/// Contiene el DID Document público (serializable, compartible)
/// pero NO contiene ninguna referencia a las claves privadas.
#[derive(Debug)]
pub struct AxiomDid {
    /// El identificador DID completo (e.g., `did:axiom:z123...`).
    pub id: String,

    /// El DID Document público — seguro de serializar y almacenar.
    pub document: DidDocument,
}

impl AxiomDid {
    /// Crea un nuevo DID AXIOM desde un `HybridKeyPair`.
    ///
    /// # Proceso
    /// 1. Deriva el fingerprint DID desde la clave pública Ed25519
    /// 2. Construye el DID Document con dos `verificationMethod`:
    ///    - `#key-ed25519`: Ed25519VerificationKey2020 (para autenticación y firma)
    ///    - `#key-kyber`: JsonWebKey2020 con Kyber768 (para key agreement poscuántico)
    /// 3. Firma el documento con la clave Ed25519 del keypair
    /// 4. Valida la Regla de Oro antes de retornar
    ///
    /// # Regla de Oro
    /// La función NUNCA retorna ni serializa material de clave privada.
    /// Esto se verifica llamando a `document.assert_no_private_key_material()`
    /// antes de retornar.
    pub fn create(keypair: &HybridKeyPair) -> Result<Self, AxiomError> {
        let fingerprint = keypair.did_fingerprint();
        let did_id = format!("did:axiom:{}", fingerprint);
        let now = Utc::now().to_rfc3339();

        // --- Método de verificación Ed25519 ---
        let ed25519_vm_id = format!("{}#key-ed25519", did_id);
        let ed25519_vm = VerificationMethod {
            id: ed25519_vm_id.clone(),
            key_type: "Ed25519VerificationKey2020".to_string(),
            controller: did_id.clone(),
            public_key_multibase: Some(keypair.ed25519_public_key_multibase()),
            public_key_jwk: None,
        };

        // --- Método de verificación Kyber (Key Agreement poscuántico) ---
        let kyber_vm_id = format!("{}#key-kyber", did_id);
        let kyber_vm = VerificationMethod {
            id: kyber_vm_id.clone(),
            key_type: "JsonWebKey2020".to_string(),
            controller: did_id.clone(),
            public_key_multibase: None,
            public_key_jwk: Some(keypair.kyber_public_key_jwk()),
        };

        // --- Firma del documento (sobre el DID id + timestamp) ---
        let signing_payload = format!("{}|{}", did_id, now);
        let signature_bytes = keypair.sign(signing_payload.as_bytes());
        let proof_value = multibase::encode(
            multibase::Base::Base58Btc,
            &signature_bytes,
        );

        let proof = Proof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: now.clone(),
            verification_method: ed25519_vm_id.clone(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        };

        // --- Ensamblar el DID Document ---
        let document = DidDocument {
            context: vec![
                DID_CONTEXT_V1.to_string(),
                DID_CONTEXT_ED25519_2020.to_string(),
                DID_CONTEXT_JWK_2020.to_string(),
                DID_CONTEXT_AXIOM.to_string(),
            ],
            id: did_id.clone(),
            also_known_as: None,
            controller: Some(vec![did_id.clone()]),
            verification_method: vec![ed25519_vm, kyber_vm],
            authentication: vec![serde_json::json!(ed25519_vm_id)],
            key_agreement: vec![serde_json::json!(kyber_vm_id)],
            assertion_method: vec![serde_json::json!(ed25519_vm_id)],
            service: vec![],
            created: now.clone(),
            updated: now,
            proof: Some(proof),
        };

        // --- Validar W3C compliance ---
        document.validate()?;

        // --- REGLA DE ORO: Verificar que no hay material privado ---
        // Esta es la última línea de defensa antes de retornar el documento
        document.assert_no_private_key_material()?;

        Ok(Self {
            id: did_id,
            document,
        })
    }

    /// Serializa el DID Document a JSON-LD con formato legible.
    pub fn to_json_ld(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(&self.document).map_err(AxiomError::Serialization)
    }

    /// Guarda el DID Document en un archivo JSON en disco.
    ///
    /// El archivo se puede usar con `LocalResolver` para resolución sin red.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), AxiomError> {
        let json = self.to_json_ld()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Añade un servicio al DID Document.
    pub fn add_service(&mut self, service: Service) {
        self.document.service.push(service);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_did_from_keypair() {
        let kp = HybridKeyPair::generate();
        let did = AxiomDid::create(&kp).expect("Crear DID debe funcionar");
        assert!(did.id.starts_with("did:axiom:"));
    }

    #[test]
    fn created_did_is_deterministic_for_same_keypair() {
        // El mismo keypair siempre produce el mismo DID identifier
        // (aunque el timestamp cambie, el ID debe ser el mismo)
        let kp = HybridKeyPair::generate();
        let did1 = AxiomDid::create(&kp).expect("Primera creación");
        let did2 = AxiomDid::create(&kp).expect("Segunda creación");
        assert_eq!(
            did1.id, did2.id,
            "El DID identifier debe ser determinístico (derivado de la clave pública)"
        );
    }

    #[test]
    fn did_document_has_both_verification_methods() {
        let kp = HybridKeyPair::generate();
        let did = AxiomDid::create(&kp).expect("Crear DID");
        assert_eq!(
            did.document.verification_method.len(),
            2,
            "Debe haber exactamente 2 métodos de verificación: Ed25519 + Kyber"
        );

        let types: Vec<&str> = did
            .document
            .verification_method
            .iter()
            .map(|vm| vm.key_type.as_str())
            .collect();
        assert!(types.contains(&"Ed25519VerificationKey2020"));
        assert!(types.contains(&"JsonWebKey2020"));
    }

    #[test]
    fn did_document_has_proof() {
        let kp = HybridKeyPair::generate();
        let did = AxiomDid::create(&kp).expect("Crear DID");
        assert!(did.document.proof.is_some(), "El DID Document debe tener prueba de integridad");
        let proof = did.document.proof.as_ref().unwrap();
        assert_eq!(proof.proof_type, "Ed25519Signature2020");
    }

    #[test]
    fn did_document_w3c_contexts_present() {
        let kp = HybridKeyPair::generate();
        let did = AxiomDid::create(&kp).expect("Crear DID");
        assert!(did.document.context.contains(&DID_CONTEXT_V1.to_string()));
    }

    #[test]
    fn to_json_ld_produces_valid_json() {
        let kp = HybridKeyPair::generate();
        let did = AxiomDid::create(&kp).expect("Crear DID");
        let json = did.to_json_ld().expect("Serialización debe funcionar");
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("JSON debe ser válido");
        assert!(parsed["id"].is_string());
        assert!(parsed["@context"].is_array());
    }
}
