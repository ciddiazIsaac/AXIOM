//! Tests de integración: validación completa del DID Document W3C.

use axiom_core::did::AxiomDid;
use axiom_core::HybridKeyPair;

#[test]
fn did_document_has_required_w3c_fields() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");
    let doc = &did.document;

    // Campos obligatorios según W3C DID Core 1.0
    assert!(!doc.id.is_empty(), "id es obligatorio");
    assert!(!doc.context.is_empty(), "@context es obligatorio");
    assert!(
        !doc.verification_method.is_empty(),
        "verificationMethod es obligatorio"
    );
    assert!(!doc.created.is_empty(), "created es obligatorio");
    assert!(!doc.updated.is_empty(), "updated es obligatorio");
}

#[test]
fn did_document_has_correct_json_ld_contexts() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");
    let doc = &did.document;

    // El contexto base W3C es OBLIGATORIO
    assert!(
        doc.context
            .contains(&"https://www.w3.org/ns/did/v1".to_string()),
        "El contexto W3C DID v1 es obligatorio"
    );
}

#[test]
fn did_document_ed25519_verification_method_is_valid() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    let ed25519_vm = did
        .document
        .verification_method
        .iter()
        .find(|vm| vm.key_type == "Ed25519VerificationKey2020")
        .expect("Debe existir un método Ed25519");

    // ID debe referenciar el DID padre
    assert!(ed25519_vm.id.starts_with(&did.id));
    assert!(ed25519_vm.id.contains("#key-ed25519"));

    // Debe tener publicKeyMultibase
    let multibase = ed25519_vm
        .public_key_multibase
        .as_ref()
        .expect("Ed25519 debe tener publicKeyMultibase");

    // Multibase base58btc comienza con 'z'
    assert!(
        multibase.starts_with('z'),
        "publicKeyMultibase debe usar base58btc (prefijo 'z')"
    );

    // NO debe tener clave privada JWK
    if let Some(jwk) = &ed25519_vm.public_key_jwk {
        assert!(
            jwk.get("d").is_none(),
            "JWK no debe contener clave privada 'd'"
        );
    }
}

#[test]
fn did_document_kyber_verification_method_is_valid() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    let kyber_vm = did
        .document
        .verification_method
        .iter()
        .find(|vm| vm.key_type == "JsonWebKey2020")
        .expect("Debe existir un método Kyber JsonWebKey2020");

    assert!(kyber_vm.id.starts_with(&did.id));
    assert!(kyber_vm.id.contains("#key-kyber"));

    let jwk = kyber_vm
        .public_key_jwk
        .as_ref()
        .expect("Kyber debe tener publicKeyJwk");

    assert_eq!(jwk["kty"], "PQK", "Kyber debe usar kty='PQK'");
    assert_eq!(jwk["crv"], "Kyber768");
    assert!(jwk["x"].is_string(), "La clave pública debe estar en 'x'");

    // CRÍTICO: No debe haber campo 'd' (clave privada)
    assert!(
        jwk.get("d").is_none(),
        "VIOLACIÓN: El JWK Kyber contiene el campo 'd' (clave privada)"
    );
}

#[test]
fn did_document_authentication_references_ed25519() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    assert!(
        !did.document.authentication.is_empty(),
        "authentication no debe estar vacío"
    );

    // La autenticación debe referenciar la clave Ed25519
    let auth_str = serde_json::to_string(&did.document.authentication).expect("Serializar");
    assert!(
        auth_str.contains("key-ed25519"),
        "authentication debe referenciar la clave Ed25519"
    );
}

#[test]
fn did_document_key_agreement_references_kyber() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    assert!(
        !did.document.key_agreement.is_empty(),
        "keyAgreement no debe estar vacío (Kyber para key exchange poscuántico)"
    );

    let ka_str = serde_json::to_string(&did.document.key_agreement).expect("Serializar");
    assert!(
        ka_str.contains("key-kyber"),
        "keyAgreement debe referenciar la clave Kyber"
    );
}

#[test]
fn did_document_proof_is_ed25519_signature() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    let proof = did.document.proof.as_ref().expect("Debe haber proof");

    assert_eq!(proof.proof_type, "Ed25519Signature2020");
    assert_eq!(proof.proof_purpose, "assertionMethod");
    assert!(!proof.proof_value.is_empty());
    assert!(
        proof.proof_value.starts_with('z'),
        "El proof_value debe estar en multibase base58btc (prefijo 'z')"
    );
}

#[test]
fn did_document_passes_w3c_validation() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    assert!(
        did.document.validate().is_ok(),
        "El DID Document debe pasar la validación W3C"
    );
}

#[test]
fn did_document_json_ld_is_parseable() {
    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    let json_ld = did.to_json_ld().expect("Serializar a JSON-LD");
    let parsed: serde_json::Value =
        serde_json::from_str(&json_ld).expect("El JSON-LD debe ser JSON válido");

    assert_eq!(parsed["id"], did.id);
    assert!(parsed["@context"].is_array());
    assert!(parsed["verificationMethod"].is_array());
}

#[test]
fn save_and_reload_did_document() {
    use tempfile::tempdir;

    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    let temp = tempdir().expect("tmpdir");
    let file_path = temp.path().join("test_did.json");

    did.save_to_file(&file_path).expect("Guardar DID Document");

    // Recargar desde disco
    let json = std::fs::read_to_string(&file_path).expect("Leer archivo");
    let reloaded: axiom_core::did::DidDocument =
        serde_json::from_str(&json).expect("Deserializar DID Document guardado");

    assert_eq!(did.document, reloaded);
}
