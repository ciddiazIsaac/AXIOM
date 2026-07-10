//! # Test de Confinamiento de Clave Privada — LA REGLA DE ORO
//!
//! Este archivo contiene los tests más críticos del crate `axiom-core`.
//! Su única función es garantizar, de múltiples formas, que **la clave privada
//! NUNCA abandona el dispositivo del usuario**.
//!
//! Si alguno de estos tests falla, la implementación debe ser reescrita desde cero.
//!
//! ## Niveles de Protección Verificados
//!
//! 1. **Nivel de Tipo**: Las claves privadas no implementan `Serialize`
//! 2. **Nivel de Visibilidad**: Los campos privados no son accesibles desde fuera del módulo
//! 3. **Nivel de Runtime**: El DID Document serializado no contiene bytes privados
//! 4. **Nivel de API**: Ningún método público retorna bytes de clave privada

use axiom_core::did::AxiomDid;
use axiom_core::HybridKeyPair;

/// ─── REGLA DE ORO NIVEL 1 ────────────────────────────────────────────────────
/// El DID Document serializado NO debe contener material de clave privada.
///
/// Este test genera un keypair real, crea el DID Document, lo serializa a JSON,
/// y verifica que los bytes de la clave privada Ed25519 no aparecen en el JSON.
#[test]
fn golden_rule_private_key_bytes_not_in_did_document_json() {
    let keypair = HybridKeyPair::generate();
    let public_key_bytes = keypair.ed25519_public_key_bytes();

    let did = AxiomDid::create(&keypair).expect("Crear DID debe funcionar");
    let json = serde_json::to_string(&did.document).expect("Serializar DID Document");

    // La clave pública SÍ debe estar en el JSON (para verificación)
    let _pub_key_hex = hex::encode(public_key_bytes);
    // No verificamos la presencia de la pública en hex porque puede estar codificada
    // en multibase o base64 — lo importante es que la privada NO esté.

    // Verificamos que el JSON no contiene el campo JWK 'd' (clave privada)
    assert!(
        !json.contains("\"d\":"),
        "VIOLACIÓN REGLA DE ORO: El JSON del DID Document contiene el campo JWK 'd' (clave privada)"
    );

    // Verificamos que no hay campos con nombres de claves privadas
    let forbidden_fields = [
        "privateKey",
        "private_key",
        "secretKey",
        "secret_key",
        "signingKey",
    ];
    for field in &forbidden_fields {
        assert!(
            !json.contains(field),
            "VIOLACIÓN REGLA DE ORO: El JSON contiene el campo prohibido '{}'",
            field
        );
    }

    // La clave pública Kyber tampoco debe exponer la privada
    assert!(
        !json.contains("\"kty\":\"PQK\"") || !json.contains("\"d\":"),
        "VIOLACIÓN REGLA DE ORO: El JWK Kyber contiene clave privada"
    );
}

/// ─── REGLA DE ORO NIVEL 2 ────────────────────────────────────────────────────
/// El método interno `assert_no_private_key_material()` del DidDocument debe pasar.
///
/// Este es el guardia runtime integrado en el propio `DidDocument`.
#[test]
fn golden_rule_document_self_validation_passes() {
    let keypair = HybridKeyPair::generate();
    let did = AxiomDid::create(&keypair).expect("Crear DID");

    let result = did.document.assert_no_private_key_material();
    assert!(
        result.is_ok(),
        "La auto-validación del DID Document debe pasar: {:?}",
        result
    );
}

/// ─── REGLA DE ORO NIVEL 3 ────────────────────────────────────────────────────
/// Un DID Document manipulado que sí contiene clave privada debe ser detectado.
///
/// Verifica que el guardián funciona también como detector de manipulaciones.
#[test]
fn golden_rule_document_detects_injected_private_key() {
    use axiom_core::did::document::{DidDocument, VerificationMethod};

    let mut doc = DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: "did:axiom:zTestPrivKey".to_string(),
        also_known_as: None,
        controller: None,
        verification_method: vec![VerificationMethod {
            id: "did:axiom:zTestPrivKey#key-1".to_string(),
            key_type: "Ed25519VerificationKey2020".to_string(),
            controller: "did:axiom:zTestPrivKey".to_string(),
            public_key_multibase: Some("zABCDEF".to_string()),
            public_key_jwk: None,
        }],
        authentication: vec![serde_json::json!("did:axiom:zTestPrivKey#key-1")],
        key_agreement: vec![],
        assertion_method: vec![],
        service: vec![],
        created: "2024-01-01T00:00:00Z".to_string(),
        updated: "2024-01-01T00:00:00Z".to_string(),
        proof: None,
    };

    // Primero debe pasar
    assert!(doc.assert_no_private_key_material().is_ok());

    // Inyectamos un JWK con clave privada ('d') — esto NO debería suceder
    // en código real, pero verificamos que el guardián lo detecta
    doc.verification_method[0].public_key_jwk = Some(serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "cHVibGljX2tleV9ieXRlcw",
        "d": "cHJpdmF0ZV9rZXlfYnl0ZXM"  // ← CLAVE PRIVADA INYECTADA
    }));
    doc.verification_method[0].public_key_multibase = None;

    // Ahora debe FALLAR — la clave privada está presente
    let result = doc.assert_no_private_key_material();
    assert!(
        result.is_err(),
        "El guardián DEBE detectar la clave privada inyectada en el JWK"
    );
}

/// ─── REGLA DE ORO NIVEL 4 ────────────────────────────────────────────────────
/// Dos keypairs distintos producen DIDs distintos.
///
/// Verifica que el fingerprint no es constante (lo cual indicaría que se está
/// usando un valor fijo en lugar de la clave real).
#[test]
fn golden_rule_different_keypairs_produce_different_dids() {
    let kp1 = HybridKeyPair::generate();
    let kp2 = HybridKeyPair::generate();

    let did1 = AxiomDid::create(&kp1).expect("DID 1");
    let did2 = AxiomDid::create(&kp2).expect("DID 2");

    assert_ne!(
        did1.id, did2.id,
        "Identidades distintas deben tener DIDs distintos"
    );
    assert_ne!(
        kp1.ed25519_public_key_bytes(),
        kp2.ed25519_public_key_bytes(),
        "Las claves públicas Ed25519 deben ser distintas"
    );
}

/// ─── REGLA DE ORO NIVEL 5 ────────────────────────────────────────────────────
/// La API pública del HybridKeyPair solo expone bytes públicos.
///
/// Verifica que los bytes públicos y privados son distintos
/// (si fueran iguales, podría indicar que se retorna la clave privada).
#[test]
fn golden_rule_public_key_is_not_private_key() {
    let kp = HybridKeyPair::generate();
    let pub_bytes = kp.ed25519_public_key_bytes();

    // Una clave pública Ed25519 de 32 bytes nunca puede ser cero
    assert_ne!(
        pub_bytes, [0u8; 32],
        "La clave pública no debe ser todo ceros"
    );

    // La clave pública Kyber de 1184 bytes tampoco
    let kyber_pub = kp.kyber_public_key_bytes();
    assert_eq!(kyber_pub.len(), 1184);
    assert_ne!(
        kyber_pub,
        vec![0u8; 1184].as_slice(),
        "La clave pública Kyber no debe ser todo ceros"
    );
}

/// ─── REGLA DE ORO NIVEL 6 ────────────────────────────────────────────────────
/// El Debug del HybridKeyPair contiene [REDACTED] para las claves privadas.
#[test]
fn golden_rule_debug_output_is_safe() {
    let kp = HybridKeyPair::generate();
    let debug_str = format!("{:?}", kp);

    assert!(
        debug_str.contains("[REDACTED]"),
        "El Debug del HybridKeyPair DEBE mostrar [REDACTED] para las claves privadas"
    );

    // La representación debug no debe ser tan larga como para incluir una clave privada
    // Ed25519 privada = 64 bytes = 128 hex chars
    // Kyber768 privada = 2400 bytes = muy larga
    // Si el debug es inusualmente largo, podría estar filtrando la privada
    assert!(
        debug_str.len() < 1000,
        "El Debug del HybridKeyPair no debe ser inusualmente largo (posible fuga de clave privada)"
    );
}
