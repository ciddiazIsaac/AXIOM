//! Par de claves Ed25519 para firma digital.
//!
//! # Regla de Oro — Confinamiento de Clave Privada
//! - `signing_key` es `pub(super)` — invisible fuera del módulo `keys`
//! - `SigningKey` NO implementa `Serialize` — imposible serializar a JSON
//! - `Ed25519KeyPair` implementa `ZeroizeOnDrop` — clave privada borrada de RAM al drop
//! - `Debug` y `Display` muestran solo la clave pública

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::ZeroizeOnDrop;

/// Par de claves Ed25519.
///
/// La clave privada (`signing_key`) es completamente privada al módulo
/// y se zeriza automáticamente en memoria al hacer `Drop`.
#[derive(ZeroizeOnDrop)]
pub struct Ed25519KeyPair {
    /// Clave de firma privada. `pub(super)` — solo accesible dentro del módulo `keys`.
    /// NUNCA serializable — `SigningKey` no implementa `serde::Serialize`.
    pub(super) signing_key: SigningKey,

    /// Clave de verificación pública. Esta sí puede ser compartida libremente.
    #[zeroize(skip)]
    pub(super) verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Genera un nuevo par de claves Ed25519 usando el CSPRNG del sistema operativo.
    ///
    /// Usa `OsRng` que en Windows delega a `BCryptGenRandom` (FIPS 140-2 aprobado).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Firma un mensaje y retorna la firma Ed25519 (64 bytes).
    ///
    /// La clave privada permanece en memoria — solo se produce la firma.
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message)
    }

    /// Retorna los bytes crudos de la clave pública (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Retorna la clave pública codificada en Multibase (base58btc, prefijo 'z').
    ///
    /// Este es el formato estándar para `publicKeyMultibase` en DID Documents W3C.
    pub fn public_key_multibase(&self) -> String {
        // Prefijo 0xed01 indica Ed25519 en Multicodec
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&self.verifying_key.to_bytes());
        multibase::encode(multibase::Base::Base58Btc, &prefixed)
    }

    /// Retorna la representación JWK de la clave pública (OKP, crv: Ed25519).
    ///
    /// Compatible con la especificación `JsonWebKey2020` del W3C DID.
    pub fn public_key_jwk(&self) -> serde_json::Value {
        let x_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            self.verifying_key.to_bytes(),
        );
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64
        })
    }
}

/// `Debug` solo muestra la clave pública — la privada es `[REDACTED]`.
impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("verifying_key", &hex::encode(self.verifying_key.to_bytes()))
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn generate_and_sign_verify() {
        let kp = Ed25519KeyPair::generate();
        let msg = b"axiom identity proof";
        let sig = kp.sign(msg);
        // La verificación debe funcionar con la clave pública
        assert!(kp.verifying_key.verify(msg, &sig).is_ok());
    }

    #[test]
    fn public_key_bytes_length() {
        let kp = Ed25519KeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    #[test]
    fn multibase_starts_with_z() {
        let kp = Ed25519KeyPair::generate();
        let mb = kp.public_key_multibase();
        assert!(mb.starts_with('z'), "Multibase base58btc debe comenzar con 'z'");
    }

    #[test]
    fn debug_does_not_expose_private_key() {
        let kp = Ed25519KeyPair::generate();
        let debug_str = format!("{:?}", kp);
        assert!(
            debug_str.contains("[REDACTED]"),
            "Debug no debe exponer la clave privada"
        );
    }

    #[test]
    fn jwk_has_correct_structure() {
        let kp = Ed25519KeyPair::generate();
        let jwk = kp.public_key_jwk();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert!(jwk["x"].is_string());
        // JWK no debe contener 'd' (clave privada en JWK)
        assert!(jwk.get("d").is_none(), "JWK no debe contener clave privada 'd'");
    }
}
