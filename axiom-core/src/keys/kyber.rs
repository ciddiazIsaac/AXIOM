//! Par de claves CRYSTALS-Kyber (ML-KEM-768) para encapsulamiento poscuántico.
//!
//! Kyber es el estándar NIST PQC para Key Encapsulation Mechanism (KEM).
//! ML-KEM-768 ofrece seguridad equivalente a AES-192 contra ataques cuánticos.
//!
//! # Regla de Oro — Confinamiento de Clave Privada
//! - `secret_key` es `pub(super)` — invisible fuera del módulo `keys`
//! - `SecretKey` no implementa `Serialize` — imposible volcar a JSON
//! - El `SharedSecret` producido por `decapsulate` es `SecureBytes` (zeroize on drop)

use pqcrypto_kyber::kyber768::{
    decapsulate, encapsulate, keypair, Ciphertext, PublicKey, SecretKey,
};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

use crate::crypto::SecureBytes;
use crate::error::AxiomError;

/// Par de claves Kyber ML-KEM-768.
///
/// La clave secreta (`secret_key`) nunca se expone fuera del módulo `keys`.
pub struct KyberKeyPair {
    /// Clave secreta de Kyber. `pub(super)` — solo accesible en el módulo `keys`.
    /// NO implementa `Serialize`.
    pub(super) secret_key: SecretKey,

    /// Clave pública de Kyber. Puede compartirse libremente.
    pub(super) public_key: PublicKey,
}

impl KyberKeyPair {
    /// Genera un nuevo par de claves ML-KEM-768 usando el CSPRNG del sistema.
    pub fn generate() -> Self {
        let (public_key, secret_key) = keypair();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Retorna los bytes crudos de la clave pública (1184 bytes para Kyber768).
    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Encapsula un secreto compartido usando la clave pública de este par.
    ///
    /// Retorna `(ciphertext_bytes, shared_secret)`.
    /// El `shared_secret` es un `SecureBytes` que se zeriza al hacer drop.
    ///
    /// # Uso típico
    /// El remitente (que solo tiene la clave pública) llama a `encapsulate`,
    /// envía el ciphertext al destinatario, y ambos derivan el mismo shared_secret.
    pub fn encapsulate(&self) -> (Vec<u8>, SecureBytes) {
        let (shared_secret, ciphertext) = encapsulate(&self.public_key);
        (
            ciphertext.as_bytes().to_vec(),
            SecureBytes::new(shared_secret.as_bytes().to_vec()),
        )
    }

    /// Decapsula un ciphertext y recupera el secreto compartido.
    ///
    /// # Errores
    /// Retorna `AxiomError::Crypto` si el ciphertext es inválido o tiene longitud incorrecta.
    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Result<SecureBytes, AxiomError> {
        let ct = Ciphertext::from_bytes(ciphertext_bytes).map_err(|_| {
            AxiomError::Crypto("Invalid Kyber ciphertext length".to_string())
        })?;
        let shared_secret = decapsulate(&ct, &self.secret_key);
        Ok(SecureBytes::new(shared_secret.as_bytes().to_vec()))
    }

    /// Retorna la clave pública en formato JWK (representación AXIOM extendida).
    ///
    /// Nota: Kyber no tiene una representación JWK estándar aún (pendiente IETF).
    /// Usamos una extensión provisional con `kty: "PQK"` y `crv: "Kyber768"`.
    pub fn public_key_jwk(&self) -> serde_json::Value {
        let pub_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            self.public_key.as_bytes(),
        );
        serde_json::json!({
            "kty": "PQK",
            "crv": "Kyber768",
            "x": pub_b64,
            "alg": "KYBER768"
        })
    }

    /// Retorna la clave pública codificada en Multibase (base64url, prefijo 'u').
    pub fn public_key_multibase(&self) -> String {
        multibase::encode(multibase::Base::Base64Url, self.public_key.as_bytes())
    }
}

/// `Debug` redactado — la clave secreta nunca aparece en logs.
impl std::fmt::Debug for KyberKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KyberKeyPair")
            .field(
                "public_key",
                &format!("[{} bytes]", self.public_key.as_bytes().len()),
            )
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_kyber_keypair() {
        let kp = KyberKeyPair::generate();
        // Kyber768 public key = 1184 bytes
        assert_eq!(kp.public_key_bytes().len(), 1184);
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let kp = KyberKeyPair::generate();
        let (ciphertext, shared_secret_enc) = kp.encapsulate();
        let shared_secret_dec = kp.decapsulate(&ciphertext).expect("Decapsulation must succeed");

        // Ambas partes deben tener el mismo secreto compartido
        assert_eq!(
            shared_secret_enc.as_bytes(),
            shared_secret_dec.as_bytes(),
            "El secreto compartido debe ser idéntico en encapsulador y decapsulador"
        );
    }

    #[test]
    fn debug_does_not_expose_secret_key() {
        let kp = KyberKeyPair::generate();
        let debug_str = format!("{:?}", kp);
        assert!(debug_str.contains("[REDACTED]"));
        // La clave secreta Kyber768 tiene 2400 bytes — no deben aparecer en debug
        assert!(!debug_str.contains("2400"));
    }

    #[test]
    fn jwk_has_correct_pqk_structure() {
        let kp = KyberKeyPair::generate();
        let jwk = kp.public_key_jwk();
        assert_eq!(jwk["kty"], "PQK");
        assert_eq!(jwk["crv"], "Kyber768");
        assert_eq!(jwk["alg"], "KYBER768");
        assert!(jwk["x"].is_string());
        // No debe contener clave privada
        assert!(jwk.get("d").is_none());
    }

    #[test]
    fn invalid_ciphertext_returns_error() {
        let kp = KyberKeyPair::generate();
        let result = kp.decapsulate(&[0u8; 10]); // longitud incorrecta
        assert!(result.is_err());
    }
}
