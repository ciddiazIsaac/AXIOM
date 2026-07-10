//! Par de claves híbrido: Ed25519 + CRYSTALS-Kyber ML-KEM-768.
//!
//! `HybridKeyPair` es la unidad atómica de identidad en AXIOM.
//! Combina la firma rápida de Ed25519 con el encapsulamiento poscuántico de Kyber,
//! siguiendo el esquema híbrido recomendado por el NIST y el IETF.
//!
//! # Regla de Oro — El Invariante Fundamental
//! La API pública de `HybridKeyPair` SOLO expone material público.
//! Las claves privadas son `pub(super)` y NO implementan `Serialize`.
//! Ninguna función pública retorna bytes de clave privada.

use crate::error::AxiomError;
use crate::keys::{Ed25519KeyPair, KyberKeyPair};

/// Par de claves híbrido para identidad AXIOM.
///
/// Agrupa Ed25519 (firma) + Kyber (KEM poscuántico) en una sola unidad.
/// El identificador DID se deriva del fingerprint de la clave pública Ed25519.
pub struct HybridKeyPair {
    /// Claves Ed25519 — para firma y autenticación.
    pub(super) ed25519: Ed25519KeyPair,

    /// Claves Kyber ML-KEM-768 — para key agreement poscuántico.
    pub(super) kyber: KyberKeyPair,
}

impl HybridKeyPair {
    /// Genera un nuevo par de claves híbrido.
    ///
    /// Ambos pares (Ed25519 y Kyber) se generan usando `OsRng` del sistema.
    /// La operación es atómica: o se generan ambos o ninguno.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            ed25519: Ed25519KeyPair::generate(),
            kyber: KyberKeyPair::generate(),
        }
    }

    // =========================================================================
    // API PÚBLICA — Solo claves públicas más allá de este punto
    // =========================================================================

    /// Retorna los bytes de la clave pública Ed25519 (32 bytes).
    #[must_use]
    pub fn ed25519_public_key_bytes(&self) -> [u8; 32] {
        self.ed25519.public_key_bytes()
    }

    /// Retorna la clave pública Ed25519 en formato Multibase (base58btc, prefijo 'z').
    #[must_use]
    pub fn ed25519_public_key_multibase(&self) -> String {
        self.ed25519.public_key_multibase()
    }

    /// Retorna la clave pública Ed25519 en formato JWK.
    #[must_use]
    pub fn ed25519_public_key_jwk(&self) -> serde_json::Value {
        self.ed25519.public_key_jwk()
    }

    /// Retorna los bytes de la clave pública Kyber (1184 bytes para ML-KEM-768).
    #[must_use]
    pub fn kyber_public_key_bytes(&self) -> &[u8] {
        self.kyber.public_key_bytes()
    }

    /// Retorna la clave pública Kyber en formato JWK extendido (kty: "PQK").
    #[must_use]
    pub fn kyber_public_key_jwk(&self) -> serde_json::Value {
        self.kyber.public_key_jwk()
    }

    /// Retorna la clave pública Kyber en formato Multibase.
    #[must_use]
    pub fn kyber_public_key_multibase(&self) -> String {
        self.kyber.public_key_multibase()
    }

    /// Firma un mensaje con la clave Ed25519.
    ///
    /// La clave privada permanece en memoria y nunca es retornada.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.ed25519.sign(message).to_bytes().to_vec()
    }

    /// Encapsula un secreto compartido con la clave pública Kyber.
    #[must_use]
    pub fn kyber_encapsulate(&self) -> (Vec<u8>, crate::crypto::SecureBytes) {
        self.kyber.encapsulate()
    }

    /// Decapsula un ciphertext Kyber.
    pub fn kyber_decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<crate::crypto::SecureBytes, AxiomError> {
        self.kyber.decapsulate(ciphertext)
    }

    /// Genera el fingerprint DID: SHA-256 de la clave pública Ed25519,
    /// codificado en base58btc (multibase 'z').
    ///
    /// Este fingerprint es el identificador único del DID `did:axiom:<fingerprint>`.
    #[must_use]
    pub fn did_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.ed25519.public_key_bytes());
        let hash = hasher.finalize();
        // Codificamos el hash en base58btc para el DID identifier
        multibase::encode(multibase::Base::Base58Btc, &hash[..])
    }
}

/// `Debug` muestra solo info pública.
impl std::fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKeyPair")
            .field(
                "ed25519_public",
                &hex::encode(self.ed25519.public_key_bytes()),
            )
            .field("kyber_public_len", &self.kyber.public_key_bytes().len())
            .field("private_keys", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_hybrid_keypair() {
        let kp = HybridKeyPair::generate();
        assert_eq!(kp.ed25519_public_key_bytes().len(), 32);
        assert_eq!(kp.kyber_public_key_bytes().len(), 1184);
    }

    #[test]
    fn did_fingerprint_is_deterministic() {
        let kp = HybridKeyPair::generate();
        // El mismo keypair siempre produce el mismo fingerprint
        assert_eq!(kp.did_fingerprint(), kp.did_fingerprint());
    }

    #[test]
    fn did_fingerprint_differs_between_keypairs() {
        let kp1 = HybridKeyPair::generate();
        let kp2 = HybridKeyPair::generate();
        assert_ne!(
            kp1.did_fingerprint(),
            kp2.did_fingerprint(),
            "Dos identidades distintas deben tener fingerprints distintos"
        );
    }

    #[test]
    fn hybrid_sign_produces_valid_bytes() {
        let kp = HybridKeyPair::generate();
        let sig = kp.sign(b"axiom test message");
        assert_eq!(sig.len(), 64, "Ed25519 signature debe tener 64 bytes");
    }

    #[test]
    fn hybrid_kyber_encap_decap_roundtrip() {
        let kp = HybridKeyPair::generate();
        let (ct, ss_enc) = kp.kyber_encapsulate();
        let ss_dec = kp
            .kyber_decapsulate(&ct)
            .expect("Decapsulation debe funcionar");
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn debug_output_is_safe() {
        let kp = HybridKeyPair::generate();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("[REDACTED]"));
    }
}
