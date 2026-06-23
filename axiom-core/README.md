# axiom-core — El Núcleo de Titanio

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Security: Post-Quantum](https://img.shields.io/badge/security-post--quantum-purple.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)

> La base criptográfica soberana del proyecto AXIOM.

## ¿Qué es esto?

`axiom-core` implementa el método DID `did:axiom` siguiendo la especificación [W3C DID Core 1.0](https://www.w3.org/TR/did-core/), usando criptografía híbrida poscuántica:

| Algoritmo | Propósito | Estándar |
|-----------|-----------|---------|
| **Ed25519** | Firma digital y autenticación | RFC 8032 |
| **CRYSTALS-Kyber ML-KEM-768** | Encapsulamiento de claves poscuántico | NIST FIPS 203 |

## La Regla de Oro 🔒

> **La clave privada NUNCA abandona el dispositivo del usuario.**

Esta regla se implementa en 4 niveles simultáneos:

1. **Visibilidad Rust**: `SigningKey` y `SecretKey` son `pub(super)` — el compilador rechaza cualquier acceso externo
2. **Sin `Serialize`**: Las claves privadas no implementan `serde::Serialize` — imposible volcarlas a JSON
3. **Zeroize on Drop**: Claves borradas de RAM con ceros al salir de scope (`ZeroizeOnDrop`)
4. **Test de confinamiento**: `cargo test private_key_confinement` valida 6 niveles de garantía en runtime

El `LocalResolver` es **100% sin red** — usa exclusivamente `std::fs`. No existe `reqwest`, ni sockets, ni HTTP en este crate.

## Estructura del DID

```
did:axiom:<fingerprint>
```

donde `<fingerprint>` = `multibase(base58btc, SHA-256(ed25519_public_key))`

## Ejemplo de DID Document

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://axiom.id/ns/v1"
  ],
  "id": "did:axiom:z6Mk...",
  "verificationMethod": [
    {
      "id": "did:axiom:z6Mk...#key-ed25519",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:axiom:z6Mk...",
      "publicKeyMultibase": "z6Mk..."
    },
    {
      "id": "did:axiom:z6Mk...#key-kyber",
      "type": "JsonWebKey2020",
      "controller": "did:axiom:z6Mk...",
      "publicKeyJwk": { "kty": "PQK", "crv": "Kyber768", "x": "..." }
    }
  ],
  "authentication": ["did:axiom:z6Mk...#key-ed25519"],
  "keyAgreement": ["did:axiom:z6Mk...#key-kyber"],
  "proof": { "type": "Ed25519Signature2020", ... }
}
```

## Uso

```rust
use axiom_core::keys::HybridKeyPair;
use axiom_core::did::{AxiomDid, LocalResolver};

// Generar identidad híbrida
let keypair = HybridKeyPair::generate();
let did = AxiomDid::create(&keypair)?;

println!("Mi DID: {}", did.id);

// Guardar en disco
let resolver = LocalResolver::new(Path::new("./did_store"))?;
resolver.store(&did.document)?;

// Resolver sin red
let resolved = resolver.resolve(&did.id)?;
```

## Tests

```bash
# Tests unitarios
cargo test --lib

# Tests de integración (incluye La Regla de Oro)
cargo test

# Solo la Regla de Oro
cargo test private_key_confinement

# Con salida detallada
cargo test -- --nocapture
```

## Requisitos

- Rust 1.75+
- Windows / Linux / macOS

## Roadmap

- [ ] Compilación a WASM (para el frontend AXIOM)
- [ ] `did:axiom` DID Method Spec publicada
- [ ] Actualización a ML-KEM (FIPS 203 final) cuando los bindings maduren
- [ ] Hardware security key support (YubiKey, TPM)

## Licencia

MIT OR Apache-2.0
