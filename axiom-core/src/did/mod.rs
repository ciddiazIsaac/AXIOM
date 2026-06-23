//! Módulo DID (Decentralized Identifier).
//!
//! Implementa el método `did:axiom` siguiendo la especificación W3C DID Core 1.0.
//! <https://www.w3.org/TR/did-core/>
//!
//! # Componentes
//! - [`document`] — Estructura del DID Document en JSON-LD
//! - [`method`] — Creación del DID `did:axiom:<fingerprint>`
//! - [`resolver`] — Resolución local desde archivo `.json` en disco

pub mod document;
pub mod method;
pub mod resolver;

pub use document::DidDocument;
pub use method::AxiomDid;
pub use resolver::LocalResolver;
