//! Resolutor local de DIDs AXIOM.
//!
//! Lee DID Documents desde el filesystem local (archivos `.json`).
//!
//! # Regla de Oro — Sin Red
//! Este resolutor usa EXCLUSIVAMENTE `std::fs` para leer archivos en disco.
//! No existe ningún `reqwest`, `hyper`, `tokio`, ni ninguna primitiva de red.
//! Si algún commit añade una dependencia de red, es una violación de la Regla de Oro.
//!
//! # Formato del Store
//! Los DID Documents se almacenan como archivos JSON en un directorio:
//! ```text
//! <store_path>/
//!   did:axiom:z123.json
//!   did:axiom:z456.json
//! ```
//! El nombre del archivo es el DID completo con `:` reemplazado por `_`.

use std::path::{Path, PathBuf};

use crate::did::document::DidDocument;
use crate::error::AxiomError;

/// Resolutor local de DID Documents — sin red, sin peticiones HTTP.
///
/// Lee documentos desde un directorio local del filesystem.
pub struct LocalResolver {
    /// Directorio donde se almacenan los DID Documents.
    store_path: PathBuf,
}

impl LocalResolver {
    /// Crea un nuevo `LocalResolver` apuntando a un directorio en disco.
    ///
    /// # Errores
    /// Retorna error si el directorio no existe y no se puede crear.
    pub fn new(store_path: &Path) -> Result<Self, AxiomError> {
        if !store_path.exists() {
            std::fs::create_dir_all(store_path)?;
        }
        Ok(Self {
            store_path: store_path.to_path_buf(),
        })
    }

    /// Resuelve un DID leyendo su documento desde disco.
    ///
    /// # Proceso (100% local, sin red)
    /// 1. Transforma el DID en un nombre de archivo seguro
    /// 2. Lee el archivo `.json` del directorio `store_path`
    /// 3. Deserializa el JSON en `DidDocument`
    /// 4. Valida que cumple W3C DID Core 1.0
    ///
    /// # Errores
    /// - `AxiomError::InvalidDid` si el formato del DID es incorrecto
    /// - `AxiomError::DidNotFound` si el archivo no existe
    /// - `AxiomError::Serialization` si el JSON está malformado
    /// - `AxiomError::InvalidDocument` si el documento no es W3C válido
    pub fn resolve(&self, did: &str) -> Result<DidDocument, AxiomError> {
        // Validar formato básico
        if !did.starts_with("did:axiom:") {
            return Err(AxiomError::InvalidDid(format!(
                "El DID '{did}' no es un DID AXIOM válido (debe comenzar con 'did:axiom:')"
            )));
        }

        let file_path = self.did_to_file_path(did);

        // Leer el archivo — SOLO std::fs, NUNCA red
        let json_content = std::fs::read_to_string(&file_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AxiomError::DidNotFound(format!(
                    "DID '{}' no encontrado en el store local (buscado en: {})",
                    did,
                    file_path.display()
                ))
            } else {
                AxiomError::Io(e)
            }
        })?;

        // Deserializar y validar
        let document: DidDocument = serde_json::from_str(&json_content)?;
        document.validate()?;

        Ok(document)
    }

    /// Almacena un DID Document en el store local.
    ///
    /// Antes de guardar, verifica la Regla de Oro:
    /// el documento no debe contener material de clave privada.
    pub fn store(&self, document: &DidDocument) -> Result<(), AxiomError> {
        // Regla de Oro: última verificación antes de escribir en disco
        document.assert_no_private_key_material()?;
        document.validate()?;

        let file_path = self.did_to_file_path(&document.id);
        let json = serde_json::to_string_pretty(document)?;
        std::fs::write(&file_path, json)?;

        Ok(())
    }

    /// Lista todos los DIDs disponibles en el store local.
    pub fn list_dids(&self) -> Result<Vec<String>, AxiomError> {
        let mut dids = Vec::new();

        for entry in std::fs::read_dir(&self.store_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    // Revertir la transformación del nombre de archivo a DID
                    let did = stem.replace('_', ":");
                    if did.starts_with("did:axiom:") {
                        dids.push(did);
                    }
                }
            }
        }

        Ok(dids)
    }

    /// Elimina un DID Document del store local.
    pub fn delete(&self, did: &str) -> Result<(), AxiomError> {
        let file_path = self.did_to_file_path(did);
        std::fs::remove_file(&file_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AxiomError::DidNotFound(did.to_string())
            } else {
                AxiomError::Io(e)
            }
        })
    }

    /// Convierte un DID en un path de archivo seguro.
    ///
    /// Ejemplo: `did:axiom:z123` → `<store_path>/did_axiom_z123.json`
    fn did_to_file_path(&self, did: &str) -> PathBuf {
        let safe_name = did.replace(':', "_");
        self.store_path.join(format!("{safe_name}.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::document::{DidDocument, VerificationMethod, DID_CONTEXT_V1};

    fn make_test_document(did: &str) -> DidDocument {
        DidDocument {
            context: vec![DID_CONTEXT_V1.to_string()],
            id: did.to_string(),
            also_known_as: None,
            controller: None,
            verification_method: vec![VerificationMethod {
                id: format!("{}#key-1", did),
                key_type: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                public_key_multibase: Some("zABCDEF123".to_string()),
                public_key_jwk: None,
            }],
            authentication: vec![serde_json::json!(format!("{}#key-1", did))],
            key_agreement: vec![],
            assertion_method: vec![],
            service: vec![],
            created: "2024-01-01T00:00:00Z".to_string(),
            updated: "2024-01-01T00:00:00Z".to_string(),
            proof: None,
        }
    }

    #[test]
    fn store_and_resolve_roundtrip() {
        let temp = tempfile::tempdir().expect("tempdir");
        let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

        let did = "did:axiom:zTestResolverRoundtrip";
        let doc = make_test_document(did);

        resolver.store(&doc).expect("Store debe funcionar");
        let resolved = resolver.resolve(did).expect("Resolve debe funcionar");

        assert_eq!(
            doc, resolved,
            "El documento resuelto debe ser idéntico al almacenado"
        );
    }

    #[test]
    fn resolve_nonexistent_did_returns_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

        let result = resolver.resolve("did:axiom:zInexistente");
        assert!(
            matches!(result, Err(AxiomError::DidNotFound(_))),
            "Resolver un DID inexistente debe retornar DidNotFound"
        );
    }

    #[test]
    fn resolve_invalid_did_format_returns_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

        let result = resolver.resolve("did:web:example.com");
        assert!(
            matches!(result, Err(AxiomError::InvalidDid(_))),
            "DID con método incorrecto debe retornar InvalidDid"
        );
    }

    #[test]
    fn list_dids_returns_stored_dids() {
        let temp = tempfile::tempdir().expect("tempdir");
        let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

        let did1 = "did:axiom:zListTest1";
        let did2 = "did:axiom:zListTest2";
        resolver.store(&make_test_document(did1)).expect("Store 1");
        resolver.store(&make_test_document(did2)).expect("Store 2");

        let mut dids = resolver.list_dids().expect("Listar DIDs");
        dids.sort();

        assert!(dids.contains(&did1.to_string()));
        assert!(dids.contains(&did2.to_string()));
    }
}
