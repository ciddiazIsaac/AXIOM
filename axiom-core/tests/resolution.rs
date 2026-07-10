//! Tests de integración: resolución local de DIDs sin red.

use axiom_core::did::{AxiomDid, LocalResolver};
use axiom_core::HybridKeyPair;
use tempfile::tempdir;

#[test]
fn full_lifecycle_create_store_resolve() {
    // Paso 1: Generar identidad
    let keypair = HybridKeyPair::generate();
    let did = AxiomDid::create(&keypair).expect("Crear DID");
    let did_id = did.id.clone();

    // Paso 2: Crear resolver y almacenar
    let temp = tempdir().expect("tempdir");
    let resolver = LocalResolver::new(temp.path()).expect("Crear LocalResolver");
    resolver
        .store(&did.document)
        .expect("Almacenar DID Document");

    // Paso 3: Resolver desde disco (sin red)
    let resolved = resolver.resolve(&did_id).expect("Resolver DID desde disco");

    // El documento resuelto debe ser idéntico al original
    assert_eq!(
        did.document, resolved,
        "Round-trip: crear → guardar → resolver debe producir documento idéntico"
    );
}

#[test]
fn resolver_creates_store_directory_if_not_exists() {
    let temp = tempdir().expect("tempdir");
    let new_dir = temp.path().join("did_store").join("nested");

    // El directorio no existe aún
    assert!(!new_dir.exists());

    // El resolver lo debe crear automáticamente
    let _resolver = LocalResolver::new(&new_dir).expect("LocalResolver debe crear el directorio");
    assert!(
        new_dir.exists(),
        "El resolver debe crear el directorio si no existe"
    );
}

#[test]
fn resolver_does_not_use_network() {
    // Este test es principalmente documental pero también verifica
    // que el resolver funciona sin ninguna conexión de red activa.
    // En Rust, la ausencia de dependencias de red en el Cargo.toml del resolutor
    // garantiza esto en tiempo de compilación.
    //
    // Adicionalmente, verificamos que el resolver funciona en un entorno
    // completamente local.
    let temp = tempdir().expect("tempdir");
    let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    // Si hubiese tráfico de red, el test fallaría en entornos offline.
    // Dado que solo usa std::fs, funciona siempre.
    resolver.store(&did.document).expect("Store");
    let resolved = resolver.resolve(&did.id).expect("Resolve");

    assert_eq!(did.document.id, resolved.id);
}

#[test]
fn multiple_dids_in_same_store() {
    let temp = tempdir().expect("tempdir");
    let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

    // Crear múltiples identidades
    let identities: Vec<AxiomDid> = (0..5)
        .map(|_| {
            let kp = HybridKeyPair::generate();
            AxiomDid::create(&kp).expect("Crear DID")
        })
        .collect();

    // Almacenar todos
    for did in &identities {
        resolver.store(&did.document).expect("Store");
    }

    // Verificar que todos se pueden resolver
    for did in &identities {
        let resolved = resolver
            .resolve(&did.id)
            .expect(&format!("Resolver {}", did.id));
        assert_eq!(did.document, resolved);
    }

    // Listar todos los DIDs
    let listed = resolver.list_dids().expect("Listar DIDs");
    assert_eq!(listed.len(), 5, "Deben haber 5 DIDs en el store");
}

#[test]
fn resolve_nonexistent_fails_gracefully() {
    let temp = tempdir().expect("tempdir");
    let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

    let result = resolver.resolve("did:axiom:zNoExiste");
    assert!(
        result.is_err(),
        "Resolver un DID no almacenado debe retornar error"
    );
}

#[test]
fn delete_removes_did_from_store() {
    let temp = tempdir().expect("tempdir");
    let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");
    let did_id = did.id.clone();

    resolver.store(&did.document).expect("Store");
    assert!(
        resolver.resolve(&did_id).is_ok(),
        "Debe existir antes de borrar"
    );

    resolver.delete(&did_id).expect("Delete");
    assert!(
        resolver.resolve(&did_id).is_err(),
        "Tras borrar, el DID no debe poder resolverse"
    );
}

#[test]
fn stored_document_retains_private_key_confinement() {
    // Verifica que incluso después de guardar en disco y recargar,
    // la Regla de Oro sigue aplicando al documento cargado.
    let temp = tempdir().expect("tempdir");
    let resolver = LocalResolver::new(temp.path()).expect("Crear resolver");

    let kp = HybridKeyPair::generate();
    let did = AxiomDid::create(&kp).expect("Crear DID");

    resolver.store(&did.document).expect("Store");
    let resolved = resolver.resolve(&did.id).expect("Resolve");

    // El documento cargado del disco tampoco debe tener material privado
    assert!(
        resolved.assert_no_private_key_material().is_ok(),
        "El DID Document cargado del disco tampoco debe contener material privado"
    );
}
