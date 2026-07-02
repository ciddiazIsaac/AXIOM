use automerge::{AutoCommit, ObjType, ReadDoc, transaction::Transactable};
use crate::message::RevocationMessage;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// Estado global de revocaciones respaldado por Automerge CRDT.
///
/// El documento Automerge tiene la estructura:
/// ```text
/// ROOT (Map)
/// ├── "<credential_id_1>" (Map)
/// │   ├── "issuer_did": String
/// │   ├── "timestamp": i64
/// │   └── "reason": String
/// ├── "<credential_id_2>" (Map)
/// │   └── ...
/// ```
///
/// Se almacenan las revocaciones directamente en ROOT (no en un sub-mapa)
/// porque ROOT tiene un ObjId universal idéntico en todos los documentos
/// Automerge, lo que permite que `load_incremental` funcione correctamente
/// entre nodos independientes sin necesidad de un documento génesis compartido.
///
/// Cada nodo mantiene su propia copia de este documento. Los cambios
/// se propagan como deltas incrementales por Gossipsub. Automerge
/// garantiza convergencia eventual sin importar el orden de entrega.
pub struct RevocationCrdt {
    doc: AutoCommit,
    db_path: Option<PathBuf>,
}

impl std::fmt::Debug for RevocationCrdt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationCrdt")
            .field("revocations_count", &self.count())
            .finish()
    }
}

impl Default for RevocationCrdt {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationCrdt {
    /// Crea un documento Automerge vacío.
    ///
    /// No se crea ninguna estructura interna — las revocaciones se almacenan
    /// directamente en ROOT para evitar conflictos de ObjId entre nodos
    /// independientes.
    pub fn new() -> Self {
        let doc = AutoCommit::new();
        Self { doc, db_path: None }
    }

    /// Crea un `RevocationCrdt` respaldado por una base de datos SQLite.
    /// 
    /// Si la base de datos ya contiene un estado previo, lo carga.
    /// De lo contrario, inicializa un documento vacío que se irá
    /// persistiendo con cada cambio.
    pub fn with_storage<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let path_buf = path.as_ref().to_path_buf();
        let db = Connection::open(&path_buf)?;
        
        // Crear tabla si no existe
        db.execute(
            "CREATE TABLE IF NOT EXISTS crdt_state (
                key TEXT PRIMARY KEY NOT NULL,
                value BLOB NOT NULL,
                updated_at INTEGER DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )?;

        let mut doc = AutoCommit::new();

        // Intentar cargar el estado guardado
        {
            let mut stmt = db.prepare("SELECT value FROM crdt_state WHERE key = 'doc_state'")?;
            let mut rows = stmt.query([])?;
            
            if let Some(row) = rows.next()? {
                let data: Vec<u8> = row.get(0)?;
                match AutoCommit::load(&data) {
                    Ok(loaded_doc) => {
                        doc = loaded_doc;
                    }
                    Err(e) => {
                        eprintln!("[CRDT] WARN: Previous state corrupted, starting fresh: {:?}", e);
                    }
                }
            }
        }

        Ok(Self { doc, db_path: Some(path_buf) })
    }

    /// Guarda el estado completo en la base de datos si está configurada.
    fn persist(&mut self) {
        if let Some(path) = &self.db_path {
            let data = self.doc.save();
            match Connection::open(path) {
                Ok(db) => {
                    if let Err(e) = db.execute(
                        "INSERT OR REPLACE INTO crdt_state (key, value) VALUES ('doc_state', ?1)",
                        rusqlite::params![data],
                    ) {
                        eprintln!("[CRDT] Error persistiendo estado a la BD: {:?}", e);
                    }
                }
                Err(e) => {
                    eprintln!("[CRDT] Error abriendo BD para persistir: {:?}", e);
                }
            }
        }
    }

    /// Inserta una revocación en el documento Automerge.
    ///
    /// Devuelve `true` si la credencial no estaba previamente revocada (inserción nueva).
    /// Devuelve `false` si ya existía (sobrescritura idempotente).
    pub fn add(&mut self, revocation: &RevocationMessage) -> bool {
        // Verificar si ya existe
        let already_exists = self.doc
            .get(automerge::ROOT, &revocation.credential_id)
            .ok()
            .flatten()
            .is_some();

        // Crear el mapa para esta credencial en ROOT
        let entry_id = self.doc
            .put_object(automerge::ROOT, &revocation.credential_id, ObjType::Map)
            .expect("fallo al crear entrada de revocación");

        self.doc.put(&entry_id, "issuer_did", revocation.issuer_did.as_str())
            .expect("fallo al escribir issuer_did");
        self.doc.put(&entry_id, "timestamp", revocation.timestamp as i64)
            .expect("fallo al escribir timestamp");
        self.doc.put(&entry_id, "reason", revocation.reason.as_str())
            .expect("fallo al escribir reason");

        self.persist();

        !already_exists
    }

    /// Verifica si una credencial está revocada.
    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.doc
            .get(automerge::ROOT, credential_id)
            .ok()
            .flatten()
            .is_some()
    }

    /// Devuelve todas las revocaciones como `Vec<RevocationMessage>`.
    pub fn all_revocations(&self) -> Vec<RevocationMessage> {
        let mut result = Vec::new();
        let keys: Vec<String> = self.doc.keys(automerge::ROOT).collect();
        for credential_id in keys {
            if let Some(msg) = self.read_revocation(&credential_id) {
                result.push(msg);
            }
        }
        result
    }

    /// Número total de revocaciones en el documento.
    pub fn count(&self) -> usize {
        self.doc.length(automerge::ROOT)
    }

    // ─── Sync: Cambios Incrementales (Gossipsub) ────────────────────────

    /// Genera los bytes del cambio incremental desde el último `save_incremental`.
    ///
    /// Este es el payload que se envía por Gossipsub cuando se publica una revocación.
    /// Solo contiene los cambios nuevos desde la última vez que se llamó.
    pub fn save_incremental(&mut self) -> Vec<u8> {
        self.doc.save_incremental()
    }

    /// Aplica cambios incrementales recibidos de otro nodo.
    ///
    /// Esta es la operación que se ejecuta cuando llega un mensaje de Gossipsub
    /// con un `GossipPayload::RevocationChange`. Automerge fusiona automáticamente
    /// sin importar el orden de llegada.
    pub fn apply_incremental(&mut self, bytes: &[u8]) -> Result<(), automerge::AutomergeError> {
        self.doc.load_incremental(bytes)?;
        self.persist();
        Ok(())
    }

    // ─── Sync: Estado Completo (Nodos que se unen tarde) ────────────────

    /// Serializa el documento completo a bytes.
    ///
    /// Se usa para responder a `SyncRequest` de nodos que se unen tarde a la red.
    pub fn save_full(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Carga un documento completo desde bytes y lo fusiona con el estado local.
    ///
    /// Se usa cuando un nodo recibe un `SyncResponse` con el estado completo de otro nodo.
    pub fn merge_full(&mut self, bytes: &[u8]) -> Result<(), automerge::AutomergeError> {
        let mut other = AutoCommit::load(bytes)?;
        self.doc.merge(&mut other)?;
        self.persist();
        Ok(())
    }

    /// Crea un `RevocationCrdt` desde un documento completo serializado.
    ///
    /// Útil para reconstruir el estado desde cero (e.g., un nodo que reinicia
    /// y carga desde disco, o que recibe un snapshot completo).
    pub fn load_full(bytes: &[u8]) -> Result<Self, automerge::AutomergeError> {
        let doc = AutoCommit::load(bytes)?;
        Ok(Self { doc, db_path: None })
    }

    // ─── Helpers privados ───────────────────────────────────────────────

    /// Lee una revocación individual del documento por su credential_id.
    fn read_revocation(&self, credential_id: &str) -> Option<RevocationMessage> {
        let (_, entry_id) = self.doc.get(automerge::ROOT, credential_id).ok()??;

        let issuer_did = self.doc.get(&entry_id, "issuer_did").ok()??.0.into_string().ok()?;
        let timestamp = self.doc.get(&entry_id, "timestamp").ok()??.0.to_i64()? as u64;
        let reason = self.doc.get(&entry_id, "reason").ok()??.0.into_string().ok()?;

        Some(RevocationMessage {
            credential_id: credential_id.to_string(),
            issuer_did,
            timestamp,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_revocation(id: &str) -> RevocationMessage {
        RevocationMessage {
            credential_id: id.to_string(),
            issuer_did: "did:axiom:issuer123".to_string(),
            timestamp: 1719300000,
            reason: "compromised".to_string(),
        }
    }

    /// Test 1: Convergencia — dos documentos reciben los mismos cambios en
    /// orden diferente y convergen al mismo estado final.
    #[test]
    fn test_convergence_different_order() {
        let rev_a = make_revocation("cred-alpha");
        let rev_b = make_revocation("cred-beta");

        // Nodo 1: añade A, luego B
        let mut node1 = RevocationCrdt::new();
        let _ = node1.save_incremental(); // flush initial
        node1.add(&rev_a);
        let delta_a = node1.save_incremental();
        node1.add(&rev_b);
        let delta_b = node1.save_incremental();

        // Nodo 2: recibe B primero, luego A (orden invertido)
        let mut node2 = RevocationCrdt::new();
        let _ = node2.save_incremental(); // flush initial
        node2.apply_incremental(&delta_b).unwrap();
        node2.apply_incremental(&delta_a).unwrap();

        // Ambos deben tener las mismas revocaciones
        assert!(node2.is_revoked("cred-alpha"), "cred-alpha debería estar revocada");
        assert!(node2.is_revoked("cred-beta"), "cred-beta debería estar revocada");
        assert_eq!(node2.count(), 2);
    }

    /// Test 2: Idempotencia — aplicar el mismo cambio dos veces no duplica.
    #[test]
    fn test_idempotency() {
        let rev = make_revocation("cred-dup");

        let mut node1 = RevocationCrdt::new();
        let _ = node1.save_incremental(); // flush initial
        node1.add(&rev);
        let delta = node1.save_incremental();

        let mut node2 = RevocationCrdt::new();
        let _ = node2.save_incremental(); // flush initial
        node2.apply_incremental(&delta).unwrap();
        // Aplicar el mismo delta otra vez — Automerge lo deduplica
        node2.apply_incremental(&delta).unwrap();

        assert!(node2.is_revoked("cred-dup"));
        assert_eq!(node2.count(), 1);
    }

    /// Test 3: Sync completo — un documento vacío recibe el estado completo
    /// de otro y queda con el mismo contenido.
    #[test]
    fn test_full_sync() {
        let mut source = RevocationCrdt::new();
        source.add(&make_revocation("cred-1"));
        source.add(&make_revocation("cred-2"));
        source.add(&make_revocation("cred-3"));

        let full_state = source.save_full();

        // Nodo nuevo que se une tarde
        let mut newcomer = RevocationCrdt::new();
        newcomer.merge_full(&full_state).unwrap();

        assert!(newcomer.is_revoked("cred-1"));
        assert!(newcomer.is_revoked("cred-2"));
        assert!(newcomer.is_revoked("cred-3"));
        assert_eq!(newcomer.count(), 3);
    }

    /// Test 4: Round-trip — add() → save_incremental() → apply_incremental()
    /// en otro doc → is_revoked() devuelve true.
    #[test]
    fn test_round_trip_incremental() {
        let rev = make_revocation("cred-roundtrip");

        let mut publisher = RevocationCrdt::new();
        let _ = publisher.save_incremental(); // flush initial
        publisher.add(&rev);
        let delta = publisher.save_incremental();

        let mut receiver = RevocationCrdt::new();
        let _ = receiver.save_incremental(); // flush initial
        assert!(!receiver.is_revoked("cred-roundtrip"));

        receiver.apply_incremental(&delta).unwrap();
        assert!(receiver.is_revoked("cred-roundtrip"));
    }

    /// Test 5: all_revocations() reconstruye correctamente los RevocationMessage.
    #[test]
    fn test_all_revocations_reconstruction() {
        let mut crdt = RevocationCrdt::new();
        let rev = RevocationMessage {
            credential_id: "cred-xyz".to_string(),
            issuer_did: "did:axiom:issuer456".to_string(),
            timestamp: 1719300999,
            reason: "key-rotation".to_string(),
        };
        crdt.add(&rev);

        let all = crdt.all_revocations();
        assert_eq!(all.len(), 1);

        let recovered = &all[0];
        assert_eq!(recovered.credential_id, "cred-xyz");
        assert_eq!(recovered.issuer_did, "did:axiom:issuer456");
        assert_eq!(recovered.timestamp, 1719300999);
        assert_eq!(recovered.reason, "key-rotation");
    }

    /// Test 6: add() devuelve true para nueva, false para existente.
    #[test]
    fn test_add_returns_correct_bool() {
        let mut crdt = RevocationCrdt::new();
        let rev = make_revocation("cred-bool");

        assert!(crdt.add(&rev));  // primera vez → true
        assert!(!crdt.add(&rev)); // segunda vez → false
    }

    /// Test 7: Dos nodos independientes revocan credenciales diferentes
    /// y ambos convergen al unir sus estados.
    #[test]
    fn test_two_nodes_independent_revocations() {
        let mut node1 = RevocationCrdt::new();
        let mut node2 = RevocationCrdt::new();

        // Cada nodo revoca una credencial diferente
        node1.add(&make_revocation("cred-from-node1"));
        node2.add(&make_revocation("cred-from-node2"));

        // Fusionar ambos estados
        let state1 = node1.save_full();
        let state2 = node2.save_full();

        node1.merge_full(&state2).unwrap();
        node2.merge_full(&state1).unwrap();

        // Ambos deben tener ambas revocaciones
        assert!(node1.is_revoked("cred-from-node1"));
        assert!(node1.is_revoked("cred-from-node2"));
        assert!(node2.is_revoked("cred-from-node1"));
        assert!(node2.is_revoked("cred-from-node2"));
        assert_eq!(node1.count(), 2);
        assert_eq!(node2.count(), 2);
    }

    #[test]
    fn test_sqlite_persistence() {
        let db_path = "test_sqlite_persistence.db";
        let _ = std::fs::remove_file(db_path); // Limpiar antes del test

        // 1. Crear con almacenamiento y añadir una revocación
        {
            let mut crdt = RevocationCrdt::with_storage(db_path).unwrap();
            crdt.add(&make_revocation("cred-persist"));
            assert!(crdt.is_revoked("cred-persist"));
        }

        // 2. Cargar desde almacenamiento y verificar
        {
            let crdt2 = RevocationCrdt::with_storage(db_path).unwrap();
            assert!(crdt2.is_revoked("cred-persist"));
            assert_eq!(crdt2.count(), 1);
        }

        let _ = std::fs::remove_file(db_path); // Limpiar después del test
    }
}
