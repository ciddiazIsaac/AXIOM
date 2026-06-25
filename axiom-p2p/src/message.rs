use serde::{Deserialize, Serialize};

/// Mensaje de dominio que representa una revocación de credencial.
/// Se usa como input/output del CRDT, pero NO se envía directamente por Gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RevocationMessage {
    pub credential_id: String,
    pub issuer_did: String,
    pub timestamp: u64,
    pub reason: String,
}

/// Payload que viaja por Gossipsub.
///
/// Discrimina entre cambios incrementales (operación normal) y
/// mensajes de sincronización (para nodos que se unen tarde).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipPayload {
    /// Cambio incremental de Automerge — contiene solo el delta.
    /// Se genera con `RevocationCrdt::save_incremental()` y se aplica
    /// con `RevocationCrdt::apply_incremental()`.
    RevocationChange(Vec<u8>),

    /// Un nodo solicita el estado completo del CRDT.
    /// Los nodos que reciben esto responden con `SyncResponse`.
    SyncRequest,

    /// Respuesta con el documento Automerge completo serializado.
    /// Se genera con `RevocationCrdt::save_full()` y se aplica
    /// con `RevocationCrdt::merge_full()`.
    SyncResponse(Vec<u8>),
}
