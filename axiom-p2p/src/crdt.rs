use std::collections::HashSet;
use crate::message::RevocationMessage;

/// Un G-Set (Grow-Only Set) simple para el CRDT de revocaciones.
/// Gossipsub no garantiza orden de entrega, así que este set acumula los mensajes revocados de forma monotónica.
#[derive(Debug, Default)]
pub struct RevocationCrdt {
    revocations: HashSet<RevocationMessage>,
}

impl RevocationCrdt {
    pub fn new() -> Self {
        Self {
            revocations: HashSet::new(),
        }
    }

    pub fn add(&mut self, revocation: RevocationMessage) -> bool {
        self.revocations.insert(revocation)
    }

    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.revocations.iter().any(|r| r.credential_id == credential_id)
    }

    pub fn all_revocations(&self) -> &HashSet<RevocationMessage> {
        &self.revocations
    }
}
