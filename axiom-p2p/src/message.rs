use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RevocationMessage {
    pub credential_id: String,
    pub issuer_did: String,
    pub timestamp: u64,
    pub reason: String,
}
