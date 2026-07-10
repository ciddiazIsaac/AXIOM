use thiserror::Error;

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("Error de Automerge: {0}")]
    AutomergeError(#[from] automerge::AutomergeError),

    #[error("Error de I/O: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Error de SQLite: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("Error de serialización JSON: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Firma criptográfica inválida del PeerId {0}")]
    InvalidSignature(String),

    #[error("Error de red P2P: {0}")]
    P2pError(String),

    #[error("Error interno: {0}")]
    Internal(String),
}
