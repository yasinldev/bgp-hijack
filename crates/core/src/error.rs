use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ModelError {
    #[error("invalid prefix {value:?}: {reason}")]
    Prefix { value: String, reason: String },
    #[error("invalid peer ID {0:?}: use nonempty ASCII letters, digits, '.', '_' or '-'")]
    PeerId(String),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{}: YAML: {source}", path.display())]
    Yaml {
        path: PathBuf,
        #[source]
        source: Box<serde_saphyr::Error>,
    },
    #[error("{}: {field}: {message}", path.display())]
    Invalid {
        path: PathBuf,
        field: String,
        message: String,
    },
}
