//! Passive routing observations, bounded ingestion, and reproducible evidence reports.
pub mod bundle;
pub mod lookup;
pub mod model;
pub mod mrt;
pub mod pcap;
pub mod ris;
pub mod state;
pub mod tcp;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("analysis interrupted by user")]
    Interrupted,
    #[error("{0}")]
    Invalid(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("provider: {0}")]
    Provider(String),
    #[error("resource limit: {0}")]
    Limit(String),
    #[error(transparent)]
    Update(#[from] bgp_hijack_core::update::UpdateError),
}
pub type Result<T> = std::result::Result<T, Error>;
