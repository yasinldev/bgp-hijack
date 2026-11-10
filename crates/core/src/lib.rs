//! Offline configuration, evidence, and evaluation contracts for isolated BGP labs.

pub mod config;
pub mod error;
pub mod evaluation;
pub mod evidence;
pub mod model;

pub const SCHEMA_VERSION: u32 = 1;
