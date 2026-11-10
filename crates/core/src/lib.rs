//! Shared BGP codecs, durable storage, and configuration/evidence contracts for routing research.

pub mod codec;
pub mod config;
pub mod error;
pub mod evaluation;
pub mod evidence;
pub mod journal;
pub mod model;

pub const SCHEMA_VERSION: u32 = 1;

pub mod storage;
pub mod update;
