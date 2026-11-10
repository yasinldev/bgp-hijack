use bgp_hijack_core::{
    model::{AddressFamily, CanonicalPrefix},
    update::Attributes,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: u32 = 1;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisLimits {
    pub record_bytes: usize,
    pub journal_bytes: u64,
    pub output_bytes: u64,
    pub input_bytes: u64,
    pub routes: usize,
    pub findings: usize,
    pub flows: usize,
    pub stream_bytes: usize,
    pub queue_bytes: usize,
}
impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            record_bytes: 1024 * 1024,
            journal_bytes: 64 * 1024 * 1024,
            output_bytes: 256 * 1024 * 1024,
            input_bytes: 1024 * 1024 * 1024,
            routes: 100_000,
            findings: 10_000,
            flows: 64,
            stream_bytes: 1024 * 1024,
            queue_bytes: 16 * 1024 * 1024,
        }
    }
}
impl AnalysisLimits {
    pub fn validate(&self) -> crate::Result<()> {
        if self.record_bytes == 0
            || self.record_bytes > 4 * 1024 * 1024
            || self.journal_bytes > 1024 * 1024 * 1024
            || self.output_bytes > 4 * 1024 * 1024 * 1024
            || self.input_bytes > 64 * 1024 * 1024 * 1024
            || self.routes > 1_000_000
            || self.findings > 100_000
            || self.flows > 256
            || self.stream_bytes > 4 * 1024 * 1024
            || self.queue_bytes > 64 * 1024 * 1024
            || self.journal_bytes < self.record_bytes as u64
            || self.output_bytes < self.journal_bytes
            || self.input_bytes == 0
            || self.routes == 0
            || self.findings == 0
            || self.flows == 0
            || self.stream_bytes == 0
            || self.queue_bytes == 0
        {
            return Err(crate::Error::Invalid("invalid analysis limits".into()));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub source: String,
    pub collector: Option<String>,
    pub peer: String,
    pub epoch: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Announce,
    Withdraw,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteObservation {
    pub source: Source,
    pub source_time: Option<f64>,
    pub prefix: CanonicalPrefix,
    pub address_family: AddressFamily,
    pub path_id: Option<u32>,
    pub action: RouteAction,
    pub attributes: Attributes,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Route(RouteObservation),
    Gap {
        source: Option<Source>,
        reason: String,
    },
    SourceStatus {
        source: Source,
        status: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AnalysisEvent {
    pub schema_version: u32,
    pub run_id: String,
    pub sequence: u64,
    pub received_at: String,
    pub elapsed_ms: u64,
    pub evidence_refs: Vec<String>,
    pub observation: Observation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    OriginChanged,
    AsPathChanged,
    MultipleOriginsObserved,
    MoreSpecificObserved,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub rule_version: u32,
    pub kind: FindingKind,
    pub prefix: CanonicalPrefix,
    pub sources: Vec<Source>,
    pub observations: Vec<u64>,
    pub explanation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub size_bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisManifest {
    pub schema_version: u32,
    pub kind: String,
    pub run_id: String,
    pub started_at: String,
    pub input: String,
    pub filters: serde_json::Value,
    pub software_version: String,
    pub limits: AnalysisLimits,
    pub complete: bool,
    pub artifacts: BTreeMap<String, Artifact>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisSummary {
    pub schema_version: u32,
    pub run_id: String,
    pub processing_status: String,
    /// Completeness is limited to the selected input, never the global routing table.
    pub coverage: String,
    pub events: u64,
    pub routes: usize,
    pub gaps: Vec<String>,
    pub findings: Vec<Finding>,
    pub metrics: BTreeMap<String, f64>,
}
