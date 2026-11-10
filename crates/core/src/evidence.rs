use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::{
    config::Config,
    model::{
        AddressFamily, CanonicalPrefix, CleanupStatus, PeerId, PolicyProfile, Scenario, Verdict,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "phase.changed")]
    PhaseChanged,
    #[serde(rename = "session.changed")]
    SessionChanged,
    #[serde(rename = "route.observed")]
    RouteObserved,
    #[serde(rename = "peer_policy.observed")]
    PeerPolicyObserved,
    #[serde(rename = "probe.observed")]
    ProbeObserved,
    #[serde(rename = "mutation.recorded")]
    MutationRecorded,
    #[serde(rename = "recovery.recorded")]
    RecoveryRecorded,
    #[serde(rename = "evidence.gap")]
    EvidenceGap,
    #[serde(rename = "assertion.evaluated")]
    AssertionEvaluated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub schema_version: u32,
    pub run_id: String,
    pub sequence: u64,
    #[serde(with = "utc_timestamp")]
    pub timestamp: OffsetDateTime,
    pub elapsed_ms: u64,
    pub kind: EventKind,
    pub source_node: Option<String>,
    pub peer_id: Option<PeerId>,
    pub address_family: Option<AddressFamily>,
    pub prefix: Option<CanonicalPrefix>,
    pub evidence_refs: Vec<String>,
    /// Payloads become more specific as their producing components are implemented.
    pub details: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub run_id: String,
    #[serde(with = "utc_timestamp")]
    pub started_at: OffsetDateTime,
    pub configuration: Config,
    pub fixture_id: String,
    pub fixture_version: String,
    pub software_versions: BTreeMap<String, String>,
    pub image_identities: BTreeMap<String, String>,
    pub artifacts: Vec<ArtifactMetadata>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub path: String,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionKey {
    pub id: String,
    pub address_family: AddressFamily,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionResult {
    pub id: String,
    pub address_family: AddressFamily,
    pub expectation: String,
    pub observation: String,
    pub result: Verdict,
    pub evidence_refs: Vec<String>,
}

impl AssertionResult {
    pub fn key(&self) -> AssertionKey {
        AssertionKey {
            id: self.id.clone(),
            address_family: self.address_family,
        }
    }

    pub(crate) fn has_evidence(&self) -> bool {
        !self.evidence_refs.is_empty()
            && self
                .evidence_refs
                .iter()
                .all(|reference| !reference.trim().is_empty())
            && !self.observation.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummary {
    pub schema_version: u32,
    pub run_id: String,
    pub scenario: Scenario,
    pub policy_profile: PolicyProfile,
    pub result: Verdict,
    pub assertions: Vec<AssertionResult>,
    pub cleanup_status: CleanupStatus,
    pub evidence_gaps: Vec<String>,
}

mod utc_timestamp {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = value
            .to_offset(UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&text, &Rfc3339)
            .map(|value| value.to_offset(UtcOffset::UTC))
            .map_err(serde::de::Error::custom)
    }
}
