use std::{collections::BTreeMap, path::Path};

use bgp_hijack_core::{
    config::parse_config,
    evidence::{ArtifactMetadata, EventEnvelope, Manifest, RunSummary},
    model::{Asn, CleanupStatus, SessionEpoch, Verdict},
};
use serde_json::{Value, json};

const EVENT: &str = include_str!("fixtures/event.json");

#[test]
fn event_matches_the_documented_golden_contract() {
    let value: Value = serde_json::from_str(EVENT).unwrap();
    let event: EventEnvelope = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&event).unwrap(), value);
    assert_eq!(event.timestamp.offset().whole_seconds(), 0);
}

#[test]
fn timestamps_normalize_to_utc_and_payloads_remain_objects() {
    let event: EventEnvelope =
        serde_json::from_str(&EVENT.replace("12:00:00Z", "15:00:00+03:00")).unwrap();
    assert_eq!(
        serde_json::to_value(event).unwrap()["timestamp"],
        "2026-11-08T12:00:00Z"
    );
    let mut value: Value = serde_json::from_str(EVENT).unwrap();
    value["details"] = json!([]);
    assert!(serde_json::from_value::<EventEnvelope>(value.clone()).is_err());
    value["details"] = json!({});
    value["kind"] = json!("unknown.event");
    assert!(serde_json::from_value::<EventEnvelope>(value).is_err());
    assert!(
        serde_json::from_str::<EventEnvelope>(&EVENT.replace("2026-11-08T12:00:00Z", "invalid"))
            .is_err()
    );
}

#[test]
fn four_octet_asn_and_epoch_survive_json() {
    let asn: Asn = serde_json::from_str("4294967294").unwrap();
    assert_eq!(asn.0, 4_294_967_294);
    assert_eq!(serde_json::to_string(&asn).unwrap(), "4294967294");
    let epoch: SessionEpoch = serde_json::from_str("18446744073709551615").unwrap();
    assert_eq!(epoch.0, u64::MAX);
    assert_eq!(
        serde_json::to_string(&epoch).unwrap(),
        "18446744073709551615"
    );
}

#[test]
fn incomplete_manifest_records_unknown_integrity_instead_of_fabricating_it() {
    let validated = parse_config(
        include_str!("../../../examples/lab-forward.yaml"),
        Path::new("example.yaml"),
    )
    .unwrap();
    let event: EventEnvelope = serde_json::from_str(EVENT).unwrap();
    let manifest = Manifest {
        schema_version: 1,
        run_id: event.run_id,
        started_at: event.timestamp,
        configuration: validated.config().clone(),
        fixture_id: "reference".into(),
        fixture_version: "planned".into(),
        software_versions: BTreeMap::from([("bgp-hijack".into(), "0.1.0".into())]),
        image_identities: BTreeMap::new(),
        artifacts: vec![ArtifactMetadata {
            path: "events.jsonl".into(),
            size_bytes: None,
            sha256: None,
            complete: false,
        }],
        complete: false,
    };
    let value = serde_json::to_value(&manifest).unwrap();
    assert_eq!(value["complete"], false);
    assert!(value["artifacts"][0]["sha256"].is_null());
    let decoded: Manifest = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.configuration.engine.local_asn.0, 4_200_000_001);
    assert_eq!(decoded.artifacts, manifest.artifacts);
}

#[test]
fn summary_preserves_result_and_cleanup_wire_names() {
    let value = json!({
        "schema_version": 1, "run_id": "example-run", "scenario": "forward",
        "policy_profile": "reject", "result": "inconclusive", "assertions": [],
        "cleanup_status": "unverified", "evidence_gaps": ["capture missing"]
    });
    let summary: RunSummary = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(summary.result, Verdict::Inconclusive);
    assert_eq!(summary.cleanup_status, CleanupStatus::Unverified);
    assert_eq!(serde_json::to_value(summary).unwrap(), value);
}
