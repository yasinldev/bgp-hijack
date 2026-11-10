use bgp_hijack_core::{
    config::parse_config,
    evidence::{EventEnvelope, EventKind, Manifest},
    journal::*,
};
use serde_json::{Map, Value, json};
use std::{cell::Cell, collections::BTreeMap, fs, io::Cursor, path::Path, time::Duration};
use time::OffsetDateTime;

fn manifest() -> Manifest {
    Manifest {
        schema_version: 1,
        run_id: "journal-test".into(),
        started_at: OffsetDateTime::UNIX_EPOCH,
        configuration: parse_config(
            include_str!("../../../examples/lab-forward.yaml"),
            Path::new("fixture.yaml"),
        )
        .unwrap()
        .config()
        .clone(),
        fixture_id: "unit-test".into(),
        fixture_version: "1".into(),
        software_versions: BTreeMap::new(),
        image_identities: BTreeMap::new(),
        artifacts: vec![],
        complete: true,
    }
}
fn draft() -> EventDraft {
    EventDraft {
        kind: EventKind::EvidenceGap,
        source_node: None,
        peer_id: None,
        address_family: None,
        prefix: None,
        evidence_refs: vec![],
        details: Map::from_iter([("reason".into(), json!("fixture observation"))]),
    }
}
struct ReversingWallClock {
    calls: Cell<u64>,
}
impl JournalClock for ReversingWallClock {
    fn sample(&self) -> (OffsetDateTime, Duration) {
        let value = self.calls.get();
        self.calls.set(value + 1);
        (
            OffsetDateTime::from_unix_timestamp(100 - value as i64).unwrap(),
            Duration::from_millis(value * 10),
        )
    }
}

fn lines() -> Vec<Vec<u8>> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    let mut writer = JournalWriter::create_with_clock(
        &path,
        manifest(),
        JournalLimits::default(),
        ReversingWallClock {
            calls: Cell::new(0),
        },
    )
    .unwrap();
    (0..3)
        .map(|_| {
            let event = writer.append(draft()).unwrap();
            let mut line = serde_json::to_vec(&event).unwrap();
            line.push(b'\n');
            line
        })
        .collect()
}

#[test]
fn writer_owns_metadata_and_keeps_manifest_incomplete_after_clean_close() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    let mut writer = JournalWriter::create_with_clock(
        &path,
        manifest(),
        JournalLimits::default(),
        ReversingWallClock {
            calls: Cell::new(0),
        },
    )
    .unwrap();
    let first = writer.append(draft()).unwrap();
    let second = writer.append(draft()).unwrap();
    assert_eq!((first.sequence, second.sequence), (1, 2));
    assert_eq!((first.elapsed_ms, second.elapsed_ms), (10, 20));
    assert!(second.timestamp < first.timestamp);
    drop(writer);
    let (manifest, mut reader) = JournalReader::open(&path, JournalLimits::default()).unwrap();
    assert!(!manifest.complete);
    assert_eq!(manifest.started_at.unix_timestamp(), 100);
    assert_eq!(manifest.artifacts[0].path, "events.jsonl");
    assert_eq!(manifest.artifacts[0].size_bytes, None);
    assert_eq!(manifest.artifacts[0].sha256, None);
    assert!(!manifest.artifacts[0].complete);
    let observed = reader.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(observed, vec![first, second]);
    assert_eq!(reader.status(), JournalReadStatus::CleanEof);
}

#[test]
fn creation_never_overwrites_and_checks_manifest_limits_before_creating() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("manifest.json"), "keep me").unwrap();
    assert!(matches!(
        JournalWriter::create(&path, manifest(), JournalLimits::default()),
        Err(JournalError::Io(_))
    ));
    assert_eq!(
        fs::read_to_string(path.join("manifest.json")).unwrap(),
        "keep me"
    );
    let missing = dir.path().join("new");
    let limits = JournalLimits {
        max_manifest_bytes: 4,
        ..JournalLimits::default()
    };
    assert!(matches!(
        JournalWriter::create(&missing, manifest(), limits),
        Err(JournalError::Limit("manifest"))
    ));
    assert!(!missing.exists());
    let mut wrong = manifest();
    wrong.schema_version = 2;
    assert!(matches!(
        JournalWriter::create(&missing, wrong, JournalLimits::default()),
        Err(JournalError::Invalid(_))
    ));
}

#[test]
fn every_partial_tail_preserves_only_newline_terminated_prefix() {
    let lines = lines();
    for cut in 0..lines[1].len() {
        let bytes = [lines[0].as_slice(), &lines[1][..cut]].concat();
        let mut reader = JournalReader::new(
            Cursor::new(bytes),
            "journal-test".into(),
            JournalLimits::default(),
        )
        .unwrap();
        assert_eq!(reader.next().unwrap().unwrap().sequence, 1);
        assert!(reader.next().is_none());
        assert_eq!(
            reader.status(),
            if cut == 0 {
                JournalReadStatus::CleanEof
            } else {
                JournalReadStatus::TruncatedTail
            }
        );
        assert!(reader.next().is_none());
    }
}

#[test]
fn corrupt_middle_records_stop_instead_of_skipping_to_later_records() {
    let lines = lines();
    for (field, value) in [
        ("schema_version", json!(2)),
        ("run_id", json!("other")),
        ("sequence", json!(1)),
        ("sequence", json!(3)),
        ("elapsed_ms", json!(0)),
    ] {
        let mut middle: Value = serde_json::from_slice(&lines[1]).unwrap();
        middle[field] = value;
        let mut bytes = lines[0].clone();
        bytes.extend(serde_json::to_vec(&middle).unwrap());
        bytes.push(b'\n');
        bytes.extend(&lines[2]);
        let mut reader = JournalReader::new(
            Cursor::new(bytes),
            "journal-test".into(),
            JournalLimits::default(),
        )
        .unwrap();
        assert!(reader.next().unwrap().is_ok());
        assert!(matches!(
            reader.next().unwrap(),
            Err(JournalError::Invalid(_))
        ));
        assert_eq!(reader.status(), JournalReadStatus::Failed);
        assert!(reader.next().is_none());
    }
    for corruption in [b"{bad json}\n".as_slice(), &[255, b'\n'], b"\n"] {
        let bytes = [lines[0].as_slice(), corruption, lines[2].as_slice()].concat();
        let mut reader = JournalReader::new(
            Cursor::new(bytes),
            "journal-test".into(),
            JournalLimits::default(),
        )
        .unwrap();
        assert!(reader.next().unwrap().is_ok());
        assert!(matches!(reader.next().unwrap(), Err(JournalError::Json(_))));
        assert!(reader.next().is_none());
    }
}

#[test]
fn bounded_reading_enforces_record_and_total_limits_including_newline() {
    let lines = lines();
    let length = lines[0].len();
    let limits = JournalLimits {
        max_record_bytes: length,
        max_journal_bytes: length as u64,
        ..JournalLimits::default()
    };
    let mut reader =
        JournalReader::new(Cursor::new(&lines[0]), "journal-test".into(), limits).unwrap();
    assert!(reader.next().unwrap().is_ok());
    assert!(reader.next().is_none());
    let mut reader = JournalReader::new(
        Cursor::new(&lines[0]),
        "journal-test".into(),
        JournalLimits {
            max_record_bytes: length - 1,
            ..limits
        },
    )
    .unwrap();
    assert!(matches!(
        reader.next().unwrap(),
        Err(JournalError::Limit("record"))
    ));
    let mut reader =
        JournalReader::new(Cursor::new(lines.concat()), "journal-test".into(), limits).unwrap();
    assert!(reader.next().unwrap().is_ok());
    assert!(matches!(
        reader.next().unwrap(),
        Err(JournalError::Limit(_))
    ));
    let mut reader = JournalReader::new(
        Cursor::new(vec![b'x'; length + 1]),
        "journal-test".into(),
        limits,
    )
    .unwrap();
    assert!(matches!(
        reader.next().unwrap(),
        Err(JournalError::Limit(_))
    ));
}

#[test]
fn writer_limits_leave_previous_records_intact_and_allow_smaller_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    let limits = JournalLimits {
        max_record_bytes: 512,
        max_journal_bytes: 512,
        ..JournalLimits::default()
    };
    let mut writer = JournalWriter::create(&path, manifest(), limits).unwrap();
    let mut huge = draft();
    huge.details
        .insert("large".into(), Value::from("x".repeat(1000)));
    assert!(matches!(
        writer.append(huge),
        Err(JournalError::Limit("record"))
    ));
    assert_eq!(fs::metadata(path.join("events.jsonl")).unwrap().len(), 0);
    assert_eq!(writer.append(draft()).unwrap().sequence, 1);
    let before = fs::read(path.join("events.jsonl")).unwrap();
    assert!(matches!(
        writer.append(draft()),
        Err(JournalError::Limit("journal"))
    ));
    assert_eq!(fs::read(path.join("events.jsonl")).unwrap(), before);
    let event: EventEnvelope = serde_json::from_slice(&before).unwrap();
    assert_eq!(event.sequence, 1);
}

#[test]
fn reader_checks_manifest_schema_and_size_without_claiming_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run");
    JournalWriter::create(&path, manifest(), JournalLimits::default()).unwrap();
    let (_, mut reader) = JournalReader::open(&path, JournalLimits::default()).unwrap();
    assert!(reader.next().is_none());
    assert_eq!(reader.status(), JournalReadStatus::CleanEof);
    let tiny = JournalLimits {
        max_manifest_bytes: 1,
        ..JournalLimits::default()
    };
    assert!(matches!(
        JournalReader::open(&path, tiny),
        Err(JournalError::Limit("manifest"))
    ));
    let mut wrong = manifest();
    wrong.schema_version = 2;
    fs::write(
        path.join("manifest.json"),
        serde_json::to_vec(&wrong).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        JournalReader::open(&path, JournalLimits::default()),
        Err(JournalError::Invalid(_))
    ));
}
