use std::{path::Path, process::Command};
fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bgp-hijack"))
}
#[test]
fn offline_commands_report_and_legacy_namespace() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../analysis/tests/fixtures");
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("capture");
    let r = binary()
        .args(["inspect", "pcap"])
        .arg(root.join("session.pcap"))
        .arg("--output")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    assert!(r.stderr.is_empty());
    let r = binary()
        .args(["report", "--analysis"])
        .arg(&dir)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(r.status.success());
    let s: serde_json::Value = serde_json::from_slice(&r.stdout).unwrap();
    assert_eq!(s["coverage"], "selected_input");
    assert_eq!(s["findings"].as_array().unwrap().len(), 2);
    let r = binary()
        .args(["lab", "validate", "--static", "--config"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/lab-forward.yaml"))
        .output()
        .unwrap();
    assert!(r.status.success());
    let r = binary()
        .args(["lab", "run", "--config", "missing", "--output"])
        .arg(temp.path().join("forbidden"))
        .output()
        .unwrap();
    assert_eq!(r.status.code(), Some(2));
    assert!(!temp.path().join("forbidden").exists());
}
#[test]
fn missing_context_and_invalid_args_do_not_claim_success() {
    let temp = tempfile::tempdir().unwrap();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../analysis/tests/fixtures/midstream.pcap");
    let r = binary()
        .args(["inspect", "pcap"])
        .arg(fixture)
        .arg("--output")
        .arg(temp.path().join("partial"))
        .output()
        .unwrap();
    assert_eq!(r.status.code(), Some(4));
    let r = binary()
        .args(["lookup", "prefix", "203.0.113.1/24"])
        .output()
        .unwrap();
    assert_eq!(r.status.code(), Some(2));
    assert!(r.stdout.is_empty());
    let r = binary()
        .args(["lookup", "asn", "4294967296"])
        .output()
        .unwrap();
    assert_eq!(r.status.code(), Some(2));
}
