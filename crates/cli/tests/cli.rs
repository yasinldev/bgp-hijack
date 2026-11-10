use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use serde_json::json;

const EXAMPLE: &str = include_str!("../../../examples/lab-forward.yaml");

fn invoke(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bgp-hijack"))
        .current_dir(directory)
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn static_validation_succeeds_without_a_lab_and_reports_its_scope() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("lab.yaml"), EXAMPLE).unwrap();
    let output = invoke(
        dir.path(),
        &["validate", "--config", "lab.yaml", "--static"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        json!({
            "schema_version": 1, "scope": "static", "result": "passed", "runtime_verified": false
        })
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn invalid_configuration_is_stderr_only_with_file_context() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("bad.yaml"),
        EXAMPLE.replace("  id: reference", "  id: reference\n  id: duplicate"),
    )
    .unwrap();
    let output = invoke(
        dir.path(),
        &["validate", "--config", "bad.yaml", "--static"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("bad.yaml"));
    assert!(error.to_lowercase().contains("duplicate"));
}

#[test]
fn unavailable_operations_error_without_creating_outputs_or_reading_run_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    for arguments in [
        vec!["validate", "--config", "missing.yaml"],
        vec![
            "run",
            "--config",
            "missing.yaml",
            "--output",
            "new-artifacts",
        ],
        vec!["report", "--run", "missing-artifacts"],
    ] {
        let output = invoke(dir.path(), &arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("not implemented"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    fs::create_dir(dir.path().join("saved")).unwrap();
    fs::write(dir.path().join("saved/report.json"), "preserve this file").unwrap();
    let output = invoke(dir.path(), &["report", "--run", "saved"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(dir.path().join("saved/report.json")).unwrap(),
        "preserve this file"
    );
}

#[test]
fn help_version_and_argument_errors_follow_the_cli_contract() {
    let dir = tempfile::tempdir().unwrap();
    for arguments in [
        vec!["--help"],
        vec!["--version"],
        vec!["validate", "--help"],
    ] {
        let output = invoke(dir.path(), &arguments);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());
    }
    let help = invoke(dir.path(), &["validate", "--help"]);
    assert!(String::from_utf8_lossy(&help.stdout).contains("--static"));
    for arguments in [
        vec![],
        vec!["unknown"],
        vec!["validate", "--static"],
        vec!["report"],
    ] {
        let output = invoke(dir.path(), &arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn missing_static_input_returns_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let output = invoke(
        dir.path(),
        &["validate", "--config", "missing.yaml", "--static"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing.yaml"));
}
