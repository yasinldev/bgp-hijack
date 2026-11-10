use std::{fs, path::Path};

use bgp_hijack_core::{
    config::{MAX_CONFIG_BYTES, load_config, parse_config},
    error::ConfigError,
    model::{AddressFamily, CanonicalPrefix},
};

const EXAMPLE: &str = include_str!("../../../examples/lab-forward.yaml");

fn rejects(text: &str, expected: &str) {
    let error = parse_config(text, Path::new("fixtures/lab.yaml"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("fixtures/lab.yaml"), "{error}");
    assert!(
        error.to_lowercase().contains(&expected.to_lowercase()),
        "expected {expected:?}: {error}"
    );
}

#[test]
fn documentation_example_and_single_family_variants_are_valid() {
    for (families, prefix_to_remove, expected) in [
        (
            "  - ipv4\n  - ipv6",
            "",
            vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
        ),
        (
            "  - ipv4",
            "    ipv6: 2001:db8:100::/48\n",
            vec![AddressFamily::Ipv4],
        ),
        (
            "  - ipv6",
            "    ipv4: 192.0.2.0/24\n",
            vec![AddressFamily::Ipv6],
        ),
    ] {
        let text = EXAMPLE
            .replace("  - ipv4\n  - ipv6", families)
            .replace(prefix_to_remove, "");
        let validated = parse_config(&text, Path::new("fixtures/configs/lab.yaml")).unwrap();
        assert_eq!(validated.config().address_families, expected);
        assert_eq!(validated.config().engine.local_asn.0, 4_200_000_001);
        assert_eq!(
            validated.config().engine.peers[0].remote_asn.0,
            4_200_000_002
        );
        assert_eq!(
            validated.topology_path(),
            Path::new("fixtures/configs/reference.clab.yaml")
        );
        assert_eq!(
            serde_json::to_value(validated.report()).unwrap(),
            serde_json::json!({
                "schema_version": 1, "scope": "static", "result": "passed", "runtime_verified": false
            })
        );
    }
}

#[test]
fn rejects_unknown_duplicate_and_wrongly_typed_fields() {
    for (from, to, expected) in [
        ("schema_version: 1", "schema_version: 2", "schema_version"),
        (
            "schema_version: 1",
            "schema_version: \"1\"",
            "schema_version",
        ),
        ("  id: reference", "  id: 123", "lab.id"),
        (
            "topology: reference.clab.yaml",
            "topology: false",
            "lab.topology",
        ),
        (
            "  baseline_seconds: 5",
            "  baseline_seconds: \"5\"",
            "limits.baseline_seconds",
        ),
        (
            "schema_version: 1",
            "schema_version: 1\nunknown: true",
            "unknown",
        ),
        (
            "  id: reference",
            "  id: reference\n  unknown: 1",
            "unknown",
        ),
        (
            "  id: reference",
            "  id: reference\n  id: duplicate",
            "duplicate",
        ),
        (
            "  baseline_seconds: 5",
            "  baseline_seconds: 5\n  baseline_seconds: 6",
            "duplicate",
        ),
        (
            "  baseline_seconds: 5",
            "  baseline_seconds: false",
            "invalid",
        ),
        (
            "  baseline_seconds: 5",
            "  baseline_seconds: 1.5",
            "invalid",
        ),
        ("  baseline_seconds: 5", "  baseline_seconds: -1", "invalid"),
        ("  kind: forward", "  kind: unknown", "unknown"),
        (
            "      remote_asn: 4200000002",
            "      remote_asn: 4294967296",
            "invalid",
        ),
    ] {
        rejects(&EXAMPLE.replace(from, to), expected);
    }
}

#[test]
fn rejects_invalid_prefixes_and_family_coverage() {
    for (from, to, expected) in [
        ("192.0.2.0/24", "192.0.2.5/24", "host bits"),
        ("2001:db8:100::/48", "2001:db8:100::1/48", "host bits"),
        ("192.0.2.0/24", "192.0.2.0/23", "documentation"),
        ("192.0.2.0/24", "8.8.8.0/24", "documentation"),
        ("2001:db8:100::/48", "2001:db8::/31", "documentation"),
        ("192.0.2.0/24", "2001:db8::/32", "wrong address family"),
        ("    ipv6: 2001:db8:100::/48\n", "", "lab.prefixes.ipv6"),
        (
            "address_families:\n  - ipv4\n  - ipv6",
            "address_families: []",
            "at least one family",
        ),
        (
            "  - ipv4\n  - ipv6",
            "  - ipv4\n  - ipv4",
            "duplicate address families",
        ),
    ] {
        rejects(&EXAMPLE.replace(from, to), expected);
    }
    assert!("192.0.2.0/33".parse::<CanonicalPrefix>().is_err());
    assert!("2001:db8::/129".parse::<CanonicalPrefix>().is_err());
}

#[test]
fn checks_private_asn_boundaries_without_truncation() {
    for asn in [64512_u32, 65534, 4_200_000_000, 4_294_967_294] {
        let config = parse_config(
            &EXAMPLE.replace("local_asn: 4200000001", &format!("local_asn: {asn}")),
            Path::new("test.yaml"),
        )
        .unwrap();
        let json = serde_json::to_value(config.config()).unwrap();
        assert_eq!(json["engine"]["local_asn"].as_u64(), Some(u64::from(asn)));
    }
    for asn in [0_u32, 64511, 65535, 4_199_999_999, u32::MAX] {
        rejects(
            &EXAMPLE.replace("local_asn: 4200000001", &format!("local_asn: {asn}")),
            "private-use",
        );
    }
}

#[test]
fn enforces_consistent_lab_references_and_peers() {
    for (from, to, expected) in [
        (
            "    transit: transit",
            "    transit: client",
            "distinct node",
        ),
        (
            "      node: transit",
            "      node: missing",
            "declared lab node",
        ),
        (
            "      remote_asn: 4200000002",
            "      remote_asn: 4200000001",
            "different ASNs",
        ),
        (
            "remote_address: 198.51.100.2",
            "remote_address: 198.51.100.1",
            "must differ",
        ),
        (
            "remote_address: 198.51.100.2",
            "remote_address: 8.8.8.8",
            "documentation",
        ),
        (
            "remote_address: 198.51.100.2",
            "remote_address: 2001:db8::2",
            "transport uses IPv4",
        ),
        (
            "router_id: 203.0.113.1",
            "router_id: 8.8.8.8",
            "engine.router_id",
        ),
        ("    - id: transit", "    - id: ' '", "peer ID"),
        (
            "interface: lab-transit",
            "interface: 'too-long-interface-name'",
            "interface",
        ),
        (
            "  - node: target\n    interface: lab-router\n",
            "",
            "capture point is required",
        ),
        ("  - node: target", "  - node: missing", "undeclared node"),
    ] {
        rejects(&EXAMPLE.replace(from, to), expected);
    }
    let peer = EXAMPLE
        .split("  peers:\n")
        .nth(1)
        .unwrap()
        .split("scenario:\n")
        .next()
        .unwrap();
    rejects(
        &EXAMPLE.replace("scenario:\n", &format!("{peer}scenario:\n")),
        "duplicate peer identity",
    );
    let second_peer = peer.replace("id: transit", "id: another");
    rejects(
        &EXAMPLE.replace("scenario:\n", &format!("{second_peer}scenario:\n")),
        "duplicate remote peer address",
    );
    rejects(
        &format!("{EXAMPLE}  - node: target\n    interface: lab-router\n"),
        "duplicate capture point",
    );
}

#[test]
fn checks_positive_budgets_and_overflow() {
    for (from, to, expected) in [
        (
            "baseline_seconds: 5",
            "baseline_seconds: 0",
            "must be positive",
        ),
        (
            "max_probe_packets: 1000",
            "max_probe_packets: 0",
            "must be positive",
        ),
        (
            "capture_max_bytes: 16777216",
            "capture_max_bytes: 0",
            "must be positive",
        ),
        (
            "active_timeout_seconds: 120",
            "active_timeout_seconds: 40",
            "must cover",
        ),
        (
            "baseline_seconds: 5",
            "baseline_seconds: 18446744073709551615",
            "overflows",
        ),
        (
            "active_timeout_seconds: 120",
            "active_timeout_seconds: 18446744073709551615",
            "milliseconds",
        ),
    ] {
        rejects(&EXAMPLE.replace(from, to), expected);
    }
}

#[test]
fn rejects_multiple_documents_aliases_merges_and_excessive_nesting() {
    rejects(&format!("{EXAMPLE}\n---\n{EXAMPLE}"), "document");
    rejects(
        &EXAMPLE.replace("  id: reference", "  id: &name reference"),
        "anchor",
    );
    rejects(
        &format!("{}0{}", "[".repeat(65), "]".repeat(65)),
        "budget breached: Depth",
    );
    // Exactly 64 levels pass the parser budget and reach typed schema checking.
    assert!(matches!(
        parse_config(
            &format!("{}0{}", "[".repeat(64), "]".repeat(64)),
            Path::new("depth-boundary.yaml")
        ),
        Err(ConfigError::Invalid { .. })
    ));
    assert!(
        parse_config(
            &EXAMPLE.replace("lab:\n", "lab:\n  <<: {id: reference}\n"),
            Path::new("merge.yaml")
        )
        .is_err()
    );
}

#[test]
fn bounded_file_loading_preserves_file_context_and_does_not_require_a_topology() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lab.yaml");
    fs::write(&path, EXAMPLE).unwrap();
    assert!(load_config(&path).is_ok());
    assert!(!dir.path().join("reference.clab.yaml").exists());
    let mut exact_limit = EXAMPLE.to_owned();
    exact_limit.push('#');
    exact_limit.extend(std::iter::repeat_n(
        'x',
        MAX_CONFIG_BYTES - exact_limit.len(),
    ));
    fs::write(&path, &exact_limit).unwrap();
    assert!(load_config(&path).is_ok());
    exact_limit.push('x');
    fs::write(&path, &exact_limit).unwrap();
    assert!(
        load_config(&path)
            .unwrap_err()
            .to_string()
            .contains("1 MiB")
    );
    rejects(&exact_limit, "1 MiB");
    fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(
        load_config(&path)
            .unwrap_err()
            .to_string()
            .contains("UTF-8")
    );
    let missing = dir.path().join("missing.yaml");
    assert!(
        load_config(&missing)
            .unwrap_err()
            .to_string()
            .contains("missing.yaml")
    );
}
