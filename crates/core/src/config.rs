use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    SCHEMA_VERSION,
    error::ConfigError,
    model::{
        AddressFamily, Asn, CanonicalPrefix, PeerId, PolicyProfile, Scenario,
        is_documentation_address, is_identifier,
    },
};

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_YAML_DEPTH: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub lab: Lab,
    pub address_families: Vec<AddressFamily>,
    pub engine: Engine,
    pub scenario: ScenarioConfig,
    pub limits: Limits,
    pub capture_points: Vec<CapturePoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lab {
    pub id: String,
    pub topology: PathBuf,
    pub nodes: Nodes,
    pub prefixes: Prefixes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nodes {
    pub source: String,
    pub transit: String,
    pub target_router: String,
    pub target: String,
    pub experiment: String,
}

impl Nodes {
    pub fn entries(&self) -> [(&str, &str); 5] {
        [
            ("source", &self.source),
            ("transit", &self.transit),
            ("target_router", &self.target_router),
            ("target", &self.target),
            ("experiment", &self.experiment),
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prefixes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<CanonicalPrefix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<CanonicalPrefix>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engine {
    pub local_asn: Asn,
    pub router_id: Ipv4Addr,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub id: PeerId,
    pub node: String,
    pub interface: String,
    pub local_address: IpAddr,
    pub remote_address: IpAddr,
    pub remote_asn: Asn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioConfig {
    pub kind: Scenario,
    pub policy_profile: PolicyProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub baseline_seconds: u64,
    pub convergence_timeout_seconds: u64,
    pub observation_seconds: u64,
    pub active_timeout_seconds: u64,
    pub recovery_timeout_seconds: u64,
    pub max_probe_packets: u64,
    pub capture_max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePoint {
    pub node: String,
    pub interface: String,
}

/// A static validation result; this type never asserts that a lab is isolated.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    config: Config,
    topology_path: PathBuf,
}

impl ValidatedConfig {
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The configured path resolved relative to the configuration file, without I/O.
    pub fn topology_path(&self) -> &Path {
        &self.topology_path
    }
}

#[derive(Debug, Serialize)]
pub struct StaticValidationReport {
    pub schema_version: u32,
    pub scope: &'static str,
    pub result: &'static str,
    pub runtime_verified: bool,
}

impl ValidatedConfig {
    pub fn report(&self) -> StaticValidationReport {
        StaticValidationReport {
            schema_version: SCHEMA_VERSION,
            scope: "static",
            result: "passed",
            runtime_verified: false,
        }
    }
}

pub fn load_config(path: &Path) -> Result<ValidatedConfig, ConfigError> {
    let file = File::open(path).map_err(|source| ConfigError::Io {
        path: path.into(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigError::Io {
            path: path.into(),
            source,
        })?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(invalid(path, "document", "input exceeds the 1 MiB limit"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| invalid(path, "document", &format!("expected UTF-8: {error}")))?;
    parse_config(text, path)
}

pub fn parse_config(text: &str, path: &Path) -> Result<ValidatedConfig, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(invalid(path, "document", "input exceeds the 1 MiB limit"));
    }
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_depth: MAX_YAML_DEPTH,
            max_documents: 1,
            max_aliases: 0,
            max_anchors: 0,
        },
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        reject_unsupported_tags: true,
    };
    // Resolve YAML scalar types before deserializing the typed schema. Direct
    // typed YAML deserialization permits coercions such as "5" -> u64.
    let value: serde_json::Value =
        serde_saphyr::from_str_with_options(text, options).map_err(|source| ConfigError::Yaml {
            path: path.into(),
            source: Box::new(source),
        })?;
    let config: Config = serde_path_to_error::deserialize(value)
        .map_err(|error| invalid(path, &error.path().to_string(), &error.inner().to_string()))?;
    config.validate(path)?;
    let topology_path = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&config.lab.topology);
    Ok(ValidatedConfig {
        config,
        topology_path,
    })
}

impl Config {
    pub fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        let check = |field: &str, condition: bool, message: &str| {
            if condition {
                Ok(())
            } else {
                Err(invalid(path, field, message))
            }
        };
        check(
            "schema_version",
            self.schema_version == SCHEMA_VERSION,
            "only schema version 1 is supported",
        )?;
        check(
            "lab.id",
            is_identifier(&self.lab.id),
            "expected a nonempty identifier",
        )?;
        check(
            "lab.topology",
            !self.lab.topology.as_os_str().is_empty(),
            "a topology reference is required",
        )?;

        let mut nodes = HashSet::new();
        for (role, node) in self.lab.nodes.entries() {
            check(
                &format!("lab.nodes.{role}"),
                is_identifier(node),
                "expected a nonempty node identifier",
            )?;
            check(
                &format!("lab.nodes.{role}"),
                nodes.insert(node),
                "each role must reference a distinct node",
            )?;
        }

        let families: HashSet<_> = self.address_families.iter().copied().collect();
        check(
            "address_families",
            !families.is_empty(),
            "at least one family is required",
        )?;
        check(
            "address_families",
            families.len() == self.address_families.len(),
            "duplicate address families are not allowed",
        )?;
        for (family, prefix, field) in [
            (
                AddressFamily::Ipv4,
                self.lab.prefixes.ipv4,
                "lab.prefixes.ipv4",
            ),
            (
                AddressFamily::Ipv6,
                self.lab.prefixes.ipv6,
                "lab.prefixes.ipv6",
            ),
        ] {
            if let Some(prefix) = prefix {
                check(
                    field,
                    prefix.family() == family,
                    "prefix has the wrong address family",
                )?;
                check(
                    field,
                    prefix.is_documentation(),
                    "prefix must be contained in documentation address space",
                )?;
            } else {
                check(
                    field,
                    !families.contains(&family),
                    "a prefix is required for every enabled family",
                )?;
            }
        }

        check(
            "engine.local_asn",
            self.engine.local_asn.is_private(),
            "ASN must be in a private-use range",
        )?;
        check(
            "engine.router_id",
            is_documentation_address(self.engine.router_id.into()),
            "router ID must be an IPv4 documentation address",
        )?;
        check(
            "engine.peers",
            !self.engine.peers.is_empty(),
            "at least one lab peer is required",
        )?;
        let mut peer_ids = HashSet::new();
        let mut peer_endpoints = HashSet::new();
        for (index, peer) in self.engine.peers.iter().enumerate() {
            let field = format!("engine.peers[{index}]");
            check(
                &format!("{field}.id"),
                peer_ids.insert(&peer.id),
                "duplicate peer identity",
            )?;
            check(
                &format!("{field}.node"),
                nodes.contains(peer.node.as_str()) && peer.node != self.lab.nodes.experiment,
                "peer must reference another declared lab node",
            )?;
            check(
                &format!("{field}.interface"),
                valid_interface(&peer.interface),
                "expected an interface name of 1-15 ASCII letters, digits, '.', '_' or '-'",
            )?;
            check(
                &format!("{field}.remote_asn"),
                peer.remote_asn.is_private(),
                "ASN must be in a private-use range",
            )?;
            check(
                &format!("{field}.remote_asn"),
                peer.remote_asn != self.engine.local_asn,
                "the reference fixture requires eBGP peers with different ASNs",
            )?;
            for (label, address) in [
                ("local_address", peer.local_address),
                ("remote_address", peer.remote_address),
            ] {
                check(
                    &format!("{field}.{label}"),
                    address.is_ipv4(),
                    "the first-release BGP transport uses IPv4, including IPv6 unicast experiments",
                )?;
                check(
                    &format!("{field}.{label}"),
                    is_documentation_address(address),
                    "peer addresses must be in documentation address space",
                )?;
            }
            check(
                &field,
                peer.local_address != peer.remote_address,
                "local and remote peer addresses must differ",
            )?;
            check(
                &field,
                peer_endpoints.insert(peer.remote_address),
                "duplicate remote peer address",
            )?;
        }

        self.limits.validate(path)?;
        let mut points = HashSet::new();
        for (index, point) in self.capture_points.iter().enumerate() {
            let field = format!("capture_points[{index}]");
            check(
                &format!("{field}.node"),
                nodes.contains(point.node.as_str()),
                "capture point references an undeclared node",
            )?;
            check(
                &format!("{field}.interface"),
                valid_interface(&point.interface),
                "expected an interface name of 1-15 ASCII letters, digits, '.', '_' or '-'",
            )?;
            check(
                &field,
                points.insert((&point.node, &point.interface)),
                "duplicate capture point",
            )?;
        }
        for node in [
            &self.lab.nodes.source,
            &self.lab.nodes.experiment,
            &self.lab.nodes.target,
        ] {
            check(
                "capture_points",
                self.capture_points.iter().any(|point| &point.node == node),
                &format!("a capture point is required on {node}"),
            )?;
        }
        Ok(())
    }
}

impl Limits {
    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        for (name, value) in [
            ("baseline_seconds", self.baseline_seconds),
            (
                "convergence_timeout_seconds",
                self.convergence_timeout_seconds,
            ),
            ("observation_seconds", self.observation_seconds),
            ("active_timeout_seconds", self.active_timeout_seconds),
            ("recovery_timeout_seconds", self.recovery_timeout_seconds),
            ("max_probe_packets", self.max_probe_packets),
            ("capture_max_bytes", self.capture_max_bytes),
        ] {
            if value == 0 {
                return Err(invalid(path, &format!("limits.{name}"), "must be positive"));
            }
        }
        let required = self
            .baseline_seconds
            .checked_add(self.convergence_timeout_seconds)
            .and_then(|sum| sum.checked_add(self.observation_seconds))
            .ok_or_else(|| invalid(path, "limits", "phase duration sum overflows u64"))?;
        if required > self.active_timeout_seconds {
            return Err(invalid(
                path,
                "limits.active_timeout_seconds",
                "must cover baseline, convergence and observation durations",
            ));
        }
        self.active_timeout_seconds
            .checked_add(self.recovery_timeout_seconds)
            .and_then(|seconds| seconds.checked_mul(1000))
            .ok_or_else(|| {
                invalid(
                    path,
                    "limits",
                    "total duration cannot be represented in milliseconds",
                )
            })?;
        Ok(())
    }
}

fn valid_interface(value: &str) -> bool {
    is_identifier(value) && value.len() <= 15
}

fn invalid(path: &Path, field: &str, message: &str) -> ConfigError {
    ConfigError::Invalid {
        path: path.into(),
        field: field.into(),
        message: message.into(),
    }
}
