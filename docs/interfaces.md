# CLI, configuration, and artifacts

**Status: partially implemented (Sprint 2).** The public binary implements `validate --static`. Core configuration/evidence types and durable journal writing/reading are available. Live validation, `run`, artifact-based `report`, and the referenced five-role fixture remain planned. Separate developer lab/fuzz tools are described in the [development guide](development.md).

## Commands

| Command | Inputs | Behavior |
| --- | --- | --- |
| `validate --static` | `--config <yaml>` | **Implemented:** file-only schema and value validation. Successful JSON includes `scope: "static"` and `runtime_verified: false`; the topology need not exist. |
| `validate` | `--config <yaml>` | Validate the configuration and inspect the prepared lab's inventory, isolation, and declared compatibility without activating a scenario. |
| `run` | `--config <yaml> --output <new-directory>` | Repeat preflight, negotiate required sessions, establish baseline, execute in the foreground, roll back, and write artifacts. |
| `report` | `--run <artifact-directory>` | Re-evaluate saved evidence offline and print a JSON report to stdout. No live network access or mutation of the saved run. |

Currently executable example:

```sh
cargo run --locked -p bgp-hijack -- validate --config examples/lab-forward.yaml --static
```

Planned live/artifact commands (currently return code `2` with an explicit unsupported-operation error):

```sh
bgp-hijack validate --config lab-forward.yaml
bgp-hijack run --config lab-forward.yaml --output artifacts/forward-001
bgp-hijack report --run artifacts/forward-001
```

For future live validation and execution, the lab must already be prepared using its pinned Containerlab fixture. The first-release CLI will not deploy arbitrary topologies. Live `validate` will inspect fixture declarations and available lab state; actual capability negotiation will occur during `run` before activation. Successful static validation does not verify topology existence, real interfaces, isolation, peer capabilities, fixture membership, or measurement-budget adequacy and will not bypass the run's fresh checks.

`run` will require a new output directory, refusing to overwrite an existing run. Diagnostics and progress will go to stderr. Its final JSON report will go to stdout and to `report.json`. `report` will print the regenerated report without replacing that original file. SIGINT and SIGTERM will initiate bounded rollback; an interruption will never be reported as an ordinary successful run.

| Exit code | Meaning |
| --- | --- |
| `0` | Validation passed, or a run/report verdict is `passed`. |
| `1` | A run/report verdict is `failed`. |
| `2` | Invalid invocation, configuration, preflight, unsupported artifact schema, or an I/O failure preventing evaluation. |
| `3` | A run/report verdict is `inconclusive`. |
| `130` | An interrupted live run, after its bounded recovery attempt. |

An offline report of an interrupted run will use its evaluated verdict code, normally `3`; the original interruption remains in its events. If an output failure prevents a report from being written, the command will return `2` and explain that failure on stderr.

## Proposed configuration

The example is accepted by the implemented static validator and is available as [examples/lab-forward.yaml](../examples/lab-forward.yaml). It is not a deployable topology. The referenced `reference.clab.yaml`, nodes, and interfaces will be supplied during the lab milestone.

```yaml
schema_version: 1
lab:
  id: reference
  topology: reference.clab.yaml
  nodes:
    source: client
    transit: transit
    target_router: target-router
    target: target
    experiment: experiment
  prefixes:
    ipv4: 192.0.2.0/24
    ipv6: 2001:db8:100::/48
address_families:
  - ipv4
  - ipv6
engine:
  local_asn: 4200000001
  router_id: 203.0.113.1
  peers:
    - id: transit
      node: transit
      interface: lab-transit
      local_address: 198.51.100.1
      remote_address: 198.51.100.2
      remote_asn: 4200000002
scenario:
  kind: forward
  policy_profile: accept
limits:
  baseline_seconds: 5
  convergence_timeout_seconds: 30
  observation_seconds: 10
  active_timeout_seconds: 120
  recovery_timeout_seconds: 30
  max_probe_packets: 1000
  capture_max_bytes: 16777216
capture_points:
  - node: client
    interface: lab-transit
  - node: experiment
    interface: lab-transit
  - node: target
    interface: lab-router
```

| Field group | Contract |
| --- | --- |
| `schema_version` | Configuration format version; initially `1`. |
| `lab` | Fixture identity, topology path, role-to-node mapping, and test prefixes. |
| `address_families` | Nonempty selection of `ipv4`, `ipv6`, or both. |
| `engine` | Local ASN/identifier and declared lab neighbors. The engine runs on the `experiment` role. |
| `scenario` | `kind` is `forward` or `blackhole`; `policy_profile` is `accept` or `reject`. |
| `limits` | Explicit finite phase durations, total active deadline, probe budget, and capture budget. |
| `capture_points` | Declared lab nodes/interfaces on which selected test traffic will be recorded. |

All shown fields are required in version 1 except a prefix for an inactive family, which may be omitted. Durations are seconds. The active deadline starts with baseline collection and excludes the separately bounded recovery interval. The capture limit is aggregate bytes across capture points, and the probe budget is aggregate across enabled families for the entire run, including baseline and recovery. These example limits bound an experiment; they are not performance guarantees.

The topology path will resolve relative to the YAML file. Output location will be supplied only by `--output`, avoiding conflicting output settings. The selected fixture will define the corresponding lab routes, policy profiles, next hops, and observation rules; YAML will not provide an arbitrary outbound BGP packet or public-peer interface.

Implemented static validation rejects unknown fields, duplicate YAML keys, incorrect scalar types, duplicate peer identities/endpoints, noncanonical prefixes, undeclared node references, invalid interface-name syntax, unsupported scenarios, and empty/duplicate family selections. Inputs are limited to one UTF-8 document, 1 MiB, and 64 nesting levels; YAML anchors, aliases, merge keys, and unsupported tags are disabled. YAML is first parsed to scalar-preserving JSON values and then checked against the typed schema, with field paths retained in errors.

The static address subset is IPv4 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and IPv6 `2001:db8::/32`. Configured ASNs must be private-use values, and an eBGP peer must have a different ASN from the local one. The five node roles must be distinct; captures on source, experiment, and target are required. Interface names accept 1-15 ASCII letters, digits, '.', '_' or '-'. The first-release transport endpoints use IPv4, including experiments carrying IPv6 unicast routes.

Future live validation will additionally check actual interfaces, fixture address/ASN membership, observed peer identity, and observation readiness. Required families, captures, and test resources cannot be silently skipped.

Each family must have its corresponding prefix and endpoint measurements. Peer addresses must resolve to the declared lab interface in the actual topology. Duration and packet budgets must permit the fixture's baseline, observation, and recovery measurements. Failure to prove these conditions will prevent activation.

## Artifact layout

The core implements serializable `EventEnvelope`, `Manifest`, `AssertionResult`, and `RunSummary` types. Sprint 2 adds a durable journal API that initializes manifests, assigns event metadata, and reads complete journal prefixes with schema/run/order checks. The CLI does not generate runtime events. Deserializing evidence types alone still does not validate artifact paths, hashes, or run completeness; full artifact verification remains future work.

The run directory will contain:

```text
manifest.json
events.jsonl
report.json
captures/
  <capture-point>.pcapng
snapshots/
  <observation>.json
```

| Artifact | Required contents |
| --- | --- |
| `manifest.json` | Schema/run identifiers; effective configuration; fixture and software versions; image identities; artifact inventory; completeness and integrity metadata. |
| `events.jsonl` | Ordered observations, phase changes, mutation/recovery journal entries, evidence gaps, and assertion evaluations. |
| `report.json` | Scenario, per-family assertions, recovery status, aggregate verdict, and supporting evidence references. |
| `captures/` | PCAPNG recordings with interface identity and capture/drop statistics for the selected flows. |
| `snapshots/` | Timestamped route, policy, endpoint, and relevant lab-state observations. |

The journal initializes and synchronizes the manifest before returning a writer. Every append is flushed and synchronized before success. Manifest finalization after recovery/reporting remains planned; Sprint 2 leaves completeness false and artifact sizes/hashes unknown. Future artifact readers will require references relative to the run directory and reject escaping paths. An interrupted run may lack a final report or finalized hashes; its incomplete state remains distinguishable from verified artifacts.

`JournalLimits` defaults to 1 MiB per record including newline, 64 MiB per journal and 4 MiB per manifest. These Rust API settings do not add fields to YAML schema 1. The reader retains complete events before a truncated tail, but stops with an error on malformed complete records, schema/run mismatch, sequence gaps or regressing elapsed time. Clean EOF does not mark a run complete. See [journal durability](development.md#journal-api-and-durability) for creation and I/O-error behavior.

The implemented manifest fields are `schema_version`, `run_id`, `started_at`, `configuration`, `fixture_id`, `fixture_version`, `software_versions`, `image_identities`, `artifacts`, and `complete`. Each artifact entry contains `path`, nullable `size_bytes` and `sha256`, and `complete`; unknown integrity data remains `null`. Version and image identities are string maps. `started_at` uses the same UTC timestamp representation as events.

## Event envelope

| Field | Meaning |
| --- | --- |
| `schema_version` | Event format version, initially `1`. |
| `run_id` | Identifier shared by all artifacts of one experiment. |
| `sequence` | Increasing journal sequence number within that run. |
| `timestamp` | UTC observation timestamp in RFC 3339 form. |
| `elapsed_ms` | Monotonic time since run start for local ordering/duration analysis. |
| `kind` | Typed event category. |
| `source_node` | Lab node supplying the observation, or `null` for coordinator-only events. |
| `peer_id` | Configured peer identity, or `null` when not applicable. |
| `address_family` | `ipv4`, `ipv6`, or `null` for non-route/non-flow events. |
| `prefix` | Canonical prefix, or `null` when not applicable. |
| `evidence_refs` | Relative artifact references supporting the observation. |
| `details` | Kind-specific payload; route/session events include the session epoch. |

The implemented event-kind names are `phase.changed`, `session.changed`, `route.observed`, `peer_policy.observed`, `probe.observed`, `mutation.recorded`, `recovery.recorded`, `evidence.gap`, and `assertion.evaluated`. `details` currently accepts JSON objects; specific payload types will accompany their producers. Serialization normalizes timestamps to UTC. The CLI does not emit placeholder events.

Illustrative event, unrelated to an actual run:

```json
{
  "schema_version": 1,
  "run_id": "example-run",
  "sequence": 12,
  "timestamp": "2026-11-08T12:00:00Z",
  "elapsed_ms": 5000,
  "kind": "assertion.evaluated",
  "source_node": "client",
  "peer_id": null,
  "address_family": "ipv4",
  "prefix": "192.0.2.0/24",
  "evidence_refs": [
    "snapshots/ipv4-baseline.json",
    "captures/client.pcapng"
  ],
  "details": {
    "assertion": "baseline_delivery",
    "result": "passed"
  }
}
```

Origin ASNs will be recorded as observations, not as an `attacker_asn` attribution. Neither this event nor a successful route update alone is a whole-run verdict.

## Report semantics

Reports will include `schema_version`, `run_id`, `scenario`, `policy_profile`, `result`, per-family `assertions`, `cleanup_status`, and `evidence_gaps`. Each assertion will identify its expectation, observation, verdict, and evidence references. Cleanup status will be `completed`, `failed`, or `unverified`.

The implemented `AssertionResult` fields are `id`, `address_family`, `expectation`, `observation`, `result`, and `evidence_refs`. The pure evaluator takes expected `(id, address_family)` keys, observations, enabled families, completion/interruption flags, cleanup status, and evidence gaps. Empty or duplicate requirements, missing family coverage, duplicate/unexpected observations, blank observations, or missing evidence references cannot produce `passed`. A supported failure with evidence takes precedence over incomplete data. Evidence references are currently assessed for presence only; the caller supplies trusted observations and cleanup status.

Aggregation order is fixed:

1. A conclusively violated assertion, including a proven recovery failure, produces `failed`.
2. Otherwise, missing required evidence, an unfinished run, an interruption, or unverified recovery produces `inconclusive`.
3. Only a normal completed run with all required assertions passed and cleanup verified produces `passed`.

A dual-family run requires both families to pass. A successful `reject` policy is evaluated against the rejection expectation. A timeout is not automatically proof of the desired blackhole behavior. Proven failures will not be hidden by an unrelated evidence gap.

The offline evaluator will share the live evaluator's rules. It will check the manifest, event sequence, schema compatibility, and referenced artifacts. A truncated final journal record will be treated as interrupted evidence; earlier complete records remain usable. A missing artifact or integrity mismatch prevents any dependent assertion from passing. The reader will never fabricate missing events to obtain a passing result.

Schema version `1` is the implemented model contract; runtime production and artifact validation remain planned. Future incompatible changes will require an explicit new schema version and compatibility notes. Reports will not claim to replay BGP traffic: this command re-evaluates saved evidence only.
