# CLI, configuration, and artifacts

**Status: planned.** The commands, configuration, and artifact examples below specify a proposed interface. No `bgp-hijack` binary or referenced lab fixture is available yet.

## Commands

| Command | Inputs | Behavior |
| --- | --- | --- |
| `validate` | `--config <yaml>` | Validate the configuration and inspect the prepared lab's inventory, isolation, and declared compatibility without activating a scenario. |
| `run` | `--config <yaml> --output <new-directory>` | Repeat preflight, negotiate required sessions, establish baseline, execute in the foreground, roll back, and write artifacts. |
| `report` | `--run <artifact-directory>` | Re-evaluate saved evidence offline and print a JSON report to stdout. No live network access or mutation of the saved run. |

Illustrative commands for a future implementation:

```sh
bgp-hijack validate --config lab-forward.yaml
bgp-hijack run --config lab-forward.yaml --output artifacts/forward-001
bgp-hijack report --run artifacts/forward-001
```

The lab must already be prepared using its pinned Containerlab fixture. The first-release CLI will not deploy arbitrary topologies. `validate` will inspect fixture declarations and available lab state; actual capability negotiation will occur during `run` before activation. A successful validation will not bypass the run's fresh checks.

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

The example is a design fixture, not a deployable topology. The referenced `reference.clab.yaml`, nodes, and interfaces will be supplied during the lab milestone.

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

All shown fields will be required in version 1. Durations are seconds. The active deadline starts with baseline collection and excludes the separately bounded recovery interval. The capture limit is aggregate bytes across capture points, and the probe budget is aggregate across enabled families for the entire run, including baseline and recovery. These example limits bound an experiment; they are not performance guarantees.

The topology path will resolve relative to the YAML file. Output location will be supplied only by `--output`, avoiding conflicting output settings. The selected fixture will define the corresponding lab routes, policy profiles, next hops, and observation rules; YAML will not provide an arbitrary outbound BGP packet or public-peer interface.

Version 1 validation will reject unknown fields, duplicate YAML keys, duplicate peer identities, noncanonical prefixes, undeclared nodes/interfaces, unsupported scenarios, and empty family selections. Prefixes and peer endpoints must belong to the fixture's declared closed address plan. Both configured and observed ASNs must match the fixture's private ASN inventory. Required families, captures, and test resources cannot be silently skipped.

Each family must have its corresponding prefix and endpoint measurements. Peer addresses must resolve to the declared lab interface in the actual topology. Duration and packet budgets must permit the fixture's baseline, observation, and recovery measurements. Failure to prove these conditions will prevent activation.

## Artifact layout

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

The manifest will be initialized before mutation and finalized after recovery/reporting. Evidence references will be relative to the run directory, and readers will reject references escaping that directory. Finalized artifacts will have recorded sizes and hashes. An interrupted run may lack a final report or finalized hashes; its incomplete state must remain distinguishable from verified artifacts.

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

Initial event kinds will be `phase.changed`, `session.changed`, `route.observed`, `peer_policy.observed`, `probe.observed`, `mutation.recorded`, `recovery.recorded`, `evidence.gap`, and `assertion.evaluated`.

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

Aggregation order is fixed:

1. A conclusively violated assertion, including a proven recovery failure, produces `failed`.
2. Otherwise, missing required evidence, an unfinished run, an interruption, or unverified recovery produces `inconclusive`.
3. Only a normal completed run with all required assertions passed and cleanup verified produces `passed`.

A dual-family run requires both families to pass. A successful `reject` policy is evaluated against the rejection expectation. A timeout is not automatically proof of the desired blackhole behavior. Proven failures will not be hidden by an unrelated evidence gap.

The offline evaluator will share the live evaluator's rules. It will check the manifest, event sequence, schema compatibility, and referenced artifacts. A truncated final journal record will be treated as interrupted evidence; earlier complete records remain usable. A missing artifact or integrity mismatch prevents any dependent assertion from passing. The reader will never fabricate missing events to obtain a passing result.

Schema version `1` is a planned contract. Future incompatible changes will require an explicit new schema version and compatibility notes. Reports will not claim to replay BGP traffic: this command re-evaluates saved evidence only.
