# Product definition

**Status: planned.** All runtime capabilities below are requirements for a future implementation.

## Purpose and users

`bgp-hijack` will let blue teams, red teams working in the reference lab, network engineers, and protocol researchers run repeatable routing experiments. A useful result will explain what changed in BGP, what happened to the selected test traffic, how a prefix filter responded, and whether the lab recovered.

The first release will answer a concrete question: given a known topology and a declared prefix policy, does a controlled route change produce the expected forwarding or packet-drop behavior for IPv4 and IPv6?

## First-release scope

| Area | Included |
| --- | --- |
| BGP implementation | A Rust codec and session engine for controlled eBGP sessions; IPv4/IPv6 unicast and four-octet ASN support. |
| Route observations | Peer-specific announcements, withdrawals, session epochs, and snapshots associated with a run. |
| Environment | A Linux Containerlab reference topology with FRR peers and synthetic client/target traffic. |
| Experiments | `forward` and `blackhole`, each under `accept` and `reject` prefix-policy fixtures. |
| Evidence | Session and route events, peer route/policy observations, endpoint measurements, and bounded PCAPNG captures. |
| Lifecycle | Preflight, baseline, scenario, observation, rollback, and recovery verification. |
| Interface | Foreground CLI, YAML configuration, JSONL events, and a JSON report. |

The first implementation is a scenario-specific BGP speaker, not a commitment to implementing every function of an Internet router. Its protocol subset and exclusions are defined in [Protocol](protocol.md).

## Product boundary

Active experiments will run only in the declared isolated lab. Reference fixtures will use documentation prefixes and private-use ASNs. Lab topology, neighbor inventory, and observed routes will supply prefix and ASN context; the first release will not perform reconnaissance against public targets or establish external production peers.

Topology isolation is an enforced runtime prerequisite. An acknowledgment flag or legal notice will not replace it. The requirements are described in [Lab and scenarios](lab-and-scenarios.md).

The reference workload will consist of bounded synthetic probes and a controlled test service. Blackhole tests will exercise intentional packet dropping, not capacity exhaustion. Recording encrypted packets will not be presented as decrypting application content.

## User journeys

### Reproduce a routing effect

A researcher will select the reference topology, `forward` or `blackhole`, an address family, and a policy fixture. The tool will verify the lab, establish a baseline, execute the experiment, collect evidence, restore the baseline, and produce a report that another researcher can inspect offline.

### Check a prefix filter

A network engineer will compare `accept` and `reject` runs using the same scenario and test traffic. A rejecting policy will be successful when evidence shows that the relevant update reached the peer, the policy rejected it, and baseline delivery remained intact. Absence of redirected traffic by itself will not prove that a filter worked.

### Investigate an incomplete run

An operator will inspect the event journal and partial artifacts after a timeout, peer failure, or interruption. The result will distinguish an observed failed assertion from an inability to evaluate it. Recovery status will remain visible even when the scenario verdict cannot be determined.

## Success criteria

The first release will be complete when all eight combinations of two scenarios, two address families, and two policy profiles satisfy the [acceptance matrix](lab-and-scenarios.md#acceptance-matrix) in the reference lab.

Each normal completed run will:

- Identify the fixture, configuration, software versions, address family, and policy under test.
- Preserve the relevant BGP observations and independently measured traffic evidence.
- Evaluate the configured expectation, including successful rejection by a defensive policy.
- Restore experiment-owned changes and verify endpoint reachability and routing recovery.
- Produce the same verdict when the saved artifacts are evaluated by the offline report command.

Missing evidence will not produce `passed`. Confirmed behavior contrary to an assertion will produce `failed`; uncertainty will produce `inconclusive`. These rules apply independently to the scenario and recovery checks before aggregation.

## Subsequent milestones

| Capability | Prerequisite and intended purpose |
| --- | --- |
| RPKI/ROV | Add local validation fixtures after prefix-policy tests are reliable. |
| Service impersonation | Add a controlled alternate service and client identity-validation checks after forwarding behavior is verified. |
| RIS Live and BMP adapters | Add passive sources with explicit source identity, freshness, and visibility limitations. |
| IRR and ASPA analysis | Add evidence sources with separate trust/freshness semantics and a pinned standards baseline. |
| TUI | Present existing events and results after the CLI/artifact contract stabilizes. |
| Prometheus, STIX, and CEF | Export the established event model after its semantics are tested. |
| eBPF and performance optimization | Introduce only when measured bottlenecks justify the additional complexity. |
| Additional BGP capabilities | Extend the tested protocol subset incrementally. |

ASPA and BGP Roles/OTC will be tracked as separate capabilities. [RFC 9234](https://www.rfc-editor.org/rfc/rfc9234.html) defines Roles/OTC; ASPA path verification has its own [IETF document](https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/). Future implementation work will record the exact revision it targets.

## Performance and limitations

Benchmarks will report decoded messages per second, processing latency distributions, peak memory, queue occupancy, capture drops, scenario convergence time, and recovery time. Each result will include hardware, software versions, workload, and measurement method. No full-table capacity or near-zero-latency claim is part of this design.

A result describes the tested source, destination, policy, and time window. It will not be generalized to worldwide routing. Prefix specificity, route selection, packet forwarding, and TLS identity are separate concepts and will be explained that way in reports.
