# BGP Hijack Lab documentation

**Passive-analysis scope update:** AN03–AN07 now provides lab-independent lookup, file inspection, RIS Live recording, and offline change reports. See [Passive analysis](passive-analysis.md) for implemented commands, schema, bounds, and limitations. The active lab requirements below remain deferred; M1–M4 are not closed by passive analysis.

**Status: passive-analysis implementation available; acceptance evidence tracked separately.**
The repository provides lab-independent lookup, MRT/capture inspection, filtered live observations,
and reproducible reports, alongside the existing lab configuration validator and protocol foundation.
Active Rust sessions and controlled traffic scenarios remain deferred.

## Reading order

| Document | Questions it answers |
| --- | --- |
| [Passive analysis](passive-analysis.md) | How do the implemented lookup, inspect, watch, and report commands work? |
| [Product](product.md) | Who is this for, what is in the first release, and what counts as success? |
| [Architecture](architecture.md) | Which component owns each responsibility, and how does evidence flow? |
| [Protocol](protocol.md) | Which BGP behaviors are supported, and how are sessions and routes handled? |
| [Lab and scenarios](lab-and-scenarios.md) | What is the reference topology, and what should each experiment demonstrate? |
| [Interfaces](interfaces.md) | What will the CLI accept and produce? |
| [Roadmap and validation](roadmap-and-validation.md) | In what order will we build, and how will we verify each milestone? |
| [Sprint plan](sprint-plan.md) | How will two developers deliver the first release across two-week sprints, with owners, dependencies, estimates, and demos? |
| [Development guide](development.md) | How do the implemented codec/journal APIs and developer lab/fuzz tools work? |

## Accepted decisions

These decisions are the baseline for implementation, rather than a list of alternatives to choose later.

| ID | Decision | Reason |
| --- | --- | --- |
| D01 | English documentation; working name `bgp-hijack`. | Support public review and contributions. |
| D02 | Rust with a project-owned BGP codec and session engine. | Protocol implementation is part of the research goal. |
| D03 | Tokio for asynchronous I/O, Clap for the CLI, and Serde for configuration and artifacts. | Use established infrastructure around the custom protocol engine. |
| D04 | Linux, Docker, and Containerlab; FRR as the reference peer. | Provide repeatable experiments against a separate BGP implementation. |
| D05 | IPv4 and IPv6 unicast in the first release. | Exercise both families through the same scenario lifecycle. |
| D06 | `forward` and `blackhole` scenarios, each with accepting and rejecting prefix-policy profiles. | Measure traffic effects and the effect of a defensive control. |
| D07 | Foreground CLI, JSONL events, JSON reports, and PCAPNG captures. | Make results inspectable and suitable for automated checks. |
| D08 | Linux performs packet forwarding; Rust coordinates experiments and observations. | Keep the custom protocol scope focused on BGP. |
| D09 | Active operations stay inside the declared isolated reference lab. | Make the experiment boundary explicit and testable. |
| D10 | RPKI/ROV, service impersonation, and interactive interfaces remain deferred; D17 advances passive external telemetry. | Establish a measurable end-to-end experiment first. |
| D11 | Two developers working in two-week sprints. | Use the agreed team capacity for the sprint forecast and backlog; estimates remain revisable. |
| D12 | Rust 1.93.1, edition 2024, resolver 3; exact direct dependency versions and a committed lockfile. | Make the foundation reproducible across local development and CI. |
| D13 | Bounded serde-saphyr YAML parsing followed by strict typed deserialization with field paths. | Reject duplicate keys and implicit scalar coercion while preserving useful errors. |
| D14 | `validate --static` is file-only and reports `runtime_verified: false`. | Distinguish implemented configuration checks from future live prerequisites. |
| D15 | Every journal append flushes and synchronizes before returning success. | Give callers an explicit durability boundary before future lab mutations. |
| D16 | Sprint 2 uses a local, two-node management-free fixture; fuzzing uses an isolated pinned nightly workspace. | Verify peer prerequisites independently while preserving the stable main toolchain and later scenario scope. |

| D17 | AN03–AN07 prioritizes passive RIPEstat/RIS Live, MRT/capture analysis, and evidence-linked findings. | Make the CLI useful without a lab; preserve active isolation requirements. |
| D18 | Capture decoding requires observed OPEN negotiation or explicit directional context. | Avoid guessing ASN width, ADD-PATH, or missing BGP boundaries. |

The more detailed contracts belong to the linked documents: product owns scope, protocol owns wire behavior, lab and scenarios owns expected outcomes, and interfaces owns configuration and artifact names. The sprint plan owns implementation sequencing and capacity estimates; it does not override those contracts. Update this decision table when an accepted choice changes, together with its affected documents.

## Current delivery state

| Deliverable | State |
| --- | --- |
| Design documents | Present; requirements for future work |
| Rust workspace and CLI | Passive commands and static validation implemented; active lab operations deferred |
| Configuration/evidence models and evaluator | Implemented, including bounded durable journals; passive artifact integrity verification implemented; lab reporting deferred |
| BGP codec | Framing, OPEN, KEEPALIVE and NOTIFICATION implemented; passive IPv4/IPv6 UPDATE processing implemented |
| Containerlab topology and FRR fixtures | Minimal developer fixture implemented; live acceptance recorded separately; full scenario topology planned |
| Scenario runner and packet recording | Planned |
| Foundation tests | Configuration, JSON, verdict, and CLI tests implemented |
| Protocol and lab tests | Control-message fixtures, fuzz targets and offline isolation checks implemented; live session tests planned |
| Performance measurements | Planned; no capacity or latency claims |

The existing repository [license](../LICENSE) is Apache-2.0. This documentation describes the product's intended behavior; it does not add license terms.

## Vocabulary

| Term | Meaning in this project |
| --- | --- |
| Prefix | An IPv4 or IPv6 address range represented by an address and prefix length. |
| ASN | An autonomous system identifier; not an identity belonging to an individual server. |
| Peer | A configured BGP neighbor inside the lab. |
| Address family | IPv4 unicast or IPv6 unicast in the first release. |
| Control-plane evidence | BGP messages, session state, policy outcomes, and route-table observations. |
| Data-plane evidence | Packets and endpoint measurements showing what actually traversed the lab. |
| Baseline | The measured routing and delivery state before a scenario changes the lab. |
| Scenario | A bounded experiment with explicit expected outcomes and recovery checks. |
| Forward | The experiment node receives test traffic and forwards it to the original target. |
| Blackhole | Selected test traffic reaches a controlled drop point and is discarded. |
| Recovery | Removal of experiment-owned changes followed by verification of baseline behavior. |
| Inconclusive | Required evidence is missing or insufficient to decide an assertion. |

An observed route change alone is not proof of interception. A path change does not grant access to TLS plaintext. Reports will describe observed behavior and its supporting evidence, without attributing malicious intent to an ASN.
