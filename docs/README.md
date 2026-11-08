# BGP Hijack Lab documentation

**Status: planned.** This directory specifies a future implementation. The repository does not yet provide an executable, a deployable lab, or validated performance results. CLI and configuration examples describe the proposed interface.

BGP Hijack Lab, working name `bgp-hijack`, is a routing research tool for isolated laboratories. It will correlate controlled BGP changes with measured packet delivery and prefix-filter behavior. Its first release will cover forwarding through an experiment node and controlled blackholing, for both IPv4 and IPv6.

## Reading order

| Document | Questions it answers |
| --- | --- |
| [Product](product.md) | Who is this for, what is in the first release, and what counts as success? |
| [Architecture](architecture.md) | Which component owns each responsibility, and how does evidence flow? |
| [Protocol](protocol.md) | Which BGP behaviors are supported, and how are sessions and routes handled? |
| [Lab and scenarios](lab-and-scenarios.md) | What is the reference topology, and what should each experiment demonstrate? |
| [Interfaces](interfaces.md) | What will the CLI accept and produce? |
| [Roadmap and validation](roadmap-and-validation.md) | In what order will we build, and how will we verify each milestone? |

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
| D10 | RPKI/ROV, external telemetry, service impersonation, and interactive interfaces follow the first release. | Establish a measurable end-to-end experiment first. |

The more detailed contracts belong to the linked documents: product owns scope, protocol owns wire behavior, lab and scenarios owns expected outcomes, and interfaces owns configuration and artifact names. Update this decision table when an accepted choice changes, together with its affected documents.

## Current delivery state

| Deliverable | State |
| --- | --- |
| Design documents | Present; requirements for future work |
| Rust implementation and CLI | Planned |
| Containerlab topology and FRR fixtures | Planned |
| Scenario runner and packet recording | Planned |
| Automated protocol and integration tests | Planned |
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
