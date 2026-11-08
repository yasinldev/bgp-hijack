# Roadmap and validation

**Status: planned.** This document defines future implementation gates. The documentation milestone delivers the specification; it does not imply that any protocol or lab test has already passed.

## Milestones

| Milestone | Deliverable | Exit gate |
| --- | --- | --- |
| M0: documentation | The seven linked documents, accepted decisions, diagrams, interface examples, and acceptance matrix. | Document checks below pass and the first-release contracts agree across files. |
| M1: protocol core | Rust workspace; bounded codec; peer FSM; four-octet ASNs; IPv4/IPv6 unicast; minimal isolated FRR peer harness. | Unit, property/fuzz, timer, and FRR interoperability checks cover the supported protocol subset. |
| M2: lab and state | Pinned Containerlab fixture; inventory/isolation checks; route store; baseline collection; recovery journal. | Baseline works for both families; peer/order/recovery faults cannot create stale state or bypass isolation. |
| M3: scenarios | `forward` and `blackhole` with `accept`/`reject` policies. | All eight scenario/family/policy rows pass with independently observed control and data planes. |
| M4: reporting and release | CLI, stable versioned artifacts, shared offline evaluator, packaging, and reproducibility instructions. | Fresh-lab end-to-end runs and offline report regeneration agree; failure and interruption artifacts are usable. |

The CLI/configuration and event interfaces may be introduced as scaffolding in earlier milestones where needed for testing. M4 completes their supported user contract. Each milestone depends on the preceding exit gate; documentation will be updated alongside implementation rather than describing unimplemented work as released.

Rust/toolchain and dependency versions, together with the minimal FRR harness image, will be pinned in M1. The complete Containerlab topology and its images will be pinned in M2. Release records will include the exact tested versions and fixture identity; no mutable `latest` tag will serve as a reproducibility claim.

## Documentation acceptance

M0 is complete when:

- All seven documents are present, in English, and linked from the index.
- Runtime capabilities and examples are marked as planned.
- Relative file links and section anchors resolve; fenced examples and tables are well formed.
- Mermaid diagrams parse successfully and agree with the text's component responsibilities and lifecycle.
- YAML and JSON examples parse and agree with the documented field names, enums, units, and constraints.
- Every scenario has explicit preconditions, control-plane evidence, traffic evidence, failure behavior, and recovery requirements.
- The IPv4/IPv6 and accepting/rejecting policy matrix is complete, with no scope contradictions between documents.
- Standards and platform references use primary sources; unsupported performance claims are absent.

No Rust test suite is required merely to add these documents. Documentation checks will not be reported as protocol or runtime validation.

## Protocol and state tests

| Test group | Required cases | Expected property |
| --- | --- | --- |
| Stream framing | Every split point, several messages per read, EOF mid-message, invalid marker/length, 4096-byte boundary. | No overread, unbounded allocation, panic, or false complete message. |
| OPEN/capabilities | Four-octet ASNs; absent required capability; unsupported AFI/SAFI; unknown capability; malformed parameter bounds. | Explicit compatibility result and standards-based error behavior. |
| UPDATE | IPv4/IPv6 announces and withdrawals; malformed supported attributes; bad NLRI/next-hop lengths. | Correct affected-route state and documented error action. |
| FSM/timers | Connection failure, retries, collision, hold expiry, zero hold, remote NOTIFICATION, EOF. | Deterministic transitions and cleanup using a controlled clock. |
| Route ownership | Same prefix from two peers; replacement; repeated withdrawal; batch updates; family independence. | No accidental overwrite of another peer/family's route. |
| Reconnection | Peer disconnect, new epoch, delayed old events, repeated connect/disconnect. | No stale route resurrection or stale baseline reuse. |
| Backpressure | Full event queues, slow storage, bounded capture capacity. | Bounded resources and explicit failure/evidence-gap behavior. |
| Fuzzing | Arbitrary byte input and targeted valid-message mutations. | Bounded execution, no panic, and replayable failure corpus. |
| Interoperability | Establishment, route exchange, withdrawal, and error effects against pinned FRR. | Agreement for the declared subset, with unsupported behavior recorded. |

Valid encoder/decoder round trips will supplement independent message fixtures, not replace them. Test inputs for malformed messages must assert the expected RFC action and route/session effect, rather than only checking for an error return.

## Scenario tests

The canonical eight cases are defined in the [acceptance matrix](lab-and-scenarios.md#acceptance-matrix): F4A, F4R, F6A, F6R, B4A, B4R, B6A, and B6R. The release suite will execute all eight and additional dual-family runs for each scenario/policy combination.

Each run will verify:

1. A healthy baseline and captures at the declared observation points.
2. The expected route receipt, policy outcome, and forwarding-route observation at the transit peer.
3. Flow-specific delivery through the experiment node, continued baseline delivery, or a verified controlled drop, as appropriate.
4. Withdrawal/removal of experiment effects and fresh successful baseline probes after recovery.
5. Complete evidence references and agreement between live and offline report verdicts.

Blackhole tests will include target-service health and capture completeness, so an unavailable target or lost capture cannot masquerade as a successful drop test. Prefix-rejection tests will require positive evidence of update receipt and policy rejection. Forwarding tests will check request and response behavior against the fixture's declared paths.

## Fault and boundary tests

| Fault or boundary | Expected result |
| --- | --- |
| Invalid YAML, duplicate key, unsupported schema, missing family prefix. | Validation error before activation. |
| External interface/peer, host networking, IPv6 egress path, or management-to-experiment forwarding. | Isolation validation rejects activation. |
| Baseline endpoint unavailable or required peer capability missing. | No scenario activation; diagnostic artifacts identify the prerequisite. |
| Partial scenario activation failure. | Previously applied changes are rolled back; the incomplete run cannot pass. |
| Peer disconnect or session expiry during observation. | Route state is invalidated and bounded rollback starts. |
| Active deadline expires without complete convergence evidence. | Recovery starts; the outcome is inconclusive unless an assertion is conclusively violated. |
| SIGINT/SIGTERM in each active phase. | Recovery is attempted independently of the cancelled operation; interruption remains visible. |
| Process termination that bypasses cleanup. | Partial evidence is preserved; lab reuse is blocked until reset and fresh validation. |
| Capture loss/limit, disk exhaustion, or failed snapshot collection. | Evidence gaps or I/O errors are explicit; affected assertions cannot pass. |
| Cleanup mutation failure or lost recovery observation. | `failed` or `unverified` cleanup is visible; overall result cannot pass. |
| Existing output directory or concurrent run on the same lab. | Refuse to overwrite artifacts or share ownership. |
| Missing/tampered artifact or truncated final journal record. | Offline evaluation retains uncertainty and never synthesizes a passing history. |
| Repeated run after verified recovery. | Fresh identifiers, fresh baseline, and no inherited experiment state. |

## Verification environments

Fast checks will run without network-administration privileges: configuration parsing, codec tests, FSM tests with virtual time, route-state tests, and offline report tests. Fuzzing will use bounded jobs and preserve reproducer inputs.

Containerlab integration will run on a dedicated Linux runner with the required container/network permissions. It will use only the isolated reference fixture. Jobs will collect artifacts on failure and dispose of lab resources afterward. Source changes from untrusted contributions will not execute with elevated lab privileges automatically; a maintainer-controlled runner/job will handle those tests.

The first release will require one complete run on a newly prepared reference environment, plus successful repeated runs on the same environment after recovery. The instructions and results will identify any host-specific requirements.

## Measurements and future work

Record codec throughput, latency distributions, peak memory, queue occupancy, capture loss, convergence time, and recovery time with workload and host details. Treat observed numbers as measurements for that environment. Performance work must preserve ordering, evidence completeness, and correctness gates.

After M4, plan RPKI/ROV fixtures, controlled service impersonation, passive telemetry adapters, IRR/ASPA evidence, TUI, and export integrations as separate changes. Extended Messages, ADD-PATH, Route Refresh, Graceful Restart, and other protocol additions will each need an updated capability matrix and interoperability tests before being advertised.
