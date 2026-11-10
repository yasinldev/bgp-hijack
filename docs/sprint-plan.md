# Sprint plan

**Status: Sprint 1 implementation available for review.** S01-A1, A2, A3, B1, B2, and B3 are implemented and locally verified; the [implementation record](#sprint-1-implementation-record) distinguishes that evidence from pending remote CI and second-developer review. Sprints 2-10 and protocol/lab acceptance gates remain planned.

## Planning basis

The team consists of **two developers working in two-week sprints**, as agreed during planning. The baseline forecast is **10 sprints / 20 working weeks**. Allow up to two additional stabilization sprints if exit gates remain unmet, giving a provisional **20-24 week planning range**. This is an estimate, not a delivery commitment. No calendar start date has been assigned.

Assume both developers are available full time and can work in Rust and Linux networking. Each standard sprint has 20 gross person-days: 14 planned implementation/test days and 6 days reserved for review, integration, debugging, planning, and documentation. The backlog budgets seven implementation/test days per developer per sprint. Holidays, leave, operational work, or reduced availability reduce this capacity before sprint commitment.

Ticket estimates include their focused implementation and tests. The six-day reserve covers cross-cutting integration and review; it is not an extra feature budget. Optional stabilization sprints address unresolved gates, not additional product scope. Reforecast after Sprint 2 and every milestone using actual completed work and blocked time.

The [product definition](product.md), [protocol contract](protocol.md), [architecture](architecture.md), [lab scenarios](lab-and-scenarios.md), and [interfaces](interfaces.md) remain authoritative for behavior. This plan assigns ownership, sequence, estimates, and evidence to that scope. The [roadmap](roadmap-and-validation.md) owns milestone exit gates.

## Ownership and working agreements

| Role | Primary responsibility | Review responsibility |
| --- | --- | --- |
| Developer A | Protocol engine, route state, scenario lifecycle, and result evaluation. | Review lab isolation, capture/measurement assumptions, and CLI behavior. |
| Developer B | Configuration, reference lab, evidence collection, user interface, and integration fixtures. | Review protocol fixtures, event contracts, cancellation, and result classification. |

A and B are role assignments, not named people or running agents. Each ticket has one accountable owner; the other developer reviews it. Pair on interface changes, fault analysis, and milestone demos using the sprint reserve. Rotate specialist work when necessary to avoid single-person ownership of essential knowledge.

Keep at most one implementation ticket per developer in progress. Integrate small changes daily where possible. Dependencies below are acceptance prerequisites: work against an agreed interface can begin earlier, but a ticket cannot be accepted until its prerequisites are complete. Shared interfaces must be agreed before both developers implement against them.

Ticket IDs are local backlog identifiers, not GitHub issue numbers. No external issue tracker or publication action is implied by this document.

## Sprint overview

Weeks are relative to the eventual project start; they are not calendar dates.

| Sprint | Relative weeks | Goal | Developer A focus | Developer B focus | Gate |
| --- | --- | --- | --- | --- | --- |
| S01 | 1-2 | Buildable foundation and testable contracts. | Workspace, shared types, CI. | Configuration, event model, CLI shell. | Foundation usable by both developers. |
| S02 | 3-4 | Bounded message parsing and independent test inputs. | Framing and control messages. | Minimal FRR harness, journal, corpus. | Decoder and harness ready for session work. |
| S03 | 5-6 | Working sessions and IPv4 route messages. | FSM and TCP session ownership. | IPv4 UPDATE and ordered event contracts. | IPv4 peer exchange demonstrated. |
| S04 | 7-8 | Complete the first-release protocol subset. | Integration, limits, protocol regression. | IPv6 MP-BGP and dual-family tests. | **M1: protocol core.** |
| S05 | 9-10 | Correct route state in the full isolated lab. | Route store, epochs, snapshots. | Reference topology, preflight, peer observations. | Full lab baseline prerequisites ready. |
| S06 | 11-12 | Measured baseline and reliable recovery. | Lifecycle, journal/ownership, assertions. | Packet capture, probes, baseline integration. | **M2: lab and state.** |
| S07 | 13-14 | Forwarding scenario with accepting/rejecting policies. | Scenario integration and fault recovery. | Flow evidence and forward acceptance cases. | Four forward cases pass. |
| S08 | 15-16 | Blackhole scenario and complete scenario matrix. | Controlled drop lifecycle and fault behavior. | Drop proof, blackhole cases, full matrix. | **M3: scenarios.** |
| S09 | 17-18 | Reliable offline reporting and public CLI contract. | Artifact verification and report command. | CLI integration, golden artifacts, user guide. | Live/offline verdict parity. |
| S10 | 19-20 | Reproducible release candidate. | Resilience, measurements, gate review. | Packaging, docs, fresh-lab acceptance. | **M4: reporting and release.** |

M1 must pass before M2 integration is accepted; M2 must pass before active scenario work; M3 must pass before final release qualification. Early CLI, journal, and evaluator scaffolding are included because later gates need real evidence. Reporting correctness is not deferred to the last sprint.

## Sprint 1: foundation and contracts

**Goal:** Both developers can build and test the same Rust workspace, parse a declared fixture configuration, and exchange versioned events without a live lab.

**Entry:** The design baseline is available; A/B ownership and access to the repository are assigned. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S01-A1 | A | 3 | Establish library/binary boundaries, pinned toolchain and dependencies, and reproducible debug/release builds. A clean checkout builds and runs the initial test suite. | Design baseline |
| S01-A2 | A | 2 | Add shared prefix/family/ASN, peer identity, epoch, and typed error models. Tests preserve 32-bit ASNs and reject invalid or noncanonical prefixes. | S01-A1 |
| S01-A3 | A | 2 | Add unprivileged format, lint, and test CI with a clear local invocation. The default job does not require network-administration permissions. | S01-A1 |
| S01-B1 | B | 3 | Implement version-1 YAML loading and static validation against the existing contract. Unknown/duplicate keys, duplicate peers, missing families, and invalid limits are rejected with actionable errors. | S01-A1 |
| S01-B2 | B | 2 | Introduce event/manifest/assertion types and pure result aggregation. Golden cases establish failed-over-inconclusive precedence and prevent empty evidence from producing a passing run. | S01-A2 |
| S01-B3 | B | 2 | Add Clap command/help scaffolding and configuration-level validation. Unavailable live operations return an explicit error; no placeholder command reports a successful experiment. | S01-B1, S01-B2 |

**Demo and exit evidence:** Fresh build/CI results, accepted/rejected YAML fixtures, serialized event examples, and golden verdict tests. Demonstrate malformed configuration and an incomplete result as well as the valid path. Freeze the initial shared type and event interfaces for Sprint 2.

### Sprint 1 implementation record

Recorded **2026-11-09** on Linux with Rust **1.93.1**, rustfmt, and Clippy from the same toolchain. This increment performs offline checks only; no lab was deployed and no BGP session or packet capture was started.

| Ticket | State | Implemented output and local evidence |
| --- | --- | --- |
| S01-A1 | `review` | Two-package [workspace](../Cargo.toml), edition 2024/resolver 3, [pinned toolchain](../rust-toolchain.toml), exact direct dependencies, and [lockfile](../Cargo.lock). Debug and release builds passed. |
| S01-A2 | `review` | [Shared models](../crates/core/src/model.rs) and typed errors; canonical IPv4/IPv6 prefixes, 32-bit ASNs, peer IDs, and session epochs. Tests reject host bits and preserve four-octet values. |
| S01-A3 | `review` | Linux [GitHub Actions workflow](../.github/workflows/ci.yml) runs the five checks below without Docker or network-administration privileges. Equivalent local checks passed; remote CI has not run. |
| S01-B1 | `review` | [Static configuration validation](../crates/core/src/config.rs) and eight test functions with table-driven valid/invalid cases. One-document, size, depth, duplicate/type, family, reference, private-ASN, documentation-address, and checked-duration constraints are exercised. |
| S01-B2 | `review` | [Evidence models](../crates/core/src/evidence.rs) and [pure evaluation](../crates/core/src/evaluation.rs); five serialization tests and six evaluator tests, including independent event/verdict JSON fixtures. Journaling and actual artifact verification remain assigned to later sprints. |
| S01-B3 | `review` | [CLI](../crates/cli/src/main.rs) with `validate --static`, help/version, and explicit errors for unavailable operations. Five subprocess tests verify output streams, exit codes, and absence of output-directory/artifact side effects. |

All six tickets await the other developer's review under the definition of done. Their implementation and local checks are complete; no second-developer approval or remote CI success is asserted. This record does not close the Sprint 1 acceptance gate or any protocol/lab milestone.

| Local command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed with no warnings. |
| `cargo test --workspace --locked` | Passed: 24 integration tests, including table-driven cases; no failed or ignored tests. |
| `cargo build --workspace --locked` | Passed. |
| `cargo build --workspace --release --locked` | Passed. |

The [example configuration](../examples/lab-forward.yaml) passes static validation and produces schema version `1`, scope `static`, result `passed`, and `runtime_verified: false`. IPv4-only and IPv6-only variants also pass. Quoted numeric fields, nested duplicate keys, noncanonical prefixes, missing family coverage, excessive nesting, and overflow inputs are rejected. The evaluator's golden matrix covers failure precedence, missing evidence, interrupted/incomplete runs, and unverified or failed cleanup.

Implementation details affecting the contract: YAML is parsed with serde-saphyr into scalar-preserving JSON values before typed deserialization; the pinned `serde_path_to_error` helper preserves field paths without allowing string/number coercion. Topology paths are resolved relative to the configuration file without loading the referenced topology. Artifact models are serialization contracts, not integrity verification.

Remote CI execution and independent review are the remaining acceptance evidence. The next implementation work is Sprint 2's framing/control-message core, bounded journal, and isolated FRR harness after the foundation contracts are reviewed.

## Sprint 2: framing, control messages, and harness

**Goal:** Decode bounded BGP streams using independent byte fixtures and prepare an isolated peer harness before opening sessions from the new engine.

**Entry:** Sprint 1 contracts and CI are usable. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S02-A1 | A | 3 | Implement bounded stream framing and incremental decode. Every split position, coalesced messages, invalid header length, EOF, and the 4096-byte boundary have explicit tests. | S01-A2, S01-A3 |
| S02-A2 | A | 2 | Encode/decode OPEN and supported capabilities, including four-octet ASN values. Capability order, unknown capabilities, and malformed optional-parameter bounds are tested. | S02-A1 |
| S02-A3 | A | 2 | Encode/decode KEEPALIVE and NOTIFICATION and expose typed framing/control-message errors. Tests check actual wire bytes rather than round trips alone. | S02-A1 |
| S02-B1 | B | 3 | Build the minimal isolated FRR peer harness with pinned image and teardown. Record node/interface inventory and verify both IPv4 and IPv6 isolation before engine integration. | S01-A3 |
| S02-B2 | B | 2 | Add append-only JSONL writing, initialized manifests, monotonic elapsed time, and partial-journal reading. Interrupted writes preserve usable complete records and incomplete status. | S01-B2 |
| S02-B3 | B | 2 | Create independently specified byte fixtures and a bounded decoder fuzz harness. Record input provenance and persist reproducible failures; do not use the encoder as the sole test oracle. | S02-A1, S02-A2, S02-A3 |

**Demo and exit evidence:** Parse known control messages from fixture input, reject malformed input without panic, and provision/tear down the peer harness without external routing connectivity. Preserve the test corpus and a fuzz-run summary, including duration and seed/corpus identity.

## Sprint 3: sessions and IPv4 UPDATE

**Goal:** Establish a real session with the reference FRR peer and exchange supported IPv4 route messages through an ordered event boundary.

**Entry:** Framing/control-message tests pass and the peer harness is isolated. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S03-A1 | A | 3 | Implement the FSM transition table and timer actions using a controllable clock. Cover connection failure, retries, negotiated hold behavior, zero hold, and remote notification. | S02-A2, S02-A3 |
| S03-A2 | A | 2 | Integrate Tokio transport with a single session owner, declared endpoint binding, collision handling, and fresh connection epochs. No detached task can mutate a replaced session. | S03-A1 |
| S03-A3 | A | 2 | Demonstrate establishment, peer close, hold expiry, and reconnect against FRR; expose ordered session events. Record expected state changes and cleanup effects. | S03-A2, S02-B1, S02-B2 |
| S03-B1 | B | 3 | Implement IPv4 UPDATE/NLRI, required path attributes, and withdrawals. Independent fixtures cover normal updates, canonical prefixes, and invalid nested lengths. | S02-A1, S01-A2 |
| S03-B2 | B | 2 | Map supported attribute errors to their prescribed actions, including obsolete AS-path set handling. Tests assert affected-route/session behavior rather than generic error returns. | S03-B1 |
| S03-B3 | B | 2 | Connect decoded updates to family-neutral ordered batch events with peer/epoch identity. A test consumer observes announcements and withdrawals in receive order. | S03-B1, S03-A2, S02-B2 |

**Demo and exit evidence:** A session transcript and IPv4 announce/withdraw observations from the isolated harness, plus timer/collision/error fixtures. Do not describe the test consumer as a completed production route store; that ownership model is implemented in Sprint 5.

## Sprint 4: IPv6 and protocol gate

**Goal:** Pass M1 for the complete declared IPv4/IPv6 protocol subset, with resource bounds and interoperability evidence.

**Entry:** IPv4 exchange and session behavior are demonstrated. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S04-A1 | A | 3 | Integrate supported message exchange across the session engine and both families. Missing required capabilities prevent activation; unsupported capabilities are never advertised. | S03-A3, S03-B2, S03-B3, S04-B1 |
| S04-A2 | A | 2 | Enforce finite peer/message/queue limits and cancellation behavior. Slow consumers and saturation produce explicit errors, bounded memory, and ordered teardown. | S03-A2, S03-B3 |
| S04-A3 | A | 2 | Complete M1 protocol regression and RFC-action traceability against pinned FRR. Every supported error category has expected route/session effects and a reproducible test. | S04-A1, S04-A2, S04-B3 |
| S04-B1 | B | 3 | Implement IPv6 MP_REACH_NLRI/MP_UNREACH_NLRI and family-specific next-hop validation. Tests cover valid forms, withdrawals, truncation, and unsupported AFI/SAFI. | S03-B1, S03-B2 |
| S04-B2 | B | 2 | Extend the harness for both unicast families over the agreed IPv4 transport and four-octet private ASNs. Demonstrate family negotiation and capability mismatch. | S04-B1, S02-B1 |
| S04-B3 | B | 2 | Extend independent fixtures and fuzzing to IPv6 and mixed-family input. Cross-family tests preserve family identity and never reinterpret unsupported routes. | S04-B1, S04-B2, S02-B3 |

**Demo and M1 exit evidence:** FRR transcripts for both families, passing protocol/fuzz/timer results, pinned versions, documented resource limits, and a supported-feature matrix. IPv6-only TCP transport remains outside the agreed first-release scope. Do not advance to accepted M2 integration if this gate fails.

## Sprint 5: route state and full reference lab

**Goal:** Retain correct peer-specific route state while the full reference topology supplies independently observable routing and policy state.

**Entry:** M1 has passed. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S05-A1 | A | 3 | Implement the single-owner route store and immutable snapshots keyed by lab/peer/family/prefix. Same-prefix paths from different peers remain distinct; update batches are ordered. | M1 |
| S05-A2 | A | 2 | Implement epoch invalidation, repeated withdrawals, reconnect behavior, and stale-event rejection. Race tests prove old work cannot restore removed routes. | S05-A1 |
| S05-A3 | A | 2 | Expose route snapshots/change events and bound state growth. Tests cover family independence, missing-route withdrawal, and disconnect cleanup. | S05-A1, S05-A2 |
| S05-B1 | B | 3 | Build and pin the five-role Containerlab fixture, including independent continuation and declared return paths. Controlled endpoints are reachable in both families before experiments. | M1, S02-B1 |
| S05-B2 | B | 2 | Implement live inventory/isolation preflight for namespaces, interfaces, peer addresses, and IPv4/IPv6 paths. External or management-to-experiment forwarding prevents activation. | S05-B1, S01-B1 |
| S05-B3 | B | 2 | Add version-aware FRR route/policy observations with timestamps and evidence references. Distinguish receipt, policy rejection, accepted route, and selected forwarding route. | S05-B1, S02-B2 |

**Demo and exit evidence:** Independent routes for two peers, disconnect/reconnect without stale state, normal dual-family endpoint reachability, and rejection of deliberately invalid lab wiring. Preserve the inspected inventory and FRR observations for the next sprint's baseline evaluator.

## Sprint 6: baseline, evidence, and recovery

**Goal:** Run the full observation/recovery lifecycle with real evidence before enabling either active scenario.

**Entry:** The full isolated lab and correct route-state store are available. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S06-A1 | A | 3 | Implement lifecycle phases, separate active/recovery deadlines, and cancellation propagation. Partial activation errors enter recovery rather than exiting through an unobserved shortcut. | S05-A3, S05-B2 |
| S06-A2 | A | 2 | Add lab ownership locks, journal-before-mutation, and idempotent recovery of fixture-owned state. An unfinished run blocks reuse until reset and fresh validation. | S06-A1, S02-B2 |
| S06-A3 | A | 2 | Connect baseline and recovery assertions to the shared evaluator. Missing routes, missing captures, unavailable endpoints, or interrupted phases cannot produce a passing run. | S06-A1, S01-B2, S06-B1, S06-B2 |
| S06-B1 | B | 3 | Record bounded PCAPNG at declared data interfaces with point identity and capture statistics. Enforce the aggregate byte limit and preserve evidence of dropped/incomplete capture data. | S05-B2, S02-B2 |
| S06-B2 | B | 2 | Generate bounded, identifiable IPv4/IPv6 probes and collect endpoint responses/target health. Record request/response directions and reserve probe budget for recovery. | S05-B1, S06-B1 |
| S06-B3 | B | 2 | Integrate baseline measurements and controlled recovery exercises in the full lab. Demonstrate normal completion, interrupted measurement, and reset/revalidation without scenario traffic redirection. | S06-A2, S06-A3, S06-B2, S05-B3 |

**Demo and M2 exit evidence:** Both-family baseline bundles, capture/probe completeness, exclusive lab ownership, and recovery results for a bounded fixture-state change. Inject a missing observation and an interruption; show explicit uncertainty and cleanup status. M3 work starts only after baseline and recovery are proven.

## Sprint 7: forwarding scenario

**Goal:** Demonstrate forwarding through the experiment node or successful policy rejection, with independent evidence and verified recovery.

**Entry:** M2 has passed. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S07-A1 | A | 3 | Implement the named `forward` fixture through the lifecycle manager. Prepare the continuation path before activation and retain it until experiment routes are removed during rollback. | M2 |
| S07-A2 | A | 2 | Integrate run execution with family-specific expectations and the evaluator. A verified `reject` policy can pass; route acceptance alone cannot prove packet traversal. | S07-A1, S06-A3, S07-B1 |
| S07-A3 | A | 2 | Exercise partial activation, peer loss, cancellation, and repeated recovery actions. Prove restoration of only experiment-owned state and preservation of the original target path. | S07-A1, S06-A2 |
| S07-B1 | B | 3 | Correlate source, experiment, target, and peer observations using flow identifiers and windows. Verify responses and the declared return path without relying on timestamp proximity alone. | M2 |
| S07-B2 | B | 2 | Automate F4A, F4R, F6A, and F6R and the two dual-family forward runs. Rejection tests include update receipt and positive policy evidence. | S07-A2, S07-B1 |
| S07-B3 | B | 2 | Add false-positive tests for capture gaps, target unavailability, and misleading route-only evidence. Save complete and incomplete forward bundles for offline evaluator regression. | S07-B2, S07-A3 |

**Demo and exit evidence:** Four single-family forward cases and both dual-family policy variants pass with packet, endpoint, policy, and recovery evidence. Missing experiment capture must not be reported as proof that the traffic avoided that node. The target service remains the original controlled endpoint.

## Sprint 8: blackhole and scenario gate

**Goal:** Add verified controlled drops and pass the complete M3 scenario matrix without false success from missing evidence.

**Entry:** Forwarding cases and recovery behavior pass. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S08-A1 | A | 3 | Implement the bounded `blackhole` fixture, scoped drop accounting, and restoration. The experiment uses deliberate drops, not overload; unrelated control traffic remains usable. | S07-A1, S06-A2 |
| S08-A2 | A | 2 | Add blackhole/rejection assertions with explicit expected outcomes for both families. A missing response alone cannot pass; rejected routes preserve baseline delivery. | S08-A1, S07-A2, S08-B1 |
| S08-A3 | A | 2 | Exercise scenario-time peer failures, deadline expiry, cleanup faults, and family-specific evidence loss. Confirm verdict precedence and no stale state between repeated runs. | S08-A2, S07-A3 |
| S08-B1 | B | 3 | Build and test the positive-drop evidence collector against controlled fixture inputs: source transmission, experiment ingress/counters, target capture completeness, and independent target health. Missing required observations are labeled as gaps; live scenario integration is accepted in S08-B2. | S07-B1, S06-B2 |
| S08-B2 | B | 2 | Automate B4A, B4R, B6A, and B6R and both dual-family blackhole runs. Rejection profiles demonstrate preserved delivery and unchanged matching drop counts. | S08-A2, S08-B1 |
| S08-B3 | B | 2 | Run all eight single-family and four dual-family combinations, preserve their artifacts, and check evaluator results and recovery. Record case IDs, versions, and any unresolved failure. | S08-B2, S08-A3, S07-B2 |

**Demo and M3 exit evidence:** All 12 runs pass their configured expectations and verify recovery. Demonstrate that a rejecting filter is a successful defensive outcome, while lost capture or an unhealthy target cannot masquerade as a proven blackhole. Every relevant failure retains actionable evidence.

## Sprint 9: offline reporting and supported CLI

**Goal:** Make the agreed CLI/artifact contract reliable for users and reproducible without access to the original running lab.

**Entry:** M3 has passed; real success/failure/incomplete evidence is available. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S09-A1 | A | 3 | Complete artifact inventory, hashes, schema checks, and path-confined evidence loading. Missing, modified, truncated, or escaping references cannot supply trustworthy passing evidence. | M3, S02-B2 |
| S09-A2 | A | 2 | Implement the public offline `report` command through the existing evaluator. It needs no live network access or elevated privileges and does not replace the original saved report. | S09-A1, S01-B2 |
| S09-A3 | A | 2 | Finalize report summaries, per-family assertions, cleanup status, and measured durations/resource fields. Stable fields and units match the interface document and golden expectations. | S09-A2 |
| S09-B1 | B | 3 | Complete `validate`/`run` behavior, stdout/stderr separation, exit codes, new-output handling, and interruption responses. End-to-end CLI tests cover the documented success and error paths. | M3, S01-B3 |
| S09-B2 | B | 2 | Build a golden artifact suite from the scenario/fault bundles. Verify live/offline verdict parity, dual-family aggregation, incomplete journals, and integrity failures. | S09-A2, S09-B1, S07-B3 |
| S09-B3 | B | 2 | Write the runnable reference-lab user guide, troubleshooting, and evidence interpretation examples. The other developer follows the guide and records missing prerequisites or mismatched commands. | S09-B1, S09-A3 |

**Demo and exit evidence:** Copy an artifact bundle to a machine without the lab and regenerate the same verdict. Show incomplete and modified bundles as well as a valid one. Verify CLI output/exit behavior and preserve the original artifacts unchanged.

## Sprint 10: release candidate and reproducibility

**Goal:** Produce a reviewable release candidate with repeatable tests, honest measurements, and complete operator instructions.

**Entry:** Supported CLI behavior and live/offline parity are verified. **Budget:** A 7 days, B 7 days, shared reserve 6 days.

| ID | Owner | Days | Work and accepted output | Depends on |
| --- | --- | --- | --- | --- |
| S10-A1 | A | 3 | Run the consolidated resilience suite: disconnects, signals, queue/storage/capture limits, unfinished journals, and repeat-run cleanup. Resolve correctness and recovery regressions before qualification. | S09-A3, S09-B2 |
| S10-A2 | A | 2 | Record reproducible codec/resource and lab convergence/recovery measurements with workload and host details. Publish observations in the release record without unsupported capacity claims. | S10-A1 |
| S10-A3 | A | 2 | Review all milestone evidence, supported-feature statements, known limitations, and open release blockers. Assemble a local release-candidate validation record and changelog. | S10-A2, S10-B3 |
| S10-B1 | B | 3 | Prepare reproducible Linux build/package artifacts and pinned lab instructions. Record checksums and software/image identities; install the candidate in a fresh reference environment. | S09-B3, S09-A3 |
| S10-B2 | B | 2 | Reconcile the index, root README, protocol matrix, configuration examples, and troubleshooting with implemented behavior. Mark only verified capabilities as available. | S10-B1, S09-B3 |
| S10-B3 | B | 2 | Qualify the same candidate with three complete 12-run matrices: one on a freshly prepared lab and two after verified recovery on the reused lab. Regenerate reports and retain all evidence. | S10-B1, S10-A1, S10-B2 |

**Demo and M4 exit evidence:** A second developer installs the candidate from the instructions; 36 qualification runs verify both clean setup and absence of state leakage across reuse. All corresponding offline verdicts agree. A failure changes the candidate or fixture and requires rerunning the affected gates; repetitions are for state/recovery validation, not a substitute for investigating failures.

The deliverable is a release candidate and its evidence bundle. Public hosting or release publication is a separate maintainer activity, not an action performed by this planning task.

## Traceability and critical dependencies

| Requirement | Primary tickets | Verification gate |
| --- | --- | --- |
| Rust workspace, static checks, pinned dependencies | S01-A1, S01-A3 | S01 demo; maintained through M4. |
| Strict versioned configuration and CLI contract | S01-B1, S01-B3, S05-B2, S09-B1 | M2 runtime preflight; S09 CLI acceptance. |
| Bounded codec, capabilities, and four-octet ASN | S02-A1, S02-A2, S02-A3, S03-B2 | M1. |
| FSM, timers, epochs, and ordered peer events | S03-A1, S03-A2, S03-A3, S03-B3 | M1; state regression at M2. |
| IPv4/IPv6 unicast and withdrawals | S03-B1, S04-B1, S04-B2, S04-B3 | M1; both-family data-plane checks at M3. |
| Peer-specific route state and stale-event rejection | S05-A1, S05-A2, S05-A3 | M2. |
| Isolated topology and independent peer observations | S02-B1, S05-B1, S05-B2, S05-B3 | M2; negative wiring tests remain release blockers. |
| Capture completeness, bounded probes, and target health | S06-B1, S06-B2, S07-B1, S08-B1 | M2 foundations; M3 scenario proof. |
| Journal, ownership, cancellation, and recovery | S02-B2, S06-A1, S06-A2, S06-B3, S10-A1 | M2, M3, and M4. |
| F4A, F4R, F6A, F6R | S07-A2, S07-B2, S07-B3 | M3. |
| B4A, B4R, B6A, B6R | S08-A2, S08-B2, S08-B3 | M3. |
| Failed/inconclusive/passed semantics | S01-B2, S06-A3, S08-A3, S09-B2 | Present before M3; parity at M4. |
| Offline reports, artifact integrity, and schema behavior | S09-A1, S09-A2, S09-A3, S09-B2 | S09 demo and M4. |
| Repeatability, packaging, and measured performance | S10-A2, S10-A3, S10-B1, S10-B2, S10-B3 | M4. |

The principal dependency chain is protocol interoperability -> trustworthy route/lab state -> complete baseline and recovery -> scenario evidence -> stable offline evaluation -> release qualification. Advancing the calendar does not close a gate. Blocked downstream acceptance stays blocked until the predecessor evidence is available.

If both developers can work independently, prioritize fixtures, independent tests, documentation, and pure offline components while a critical-path issue is investigated. Do not integrate active scenarios ahead of M2 just to keep both developers busy.

## Sprint operation

### Definition of ready

A ticket is ready when it has a single owner, understood acceptance evidence, known prerequisite status, applicable source contracts, and a test environment or independent fixture. Any cross-component interface change must have an agreed representation and error behavior before competing implementations start.

Break a ticket into smaller implementation steps if its estimate grows beyond three focused days. Preserve the parent acceptance criterion and ticket ID in the plan; new subtasks must not hide an unfinished parent. Timebox uncertain investigations within the ticket and reserve, then revise the forecast if a design change is required.

### Definition of done

- The accepted behavior is implemented, reviewed by the other developer, and integrated with its callers.
- Relevant independent tests pass, including the failure behavior named in the ticket.
- Changes to contracts, fixtures, prerequisites, or supported features are reflected in the owning documents.
- Required evidence is attached to the local ticket/PR record: test result, fixture identity, artifact bundle, or demo transcript as appropriate.
- No known defect contradicts the ticket's acceptance criteria; unfinished work remains visible rather than counted as complete.

All implementation tickets start as `planned`. Use `ready`, `in_progress`, `review`, `done`, and `blocked` when execution begins. A blocked ticket records the reason, dependency, owner, and next action. Reopening a completed ticket after a regression also reopens any affected gate.

### Two-week cadence

| Point | Activity | Output |
| --- | --- | --- |
| Start of sprint | Confirm actual availability, prerequisites, and the feature budget; agree interface changes. | Committed ticket list and explicit risks. |
| Daily | Integrate small changes, review evidence, and surface blocked dependencies. | Updated ticket states and remaining work. |
| Mid-sprint | Run the earliest integrated demo; compare remaining effort with capacity. | Reforecast or reduce commitment while preserving mandatory scope. |
| Final two days | Finish integration, fault checks, and evidence collection; avoid starting unrelated features. | Reviewable increment and acceptance results. |
| Sprint end | Demonstrate success and a representative failure path; review estimates and process issues. | Gate decision, carryover list, and next-sprint adjustments. |

Carryover is re-estimated against the next sprint's capacity. It is not added on top of an unchanged full commitment. Changes to the first-release scope require a corresponding update to the product/decision documents; IPv6, recovery, isolation, and verdict correctness cannot quietly disappear to meet a date.

## Capacity and progress tracking

| Quantity | Baseline |
| --- | --- |
| Developers | 2 |
| Sprint length | 2 working weeks / 10 working days |
| Planned implementation sprints | 10 |
| Gross capacity per sprint | 20 person-days |
| Ticket budget per sprint | 14 person-days: 7 for A and 7 for B |
| Review/integration/reserve per sprint | 6 person-days |
| Total planned ticket effort | 140 person-days across 60 tickets |
| Total gross baseline capacity | 200 person-days |
| Optional stabilization | Up to 2 additional two-week sprints, subject to reforecast |

Record completed acceptance criteria, actual effort, review delay, blocked days, open correctness defects, and gate status. Separate implementation progress from test pass counts. A mostly written component with no demonstrated behavior is unfinished.

After Sprint 2, compare estimated and actual effort by subsystem. If sustained actual capacity is below 14 ticket days per sprint, spread remaining work over more sprints. If a critical-path problem exceeds the optional stabilization allowance, revise the forecast again rather than treating 24 weeks as a guaranteed upper bound.

## Risks and contingency actions

| Risk | Early signal | Owner | Planned response |
| --- | --- | --- | --- |
| Custom BGP error/FSM work exceeds estimate | Unmapped attribute behavior, repeated interop failures in S03/S04. | A | Use the independent corpus and minimal harness to isolate the issue; spend reserve or extend M1 before accepting M2. |
| Privileged Linux test environment is unavailable | Harness cannot be provisioned or its isolation cannot be verified in S02. | B | Resolve runner access/topology early; continue pure tests while blocked. Do not claim live interoperability from mocks. |
| IPv6 handling diverges from IPv4 | Next-hop, policy, or flow evidence fails only for IPv6. | B | Keep family-specific fixtures and negative tests; repair the shared model rather than silently narrowing release scope. |
| Evidence loss creates misleading results | Capture drops, missing policy observations, or uncertain flow matching. | B | Mark dependent assertions inconclusive; fix observation completeness before scenario acceptance. |
| Cancellation or reconnection leaves state behind | Repeated runs differ from clean-lab results or obsolete epochs reappear. | A | Block lab reuse, preserve the journal, and fix recovery/state ownership before the next gate. |
| Workstreams diverge on shared contracts | Events/configurations require incompatible adapters or repeated rework. | A and B | Agree contract changes first, keep golden examples, and use daily integration; update the owning document with the change. |
| Review capacity or specialist knowledge is insufficient | Review queues grow or one developer cannot reproduce the other's demo. | A and B | Pair using reserve, reduce sprint commitment, and revise the forecast. Do not substitute self-approval for demonstrated understanding. |
| Release setup is not reproducible | Candidate works only on the original developer's host. | B | Use S10's fresh environment and pinned versions to identify missing prerequisites; defer qualification until repeatable. |

Use an additional stabilization sprint only for identified unfinished gates or defects. Each such sprint needs a concrete backlog, owners, acceptance evidence, and a revised forecast. Deferred features do not enter this reserve.

## Release readiness and deferred backlog

M4 requires all predecessor gates, the 12-case functional matrix, the fault suite, live/offline parity, and repeated clean/reused-lab qualification. No unresolved defect may allow operations outside the lab, false passing results, incorrect supported protocol behavior, or failed recovery to be hidden. Lower-impact limitations may be documented only when they do not contradict the acceptance criteria.

The release candidate record will contain the supported subset, toolchain/dependency/image versions, fixture identities, validation artifacts, measured performance context, reproducible setup instructions, and known limitations. This plan does not mark any of those deliverables as complete in advance.

RPKI/ROV, service impersonation, RIS Live/BMP, IRR/ASPA, TUI, Prometheus, STIX/CEF, eBPF, IPv6-only BGP transport, and additional BGP capabilities remain in the [subsequent milestones](product.md#subsequent-milestones). They require separate estimates and gates after the first-release baseline is delivered.
