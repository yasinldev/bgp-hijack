# Sprint 2 development tools

The core library implements bounded control-message decoding and durable JSONL recording. The developer lab and fuzz tools are separate from the public `bgp-hijack` CLI. The CLI still provides static configuration validation only. See the [sprint record](sprint-plan.md#sprint-2-implementation-record) for executed checks and outstanding acceptance evidence.

## Codec API

`codec::FrameDecoder::consume(&[u8])` returns the number of consumed octets and at most one `Frame`. Supply the remaining slice again to process coalesced messages. Incomplete input returns no frame; `finish()` distinguishes clean EOF from a partial header/body. Each decoder owns a fixed 4096-byte buffer. Framing errors are terminal; create a new decoder for a new stream. No socket, retry, or resynchronization is hidden in this API.

`Frame::from_bytes` accepts exactly one complete frame. `decode_control` and `encode_control` handle OPEN, KEEPALIVE and NOTIFICATION. UPDATE is recognized and retained as raw bytes, but `decode_control` returns `UpdateNotImplemented`. Unknown message types fail framing. NOTIFICATION codes/subcodes and data are preserved, including unknown values.

`OpenMessage::new` constructs the two-octet field and four-octet ASN capability without truncation. `validate_open` separately checks peer identity and required IPv4/IPv6 unicast capabilities against a local OPEN. Identical capability repetitions are accepted; unknown capabilities remain observable but do not negotiate a feature. Conflicting four-octet ASNs fail compatibility. Zero hold time is permitted and the negotiated hold time is the minimum of the two proposals.

The decoder accepts normal and RFC 9072 extended optional-parameter lengths. The encoder uses extended encoding when its parameter block exceeds 255 bytes. The 4096-byte message ceiling remains unchanged. MP reserved octets are ignored on receive and zeroed on encode; four-octet ASN capability values take precedence over the received two-octet field. Re-encoding normalizes these fields and parameter grouping, so it is not a byte-preserving packet replay facility.

`CodecError::notification` and `OpenCompatibilityError::notification` provide protocol rejection metadata where applicable. Local misuse, EOF and invalid local requirements do not generate a peer notification. Actual socket writes and FSM actions belong to Sprint 3. Malformed OPEN boundaries/capability lengths use OPEN Error / Unspecific; unsupported optional parameters use subcode 4, while a missing required capability uses subcode 7. Independent fixtures record their RFC provenance in the [control-message catalogue](../crates/core/tests/fixtures/control-messages.json).

## Journal API and durability

`journal::JournalWriter::create` takes a new directory path, a `Manifest`, and `JournalLimits`. Its parent must already exist. The manifest supplies the run identity and configuration; the writer owns every event's identity, schema, sequence, timestamp and elapsed time. It initializes `manifest.json` and `events.jsonl`, synchronizes them and their directory entries, and refuses existing run directories. Partial initialization is retained on error and cannot be resumed or overwritten.

`append(EventDraft)` serializes one bounded JSON line, calls `write_all`, `flush` and `sync_all`, and returns its envelope only after all succeed. An I/O failure makes the writer unusable. Size/serialization errors before I/O leave prior records intact. A writer remains synchronous and single-owner; future asynchronous callers must arrange their own bounded ownership boundary.

Default limits are 1 MiB per event including newline, 64 MiB per journal, and 4 MiB per manifest. They can be changed through the Rust `JournalLimits` API without changing configuration schema 1. Wall-clock UTC and monotonic elapsed time are distinct. `JournalClock` permits controlled time tests; production uses `SystemClock`.

`JournalReader::open` reads the fixed manifest/events filenames and checks schema 1. Iteration yields complete events in sequence from one and checks run identity and nondecreasing elapsed time. A trailing record without newline is never accepted, even if its JSON parses. Earlier complete events remain available. `JournalReadStatus` is `Reading`, `CleanEof`, `TruncatedTail`, or `Failed`; malformed complete records are reported once and terminate iteration. Size limits apply during reading, before unbounded allocation.

The writer leaves manifest/artifact completeness false and hashes/sizes unknown. Neither a clean EOF nor successful append verifies recovery or artifact integrity. Hash checking, full run finalization and user-facing reports remain later work. Raw deserialization of an evidence type alone does not perform these journal checks.

## Minimal FRR fixture

The [Sprint 2 fixture](../lab/s02/topology.clab.yml) is JSON-syntax YAML, readable with Python's standard library and Containerlab. It has two nodes, `dut` and `peer`; it is not the five-role scenario topology referenced by the public configuration example. Both use the exact FRR image in [versions.json](../lab/s02/versions.json). `dut` runs Zebra but no bgpd; `peer` runs Zebra and bgpd with a passive neighbor. No Rust session is started.

Both nodes use `network-mode: none`, with unused management-network creation disabled. Only their direct `eth1` veth pair connects them. IPv4 addresses are `198.51.100.1/30` and `.2/30`; IPv6 addresses are `2001:db8:2::1/64` and `::2/64`. Management uses Docker exec through the local Unix socket. Data-plane forwarding is disabled for this peer harness.

Host prerequisites: Linux amd64, Python 3, Docker, sudo, iproute2 (`ip`, `ss`), `nsenter`, `readlink`, and dual-family `ping`. Docker/namespace commands use `sudo -n`, so authenticate in the same terminal before invoking the tools. The installer downloads the pinned Containerlab archive, verifies its recorded SHA-256, extracts only the binary, and records the binary checksum under `.cache/tools`.

Run the real acceptance suite from a terminal:

```sh
python3 tools/prepare_lab.py
sudo -v
python3 tools/lab_acceptance.py --output artifacts/lab-s02-local
```

The acceptance suite refuses existing fixture containers, downloads the digest-pinned image before activation, and performs two create/verify/destroy cycles. Each cycle checks IPv4/IPv6 connectivity and expected BGP listeners, rejects a temporary unexpected interface and temporary IPv4/IPv6 default routes, restores the fixture, and verifies cleanup twice. Inventory, FRR/Docker versions, negative-test results and cleanup evidence are written to `summary.json`. Failed or interrupted work is recorded as incomplete. Use a new output directory for each attempt.

Individual lifecycle operations are also available once the pinned image is present:

```sh
python3 tools/lab.py preflight
python3 tools/lab.py up
python3 tools/lab.py verify
python3 tools/lab.py down
```

`--output FILE` additionally saves a JSON result without overwriting an existing file. `preflight` does not fetch images. `up` refuses occupied names and attempts cleanup after partial deployment. `down` checks both fixture and Containerlab ownership labels before removal; repeating it is safe. Verification checks namespace identity, Docker network attachment, image ID, published ports, interfaces, veth pairing, addresses, routes and policy routing. Offline tests of these predicates are useful regressions but do not prove that a real lab was deployed.

## Bounded fuzzing

The separate `fuzz` workspace pins `libfuzzer-sys 0.4.13`, its own lockfile, and `nightly-2026-11-09`. The main workspace remains on Rust 1.93.1. The pinned cargo-fuzz version uses sanitizer instrumentation and needs the nightly `rust-src` component plus a C++ compiler.

```sh
rustup toolchain install nightly-2026-11-09 --profile minimal --component rust-src
cargo +nightly-2026-11-09 install cargo-fuzz --version 0.13.2 --locked
python3 tools/fuzz.py --output artifacts/fuzz-local --seconds 600 --seed 1
```

`framing` compares split and unsplit decoding with an 8192-byte input limit. `control_messages` tests decoding and canonical re-encoding with a 4096-byte input limit. Each has a two-second per-input timeout and 1024 MiB RSS limit. The fixture catalogue materializes independent binary seeds into the run's corpus; generated corpus entries and crash inputs stay in artifacts rather than modifying fixtures.

The runner checks the pinned cargo-fuzz version, validates dependency resolution with `cargo metadata --locked`, and checks that cargo-fuzz did not change the lockfile. It requires a normal libFuzzer completion line covering the requested duration, not just exit code zero. It records tool versions, seed/corpus hashes, logs, elapsed time, exit codes and failure files. A fixed seed aids replay but does not make timed fuzzing exhaustive or prove full protocol conformance. Reproduce a failure using its saved input and the recorded toolchain/command.

## Local and remote checks

The five Rust checks in the [root README](../README.md#development-checks) remain required. Run the additional unprivileged checks with:

```sh
python3 -m unittest discover -s tools/tests -v
cargo +1.93.1 fmt --manifest-path fuzz/Cargo.toml -- --check
```

Normal CI runs Rust and offline lab-validation tests. The manually triggered fuzz workflow saves logs/corpora/reproducers even on failure. Privileged lab acceptance is explicit local work; it is not silently enabled for pull requests. Neither a workflow file nor offline predicate tests count as an executed remote/lab acceptance run.
