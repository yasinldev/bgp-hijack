# BGP Hijack Lab

A Rust research project for reproducible BGP experiments in isolated laboratories.

**Current implementation: Sprint 2 increment.** The executable validates configuration files offline. The core library includes bounded BGP framing/control messages, durable JSONL recording, shared evidence types, and pure result evaluation. A minimal FRR developer fixture and bounded fuzz tools are available. BGP sessions, UPDATE processing, packet capture, scenarios, and artifact-based reports remain planned. See the [sprint record](docs/sprint-plan.md#sprint-2-implementation-record) for verification status.

## Build

The workspace pins Rust **1.93.1** and commits `Cargo.lock`. With [Rustup](https://rustup.rs/) installed:

```sh
rustup toolchain install 1.93.1 --profile minimal --component rustfmt --component clippy
cargo build --workspace --locked
```

The public CLI and normal Rust tests need no Docker installation, running lab, or network-administration privileges. The separate developer lab tool requires local Docker and sudo access. Cargo needs access to dependencies on its first build; configuration validation itself performs no network access.

## Validate a configuration

```sh
cargo run --locked -p bgp-hijack -- validate --config examples/lab-forward.yaml --static
```

Successful output:

```json
{"schema_version":1,"scope":"static","result":"passed","runtime_verified":false}
```

The example references a future `reference.clab.yaml` fixture. That topology does not need to exist for static validation. A passing result verifies the file's schema and declared values; it does not establish that any lab, interface, isolation rule, or BGP capability exists.

Invalid input produces an error with file/field context on stderr and exits with code `2`. Help and version requests exit with `0`. Live `validate` without `--static`, `run`, and `report` currently return an explicit unsupported-operation error with code `2` and do not create run artifacts.

```sh
./target/debug/bgp-hijack --help
./target/debug/bgp-hijack validate --help
```

## Static validation rules

- One UTF-8 YAML document, at most 1 MiB and 64 nesting levels; anchors, aliases, merge keys, and unsupported tags are rejected.
- Unknown/duplicate fields and scalar type coercion are rejected. Numeric fields must be YAML numbers, not quoted strings.
- Prefixes must have zero host bits and match their enabled IPv4/IPv6 families. Each enabled family needs a prefix; an inactive family's prefix may be omitted.
- Reference-lab addresses are restricted to IPv4 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and IPv6 `2001:db8::/32`. Subprefixes must stay within those ranges.
- Local/remote ASNs must be private-use values, with distinct ASNs for each eBGP relationship. Four-octet values are retained without truncation.
- Peer and capture references must name declared nodes; source, experiment, and target capture points are required. Actual interface existence is a later live check.
- Limits must be positive, active duration must cover baseline/convergence/observation, and duration arithmetic must not overflow.

See the [interface contract](docs/interfaces.md) for details and the [example configuration](examples/lab-forward.yaml) for the field layout.

## Development checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
cargo build --workspace --release --locked
python3 -m unittest discover -s tools/tests -v
```

The GitHub Actions workflow runs these commands on Linux with the pinned toolchain. Local execution of these checks does not establish that a remote CI run has occurred.

The core library is in `crates/core`; argument handling and command output are in `crates/cli`. Configuration, codec, journal, verdict, serialization, and CLI tests cover failures and independent fixtures. The evaluator assumes caller-supplied observations; artifact integrity verification remains future work.

See the [development guide](docs/development.md) for codec/journal APIs, the two-node FRR fixture, its real acceptance command, and reproducible fuzzing. These developer tools do not turn `run` or `report` into implemented user commands.

## Project documents

Start with the [documentation index](docs/README.md), [sprint plan](docs/sprint-plan.md), and [roadmap and validation gates](docs/roadmap-and-validation.md). The target first release includes IPv4/IPv6 forwarding and controlled-blackhole experiments with accepting/rejecting prefix-policy fixtures inside the reference lab.

Licensed under [Apache-2.0](LICENSE).
