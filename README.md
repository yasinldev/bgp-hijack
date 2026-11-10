# BGP Hijack Lab

A Rust toolkit for passive BGP analysis and reproducible experiments in isolated laboratories.

**Current implementation: passive analysis increment (AN03–AN07).** Query IP/prefix/ASN
observations with RIPEstat, inspect MRT and BGP PCAP/PCAPNG files, record filtered RIS Live
updates, and replay evidence into change reports. These commands need no lab or root access.
The core provides custom BGP control/UPDATE decoding and durable recording. Active BGP sessions,
route advertisements, packet capture, forwarding, and blackhole scenarios remain deferred.
See the [passive analysis guide](docs/passive-analysis.md) and [sprint record](docs/sprint-plan.md).

```sh
bgp-hijack lookup asn AS3333 --format json
bgp-hijack inspect mrt routes.mrt.gz --output artifacts/mrt-001
bgp-hijack inspect pcap session.pcapng --output artifacts/pcap-001
bgp-hijack watch routes --prefix 193.0.0.0/21 --collector rrc00 --duration 60 --output artifacts/watch-001
bgp-hijack report --analysis artifacts/watch-001 --format json
```

Create the parent `artifacts/` directory first; each run directory must be new.

## Build

The workspace pins Rust **1.93.1** and commits `Cargo.lock`. With [Rustup](https://rustup.rs/) installed:

```sh
rustup toolchain install 1.93.1 --profile minimal --component rustfmt --component clippy
cargo build --workspace --locked
# Optional: install the executable on your PATH
cargo install --path crates/cli --locked
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

Invalid input produces an error with file/field context on stderr and exits with code `2`. Help and version requests exit with `0`. Live `validate` without `--static`, `run`, and `report --run` currently return an explicit unsupported-operation error with code `2` and do not create run artifacts.

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

The core library is in `crates/core`; passive adapters and reports are in `crates/analysis`; argument handling and command output are in `crates/cli`. Configuration, codec, journal, verdict, serialization, and CLI tests cover failures and independent fixtures. The evaluator assumes caller-supplied observations; lab artifact integrity verification remains future work. Passive reports verify their own bundle artifacts.

See the [development guide](docs/development.md) for codec/journal APIs, the two-node FRR fixture, its real acceptance command, and reproducible fuzzing. These developer tools do not implement active `lab run` or `lab report`.

## Project documents

Start with the [documentation index](docs/README.md), [sprint plan](docs/sprint-plan.md), and [roadmap and validation gates](docs/roadmap-and-validation.md). The next release targets passive analysis. IPv4/IPv6 forwarding and controlled-blackhole experiments remain in the deferred active backlog.

Licensed under [Apache-2.0](LICENSE).
