# Passive BGP analysis

The AN03–AN07 increment adds RIPEstat lookup, MRT inspection, BGP PCAP/PCAPNG inspection,
RIS Live recording, source-local change observations, and offline reports. These operations
do not require Docker, a lab configuration, private ASNs, documentation addresses, or root.
The active lab engine remains deferred; its static validation rules are unchanged.

## Commands

```sh
bgp-hijack lookup ip 193.0.0.1 --format json
bgp-hijack lookup prefix 193.0.0.0/21
bgp-hijack lookup asn AS3333 --start 2026-11-01T00:00:00Z --end 2026-11-02T00:00:00Z
bgp-hijack inspect mrt routes.mrt.gz --output artifacts/mrt-001
bgp-hijack inspect pcap session.pcapng --output artifacts/pcap-001
bgp-hijack inspect pcap midstream.pcap --session-context context.yaml --output artifacts/pcap-002
bgp-hijack watch routes --prefix 193.0.0.0/21 --collector rrc00 --duration 60 --output artifacts/watch-001
bgp-hijack report --analysis artifacts/watch-001 --format json
bgp-hijack lab validate --config examples/lab-forward.yaml --static
```

Output directories must not exist; their parent must exist. `inspect` and `watch` print JSON
summaries. `lookup` and `report` accept `--format text|json`. Diagnostics use stderr.
Legacy `validate`, `run`, and `report --run` retain their previous behavior. `lab run`,
`lab report`, and live lab validation still return an explicit unsupported error.

| Code | Meaning |
| --- | --- |
| 0 | Requested processing completed. No-data lookup is a valid result. |
| 2 | Argument, configuration, or contract error. |
| 3 | Provider or storage failure. |
| 4 | Partial analysis, missing integrity evidence, or incomplete recording. |
| 130 | User interruption. |

Finding an origin change does not itself change the exit code. Offline commands perform no
network enrichment. Lookup uses the official RIPEstat HTTPS origin; watch uses the official
RIS Live WSS origin. Rust APIs accept explicit alternate endpoints for local mock tests.

## Sources and visibility

IP lookup uses `network-info`, prefix lookup uses `prefix-overview`, and ASN lookup combines
`as-overview` with `announced-prefixes`. ASN queries default to the preceding 24 hours.
Provider response envelopes preserve source time, visibility thresholds, filtering messages,
related-prefix truncation, and less-specific matches. Retrieval time is recorded separately.
An announcing ASN is not proof of address ownership; a registry holder label is separate data.
RIPEstat Network Info uses periodic RIS data, not a real-time packet path measurement.

Requests have a 10-second connect and 30-second request timeout, a 4 MiB response bound,
and at most three attempts. Retry-After is honored up to a 30-second retry budget; a larger
server delay is reported instead of retried early. There is no persistent lookup cache.

Watch requires prefix and collector filters and a duration of 1–86400 seconds. Repeated
prefix/collector flags create at most 128 subscriptions. Prefix matching is exact by default;
`--more-specific` adds contained prefixes. Receipt of all subscription acknowledgements is
required for successful collection. A disconnect records a gap and invalidates comparisons;
reconnection creates a new epoch. The feed is not an initial complete RIB. Silence does not
mean withdrawal. A source's first route is a baseline observation, not an origin-change alert.

## Supported inputs

| Input | Supported | Explicit partial coverage |
| --- | --- | --- |
| BGP UPDATE | IPv4/IPv6 unicast, MP_REACH/MP_UNREACH, AS_PATH segments, AS4_PATH reconstruction, two/four-octet ASN contexts, contextual ADD-PATH | Other AFI/SAFI, malformed attributes, messages over 4096 bytes |
| MRT | TABLE_DUMP_V2 peer index and IPv4/IPv6 unicast RIB, BGP4MP/BGP4MP_ET messages and state changes, relevant ADD-PATH subtypes; plain/gzip/bzip2 | Legacy TABLE_DUMP, other subtypes, invalid peer indexes, truncated records |
| Capture | PCAP and PCAPNG enhanced packets; Ethernet/VLAN, raw IPv4/IPv6, SLL/SLL2; TCP port 179 or explicitly described flows | IP fragments, unsupported link types, PCAPNG simple packets without timestamps, missing TCP bytes or context |

Passive decoding never applies a speaker's treat-as-withdraw action. Unsupported records are
counted as gap events, not silently skipped. Unknown attributes remain in raw attribute data.
Malformed framing poisons that TCP stream; arbitrary marker searching is not used to recover it.
No active ADD-PATH capability or Extended Messages support is added to the lab engine.

## Capture session context

Captured OPENs from both directions determine negotiated ASN width and directional ADD-PATH.
Without them, provide a bounded YAML or JSON file. Section/interface indexes are zero-based
for legacy PCAP; PCAPNG section numbers start at one and interfaces start at zero per section.

```yaml
schema_version: 1
sessions:
  - flow:
      section: 0
      interface: 0
      source: 192.0.2.1
      source_port: 50000
      destination: 192.0.2.2
      destination_port: 179
    asn_width: 4
    add_path: []
    first_bgp_sequence: 5000
```

`first_bgp_sequence` is the TCP sequence of the first complete BGP message to decode, or null
when the first captured payload begins at the boundary. No search guesses a boundary inside
an incomplete message. Conflicts with observed OPEN negotiation are errors. Each direction
needs its own context entry if it lacks OPEN evidence. Identical retransmissions are accepted;
conflicting overlaps and retransmissions older than retained history are explicit gaps.

## Evidence, state, and findings

`crates/core` owns shared types and wire decoding. `crates/analysis` owns source adapters,
reassembly, source-local route state, durable bundles, and rules. `crates/cli` presents them.
The lab schema remains version 1; passive manifests use their own `kind: passive_analysis`
and schema version 1, without a fabricated lab configuration or cleanup verdict.

Bundles contain `manifest.json`, `events.jsonl`, `findings.jsonl`, `summary.json`, and
content-addressed evidence under `evidence/`. Source messages/MRT records/relevant packet
bytes are retained; entire input files are not copied. Writer-assigned sequence numbers start
at one, UTC receipt time is separate from source time, and elapsed time is monotonic.
Each event is flushed and synced. Initial manifests are incomplete; final manifests record
artifact sizes and SHA-256 hashes. A finalized partial result still reports its coverage gaps.
A clean JSONL EOF alone never establishes completion.

Reports verify stored artifact hashes and references, then replay normalized observations with
the current rule version. They do not trust the saved summary. Changed/missing artifacts suppress
findings and produce partial coverage; malformed complete JSONL lines or invalid envelope order
are errors. An interrupted final line preserves prior complete records. Hashes detect accidental
changes relative to the manifest; they are not an external signature or source-authenticity proof.

State keys include source, collector, peer, epoch, family/prefix, and path ID. Older epochs cannot
replace newer state. Source time regression invalidates a baseline. Findings are deterministic:

- `origin_changed`: an unambiguous origin changes in one peer's continuous observation period.
- `as_path_changed`: path segments or prepends change for that route.
- `multiple_origins_observed`: differing origins coexist for a prefix in one source/collector
  epoch, with observations no more than five minutes apart. This window is a rule heuristic,
  not evidence that every Internet vantage point sees both routes.
- `more_specific_observed`: a newly observed prefix coexists with a covering route in that peer.

AS_SET does not supply a guessed single origin. Repeated identical observations do not repeat
change findings. Findings retain source identities and event sequence references. None alone
proves malicious hijacking or the actual data-plane path. `coverage: selected_input` describes
processing of the selected input, not global routing-table completeness.

## Resource bounds and validation

Default analysis limits are 1 MiB per evidence/event record, 64 MiB journal, 256 MiB output,
1 GiB decompressed input, 100000 routes, 10000 findings, 64 directional capture flows,
1 MiB retained TCP window per direction, and a 16 MiB live queue. RIS normalization additionally bounds routes/path entries and estimated expansion per message
to 8 MiB. Evidence files are capped
at 10000; per-flow evidence references at 4096. Rust callers can supply `AnalysisLimits`
within the documented implementation ceilings. Limits fail explicitly, with incomplete evidence
preserved. The writer reserves journal space for a terminal gap. Slow storage cannot cause
unbounded WebSocket buffering. Storage errors poison the writer and leave the manifest incomplete.

Run the normal workspace checks and `python3 -m unittest discover -s tools/tests -v`.
Independent wire fixtures are under `crates/analysis/tests/fixtures`; they are not generated by
the Rust BGP encoder. Provider tests use local HTTP/WebSocket mocks, not public services.
`tools/fuzz.py` also supports `updates`, `mrt`, and `tcp`, with a 600-second default per target,
2-second input timeout, 1 GiB RSS ceiling, seed and corpus hashes, and preserved reproducers.
Real service smoke tests, resource measurements, remote CI, and independent review are recorded
separately in the sprint evidence; local success does not imply remote CI or reviewer approval.

References: [RIPEstat API](https://stat.ripe.net/docs/data-api/ripestat-data-api),
[RIS Live](https://ris-live.ripe.net/manual/), [MRT RFC 6396](https://www.rfc-editor.org/rfc/rfc6396.html),
[MRT ADD-PATH RFC 8050](https://www.rfc-editor.org/rfc/rfc8050.html).

Metrics report event-append flush/sync latency and queue occupancy. Output-byte counters cover
recorded evidence and events before final summary/manifest serialization. RSS measurements in
the acceptance record describe only the stated synthetic workload.
