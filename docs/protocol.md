# BGP protocol contract

**Status: planned.** This is the required subset for the first release, not a claim of a complete BGP implementation.

## Supported subset

| Feature | First-release contract |
| --- | --- |
| Session type | Configured eBGP peers inside the reference lab. |
| Transport | TCP with explicit local lab-interface binding and declared peer endpoints. |
| Messages | OPEN, UPDATE, KEEPALIVE, and NOTIFICATION. |
| Capabilities | Multiprotocol unicast and four-octet ASNs. |
| IPv4 routes | AFI 1 / SAFI 1; conventional IPv4 UPDATE encoding in the reference fixture. |
| IPv6 routes | AFI 2 / SAFI 1 through MP_REACH_NLRI and MP_UNREACH_NLRI. |
| ASN representation | Unsigned 32-bit values throughout the internal model. |
| Routes | Per-peer announcements, withdrawals, and session-scoped observations. |
| Outbound updates | Only the named scenario's declared lab routes; no automatic redistribution of received routes. |

Reference peers will support four-octet ASNs. Interoperability with legacy peers that lack that capability is deferred; such a peer will fail the first-release compatibility check before scenario activation. Private ASNs above 65535 will be included in the test fixtures to catch truncation.

Route Refresh, Extended Messages, ADD-PATH, Graceful Restart, iBGP/route reflection, confederations, VPN address families, and general-purpose best-path routing are deferred. Their capabilities will not be advertised. Unsupported features will not be silently interpreted as supported ones.

## Framing and decoding

The codec will handle a byte stream: one read may contain part of a message or several messages. It will validate the common header before allocating storage for the body, preserve incomplete input for a later read, and distinguish incomplete data from a malformed complete message.

Without Extended Messages, the accepted message-size ceiling will be 4096 octets. KEEPALIVE has no body. Lengths, nested attribute boundaries, NLRI prefix lengths, and buffer arithmetic will be checked before access. Malformed peer input must not cause a panic or an unbounded allocation. The base message layouts are defined by [RFC 4271](https://www.rfc-editor.org/rfc/rfc4271.html).

Decoded values will preserve attribute flags and AS-path segment types. Prefixes will be canonicalized before use as keys. The first-release fixture will use AS_SEQUENCE paths. AS_SET and AS_CONFED_SET will not be originated; received routes containing them will use treat-as-withdraw handling under [RFC 9774](https://www.rfc-editor.org/rfc/rfc9774.html). Unsupported path forms will never be flattened into a plausible-looking sequence.

## OPEN and capability handling

The engine will validate the BGP version, peer identity, BGP identifier, hold time, and optional-parameter bounds. BGP identifiers remain four-octet identifiers even in an IPv6 experiment. Capabilities will be processed independently rather than assuming a fixed order. Unknown capabilities will follow the handling specified by [RFC 5492](https://www.rfc-editor.org/rfc/rfc5492.html).

Four-octet ASN handling will follow [RFC 6793](https://www.rfc-editor.org/rfc/rfc6793.html). Address-family negotiation and IPv6 reachability encoding will follow [RFC 4760](https://www.rfc-editor.org/rfc/rfc4760.html). A missing family required by the selected run will prevent activation; an IPv6 request will not fall back to an IPv4-only result.

The reference fixture will use IPv4 transport carrying both IPv4 and IPv6 unicast routes. IPv6 NLRI and IPv6 next hops will be tested independently of that transport choice. IPv6-only BGP transport is a later interoperability extension, not required for the first release's IPv6 data-plane coverage.

## Session ownership and FSM

The session engine will implement Idle, Connect, Active, OpenSent, OpenConfirm, and Established states. Each transition will have a typed triggering event, a timer action, a socket action, and an observable result. An FSM test table will be introduced with the implementation rather than embedding transitions across unrelated socket callbacks.

Only the session owner will mutate its connection state. It will handle connection failure, retries, simultaneous connection collision, remote NOTIFICATION, EOF, hold expiry, and operator shutdown. Fixture identity checks will prevent an unexpected connection from being mistaken for a declared peer.

Hold/keepalive behavior will use the negotiated hold time, including the permitted zero-hold case. A zero hold time will not disable the scenario manager's independent execution deadlines. Timer tests will use a controllable clock.

## UPDATE and route-state semantics

| Concern | Required behavior |
| --- | --- |
| IPv4 attributes | Decode and validate ORIGIN, AS_PATH, and NEXT_HOP where applicable. |
| IPv6 attributes | Decode MP_REACH_NLRI/MP_UNREACH_NLRI with family-specific next-hop and NLRI validation. |
| Other attributes | Preserve valid observation metadata; handle unknown attributes according to their flags and applicable RFC rules. |
| Announce | Replace the current path only for the same peer, family, and prefix. |
| Withdraw | Remove only that peer's matching route; an absent route is an idempotent no-op. |
| Multiple peers | Retain distinct paths from distinct neighbors. |
| Connection loss | Remove the disconnected session's routes and emit explicit removals. |
| Reconnection | Begin a new epoch and collect fresh observations; no implicit stale-route retention. |
| Late event | Reject events associated with an obsolete session epoch. |

AS-path observation is not packet-path confirmation. Likewise, a peer's announcement is not proof that its route is selected for forwarding. The lab adapter will collect peer routing observations separately, and packet evidence will verify the resulting path.

The route store will expose snapshots and ordered changes. Since ADD-PATH is deferred, it will not invent path IDs. A family reset or session loss will invalidate the affected observations; subsequent reports will retain their historical evidence with the appropriate epoch.

Baseline readiness will depend on expected fixture routes and successful endpoint measurements. A quiet stream, or the absence of an End-of-RIB marker, will not be treated as proof that an arbitrary full routing table has been collected.

## Error handling

The implementation will distinguish session-fatal errors, route withdrawals caused by malformed updates, discarded attributes, and unsupported fixture requirements. UPDATE error handling will be mapped by attribute to [RFC 7606](https://www.rfc-editor.org/rfc/rfc7606.html), rather than resetting a session for every decoder error.

| Error class | Required treatment |
| --- | --- |
| Invalid framing or fatal OPEN/FSM error | Apply the relevant protocol notification/close behavior; remove the session's routes. |
| Attribute error with recoverable affected routes | Apply the RFC's treat-as-withdraw or attribute-discard rule; emit a structured error observation. |
| Ambiguous or unrecoverable UPDATE boundaries | Apply the protocol's prescribed reset behavior; do not guess affected prefixes. |
| Missing required capability | Abort fixture compatibility before scenario activation and report the missing requirement. |
| Resource limit or queue exhaustion | End the affected experiment in a controlled manner; record incomplete evidence and attempt recovery. |

Every supported attribute will receive normal, truncated, invalid-length, invalid-flags, and missing-required-attribute test cases as applicable. The implementation milestone must resolve each case to a documented RFC action before its interoperability gate passes.

## Protocol verification

- Use independent byte fixtures for valid and invalid messages; round-trip tests alone are insufficient.
- Split a message at every byte boundary and combine several messages in one input buffer.
- Exercise the 4096-octet boundary, invalid NLRI lengths, and nested length overflow/truncation.
- Check IPv4 and IPv6 updates, next-hop validation, announcements, and withdrawals.
- Check four-octet private ASNs, capability absence, and unsupported families.
- Verify hold expiry, connection loss, collision handling, and reconnection without stale route resurrection.
- Fuzz framing and decoding under bounded memory with a reproducible seed/corpus for failures.
- Compare session establishment, accepted routes, withdrawals, and error effects with a pinned FRR reference version.

The release record will identify RFC revisions/errata reviewed, the tested subset, the Rust toolchain, and FRR versions. A successful lab test will not be described as full standards conformance.
