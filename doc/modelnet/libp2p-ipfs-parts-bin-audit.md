# libp2p / IPFS parts-bin audit (BTX 0.34.7 connectivity)

Study-only. These trees are **not** vendored, linked, or depended on at
runtime. Identity, PQ1, and model resource IDs stay BTX-native.

Reference clones (`~/Documents/btx-reference-sources/`, 2026-09-15):

| Tree | SHA | describe |
|---|---|---|
| go-libp2p | `e20bb60ffc4b4ee33640e5fe8f45fccce893cecd` | e20bb60 |
| rust-libp2p | `050fbb77bfdede696344da8d4602536b52bcf19e` | 050fbb7 |
| kubo | `421a0f14b26db518e1e161c1b7589f625e2f3981` | 421a0f1 |

## AutoNAT / reachability

| Field | Value |
|---|---|
| upstream | go-libp2p `p2p/host/autonat/autonat.go`; rust-libp2p `protocols/autonat/src/v1/behaviour.rs`, `v2/` |
| functions | `AmbientAutoNAT`, `maxConfidence = 3`, dial-back observations, confidence against a single liar |
| learned | Listen sockets are not public. Confidence needs multiple independent dial-backs. Status expires and is re-probed. |
| failure modes | one malicious observer; probe storms; RFC1918 abuse as a free scanner |
| BTX files | `src/modelnet/reachability.h/.cpp`, helper `POST /ext/autonat/probe\|report` |
| BTX differences | Two independent netgroups (not libp2p peer IDs). Dial-back is a full PQ1 session, not Noise/TLS-classic. No X25519. |
| copy? | No. Confidence idea only. |

## Circuit Relay v2 / reservations / limits

| Field | Value |
|---|---|
| upstream | go-libp2p `p2p/protocol/circuitv2/relay/resources.go`, `constraints.go`, `relay.go` |
| functions | `DefaultResources` (TTL 1h, 128 reservations, 8/IP, 32/ASN), `RelayLimit` 128KiB / 2min |
| learned | Reservations expire. Per-peer / per-IP / global caps. Relays forward opaque bytes. |
| BTX files | `src/modelnet/relay_reserve.h/.cpp`, helper `POST /ext/relay/reserve` |
| BTX differences | Byte ceiling 32 MiB (model pieces). Inner session remains PQ1. No relay wallet/mining role. No automatic spend. |
| copy? | No. Caps and TTL only. |

## DCUtR / hole punching

| Field | Value |
|---|---|
| upstream | go-libp2p `p2p/protocol/holepunch/holepuncher.go` (`maxRetries = 3`, relay-first, then synchronized direct) |
| learned | Direct upgrade after a working relay path. Bounded retries. Identity still via identify on the direct socket. |
| BTX files | `PunchPlan` / `RecordPunchAttempt` in `relay_reserve.*`, helper `POST /ext/holepunch` |
| BTX differences | Direct success requires transport + PQ1 + expected service identity. Relay auth never skips inner PQ1. No classical fallback. |
| copy? | No. Timing/retry idea only. |

## Address observation / listen / NAT mapping

| Field | Value |
|---|---|
| upstream | go-libp2p identify observed-addrs; BTX already has `common/pcp.h` PCP/NAT-PMP |
| learned | Observations are hints. Mapping is a separate gateway protocol. UPnP/PCP must not expose unrelated ports. |
| BTX files | `src/modelnet/model_nat.*` (model port 29447 only), `ReachabilityTracker` observations |
| BTX differences | Wallet RPC, monetary RPC, attestor cookie paths are forbidden. Mapping failure is fail-soft. Mapping ≠ public until dial-back. |
| copy? | No. Reuse existing BTX PCP, do not add miniupnpc. |

## Provider records / Kademlia / client vs server

| Field | Value |
|---|---|
| upstream | kubo `core/node/provider.go`, `routing/delegated.go` (`dht.ModeClient` vs server); go-libp2p kad-dht |
| learned | Provider records expire (hours). Unreachable nodes should not serve the DHT. Bootstrap is introduction only. |
| BTX files | `src/modelnet/provider_route.h/.cpp` typed `btx-provider-v1` records, k-buckets, netgroup cap 2 |
| BTX differences | SHA-384 model IDs, ML-DSA-44 signatures, no CIDs, no generic PUT, not monetary AddrMan. Fine-grained piece maps stay on the PQ1 availability query. |
| copy? | No. Typed records + bucket diversity only. |

## Connection manager / racing / QUIC

| Field | Value |
|---|---|
| upstream | go-libp2p swarm dial racing; QUIC migration in quic-go |
| learned | Race a small candidate set; first authenticated win. QUIC helps NAT/mobility. |
| BTX | `RaceBounded` + `ConnectionFullyReady`. **QUIC deferred**: cannot carry strict PQ1 (ML-KEM-768 + ML-DSA-44, no X25519) without a new transport design. TCP/PQ1 + relay/hole-punch is the 0.34.7 path. |
| copy? | No. |

## Network changes / reconnect

| Field | Value |
|---|---|
| upstream | libp2p eventbus interface/address changes |
| BTX | `NetworkEpoch` (address, sleep/wake). Reachability proof invalidates on epoch. Relay reservations may expire during sleep. |
| copy? | No. |

## Intentionally deferred

- AutoNAT v2 protocol bytes / protobuf
- libp2p circuit hop/stop wire
- DCUtR protobuf
- QUIC / WebTransport
- IPFS CID / Bitswap / IPNS
- Generic content DHT
- Tor / I2P
- Global relay reputation token
- Automatic monetary payment for relay capacity
