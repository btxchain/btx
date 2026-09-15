# Reachability

A listen socket is not proof of public reachability.

## States

| State | Meaning |
|---|---|
| `UNKNOWN` | No evidence yet |
| `PRIVATE` | Dial-backs failed or never succeeded |
| `PUBLIC_DIRECT` | ≥2 independent peers completed PQ1 to a candidate |
| `PUBLIC_MAPPED` | Same, and a PCP/NAT-PMP mapping is in use |
| `RELAY_REACHABLE` | Direct failed; a reservation is healthy |
| `DEGRADED` | Network epoch changed; re-probe |

`PUBLIC_*` requires **two** successful dial-backs from distinct netgroups.
One observer cannot force an advertised endpoint. Observations of wallet
or RPC ports are ignored.

## AutoNAT-style probes (BTX-native)

`POST /btx-model/2/ext/autonat/probe` asks a peer to attempt a model-plane
PQ1 connect to a candidate. The helper:

- rate-limits per requester and netgroup
- caps concurrent probes
- rejects RFC1918/link-local targets except explicit local test mode
- rejects control-plane ports (8332, 18443, attestor/wallet)
- requires a request id and TTL

Reports are `POST /ext/autonat/report`. They are evidence, not consensus,
and are never written to the chain.

Proof TTL is 15 minutes. A network epoch (address change, sleep/wake)
invalidates `PUBLIC_*`.

## Host advertisement

`NODE_MODEL_HOST` / helper `advertised_host` is allowed only when the
operator asked to host **and** reachability is `PUBLIC_DIRECT` or
`PUBLIC_MAPPED`. Mapping success alone is not enough. Relay-only nodes
advertise the relay form, not a fake direct host.

When proof expires, the host hint is withdrawn.
