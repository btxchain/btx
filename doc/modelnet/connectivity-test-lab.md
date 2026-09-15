# Connectivity test lab

Real NAT topologies live in `contrib/modelnet/e2e-connectivity-lab.sh`.

The script uses Linux network namespaces when `CAP_NET_ADMIN` is
available. Without it, loopback PUBLIC stand-in (A), IPv6 `::1` (H),
and roam (G, via `e2e-combined-20.sh`) still run. Topologies B–F stay
`NOT_RUN`.

Never point this lab at production `btxd`, attestors, or public IPs.

## Target topologies

| Id | Topology | Expected path |
|---|---|---|
| A | public ↔ public | direct PQ1 |
| B | private ↔ public | outbound or mapped |
| C | private ↔ private | rendezvous, hole punch, direct if possible |
| D | symmetric-like NAT | punch fails, relay stays up |
| E | relay failure | alternate reservation |
| F | bootstrap loss | provider lookup continues |
| G | roam mid-download | job resumes, pieces kept |
| H | global IPv6 | prefer direct v6 |

Namespace recipe (when permitted): veth pairs, `nft`/`iptables` MASQUERADE,
cone vs port-restricted vs address-and-port-dependent mapping, no
production endpoints.

Combined swarm + connectivity (rarest-first + relay/direct mix) is
`contrib/modelnet/e2e-swarm-three-peer.sh` plus this lab. The 13.8 GiB
granite fixture is opt-in (`BTX_SHARD19=1`) and is not claimed from tiny
fixtures.
