> **Historical provenance / current deferral.** This document preserves a dated
> design, audit, or measurement record; its body is not the current activation
> plan. Current source keeps public-network Epoch A (`v4 = BMX4C = RC`) disabled
> at `INT32_MAX`, with RC ASERT `1/1` and GPU-lifecycle ratification false.
> The current signed annotated `v0.33.2` tag identifies an earlier `H=185000`
> source tree. It was recreated during pre-release work; no GitHub v0.33.2
> release, assets, or release binaries were published. The tag is not the
> corrective tree; any further disposition requires an explicit release decision.
> See the
> [canonical transition roadmap](btx-matmul-v4.7-transition-roadmap.md).

# V3 adversarial miner analysis (attack-first)

## Architectural blunt answer

A **static template-scoped bank** alone cannot *guarantee* B200 ≻ RTX 5090 on $/block when miners may batch unlimited nonces and regenerate/cache pages. Batching amortizes bank load; regeneration bypasses capacity. Any GO claim requires matched device-timed measurements with the **best legal Streamed strategy** on 5090, not the reference miner.

## Attack surface (status)

| Attack | Status |
|--------|--------|
| Strassen / fast matmul | OPEN — exact int path must remain oracle |
| Shared-B batching across Q | OPEN — Q is miner-opt; consensus M=128 fixed |
| Seed-only regeneration | OPEN — primary TMTO threat |
| Partial 32 GiB cache | OPEN — erodes V2; challenges V3 |
| Multi-GPU consumer sharding | OPEN |
| Exchange algebraic collapse | OPEN — X_exchange still largely decorative |
| Accumulator overflow / UB | MITIGATING — checked MAC helpers; butterfly bounds required |
| CPU/GPU divergence | IN PROGRESS — medium digest fix (full page accumulate) |
| Proof forgery | GKR G1–G5 constructions integrated & validated in-tree (external audit pending); arbiter OFF |

## Nonce-conditioned transforms

Diagonal signs/scales/permutations that push into A or Y do not prevent batching. Resistance must be demonstrated, not assumed.
