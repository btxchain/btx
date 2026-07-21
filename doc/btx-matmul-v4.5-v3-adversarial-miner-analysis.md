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
| Proof forgery | GKR G1–G5 OPEN/PARKED; arbiter OFF |

## Nonce-conditioned transforms

Diagonal signs/scales/permutations that push into A or Y do not prevent batching. Resistance must be demonstrated, not assumed.
