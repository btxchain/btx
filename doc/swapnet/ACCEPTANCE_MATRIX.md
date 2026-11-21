# Acceptance matrix for the shared-core candidate

Every row needs an exact source commit, commands, environment, exit status and raw evidence. The package report records only what this build session actually executed. Required platform/chain rows remain NOT_RUN unless a matching receipt exists.

| Gate | Acceptance |
|---|---|
| Pinned integration | Generated full files/patch; exact before/after hashes; newer branch overlaps reviewed |
| Shared core | Wrong network/PQ1 rejection, namespace isolation, finite memory, route expiry/replay, fair scheduling, cursor bounds |
| Python controls | Integer boundaries, fee/reference limits, identity-count disclaimers, stale inputs, maker skew/minimum/floor |
| Authority | New observer cannot spend; mode is not a mandate; non-owner mutation refused; cross-principal/wallet previews refused |
| Preview recovery | Expiry, policy change, rejected save, duplicate confirmation, crash before/after acceptance acknowledgement |
| Existing coordinator | Original full suite remains green; no regression of #805/#809/#814/#816 |
| Native build | Actual daemon, embed/transport, wallet/PQ, ModelNet and Qt targets compile with matched Python/crypto |
| Qt/CLI | Exact amounts/caps, no UI-thread RPC blocking, explicit consent, safe error/timeout handling |
| Bitcoin setup | No node/ambiguous wallet/incorrect watch type/partial failure/restart; no private-key import or spending |
| EVM proof | Wrong init with matching runtime refused; direct and deterministic deployment proof; missing proof blocks new trades only |
| Finality/RPC | Lag at quote/accept, RPC 429/outage recovery/backoff; no latest downgrade; existing refund continues |
| Real BTC lifecycle | Both directions, exact funding and final balances, confirmation/maturity boundaries |
| Real ETH lifecycle | Both directions, contract lock/claim/refund and exact finalized pull withdrawal |
| Crash/reorg | Every durable boundary, original-byte rebroadcast, adopted funding, unknown fee refusal, secret monotonicity |
| Hostile network | Multi-hop delay/loss/replay, preferred-hop blackhole, >32 providers, sequence-history churn, PQ1 wrong network |
| Multi-platform | Clean Linux/macOS/Windows build/install/start/stop/restore; source probes alone insufficient |
| Release | Signed provenance, dependency hashes, packaged recovery, reproducible final binary receipts |
| Independent review | Scope appropriate to funds at risk; no claim that tests constitute an audit |

## Economic release indicators

Measure actual executable net quotes and funded completions, not advertisement counts. Record spreads/dispersion at exact sizes, failures to fund, refund delays, fee exposure and concentration by signing identity with ownership uncertainty. Do not label a timeout as fraud or count self-reported reserves as proven liquidity.
