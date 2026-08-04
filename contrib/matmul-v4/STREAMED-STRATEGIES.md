# V3 Streamed adversarial strategies (harness)

> **Historical Profile-2/coupled measurement vocabulary.** These strategies do
> not describe MatMul v4.7 Epoch-A Profile-1 ExactReplay and provide no
> consensus authority. Profile 2 is reserved for proof-authoritative Epoch D.
> See `doc/btx-matmul-v4.7-transition-roadmap.md`.
>
Labels for capacity-bypass measurement campaigns. C++ enum:
`src/matmul/matmul_v4_rc_streamed_strategy.h`.

| Label | Meaning |
|-------|---------|
| `hot_32gib_cache` | Hot ~32 GiB page working set on device |
| `pinned_host` | Pinned-host staging of bank pages |
| `double_buffer` | Compute / H2D overlap via double buffering |
| `seed_regen` | Regenerate pages from seed/XOF |
| `multi_gpu_shard` | Multi-GPU consumer sharding |
| `partial_cache_stream` | Hot cache + stream cold pages |
| `partial_cache_regen` | Hot cache + regen cold misses |

Q digests: use `TryMineRCCoupledBatch` (≤ `kRCMinerBatchQMax`) or
`RunCoupledQSweep` (harness, may exceed miner max). Independent per-nonce state;
no slot-0 serialization. Do not invent performance numbers.
