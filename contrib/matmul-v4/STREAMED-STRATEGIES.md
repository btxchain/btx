# V3 Streamed adversarial strategies (harness)

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
