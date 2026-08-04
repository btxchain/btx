# Parallel block-input prevout fetching

This change is targeted for the BTX 0.33.2 integration. It adapts Bitcoin
Core's parallel-prevout work to BTX's current chainstate and keeps the
transparent UTXO consensus path ordered and unchanged.

## Upstream provenance

The primary source is [Bitcoin Core PR #35295](https://github.com/bitcoin/bitcoin/pull/35295),
merged as `c0e91efdb31fa930593f61cc87464e94c9f1ac72`. The port includes the
required `PeekCoin`, cache reset guard, non-mutating `CoinsViewOverlay`, and
general thread-pool architecture rather than transplanting only the final
parallel loop.

It also incorporates the following hardening from the still-open
[Bitcoin Core PR #35738](https://github.com/bitcoin/bitcoin/pull/35738):

- filter the coinbase transaction ID from the fetch queue;
- delete unsupported `Sync` and `SetBackend` operations on the overlay;
- report the reason for a thread-pool submission failure; and
- document ownership, lifetime, and memory-ordering invariants.

The BTX adaptation retains the existing `bool Flush()` contract so database
write failures still propagate through `ConnectTip`. It does not import
unrelated newer UTXO-cache API changes.

## Safety invariants

- `ConnectTip` and all externally visible overlay methods remain protected by
  `cs_main`.
- Workers only call the non-caching `PeekCoin()` path. They do not mutate the
  parent UTXO cache or the overlay cache.
- The validation thread consumes prefetched inputs in block order. An atomic
  ready flag publishes each result with release/acquire ordering.
- References in the work queue point into the connected block. The reset guard
  drains and joins all submitted tasks before those references can expire,
  including every early-return and failed-validation path.
- Outputs created earlier in the same block, including coinbase outputs, are
  omitted from the fetch queue and are read from the overlay after creation.
- A disabled, inactive, interrupted, or concurrently stopping pool falls back
  to serial lookups without changing validation results.
- The reusable overlay is flushed only after successful block connection and
  reset after every attempt.

## Configuration

`-prevoutfetchthreads=<n>` selects the number of additional fetch workers.
The BTX default is 2, values are capped at 16, `0` disables parallel fetching, and
negative values are rejected.

## Test coverage

- Unit tests cover thread-pool lifecycle, submission failure, exception
  propagation, overlay isolation, spent parent entries, reset/flush reuse,
  disabled/interrupted fallback, and coinbase filtering.
- The chainstate argument test covers the default, disabled, explicit, capped,
  and rejected configurations.
- `feature_prevoutfetch.py` connects the same P2MR blocks on nodes with parallel
  and serial fetching, including a transaction that spends an external
  prevout, and asserts identical tips.

## Performance validation

Bitcoin Core's reported results are not BTX benchmark results. Before claiming
a speedup, compare default settings against `-prevoutfetchthreads=0` using the
same BTX 0.33.2 binary, chain data, pruning mode, `-dbcache`, storage device,
and hardware. Record both IBD/reindex wall time and peak memory. In particular,
do not compare runs with different `-dbcache` values as if thread count were
the only variable.

Two reproducible benchmarks cover the two performance regimes:

- `bench_btx -filter='CoinsViewOverlay.*'` measures the overlay with both an
  immediately available parent view and a controlled 50 microsecond wait per
  parent lookup. The latter models concurrent I/O latency without claiming to
  reproduce a particular storage device.
- `feature_prevoutfetch_benchmark.py` mines a persisted UTXO set, restarts the
  serial and parallel target nodes before each trial, submits identical
  spend-heavy blocks to both, extracts the `ConnectBlock` times from bench
  logging, and checks that all nodes reach the identical tip. Restarting clears
  the node and LevelDB caches, but it cannot clear the operating system's page
  cache.

On 2026-07-17, a release build on an Apple M4 Max Mac Studio produced:

| Workload | Serial | Parallel configuration | Serial / parallel |
|---|---:|---:|---:|
| Overlay, immediately available lookup | 26.07 ns/prevout | 237.93 ns/prevout (8 workers) | 0.11x |
| Overlay, controlled 50 us lookup wait | 79.23 us/prevout | 10.43 us/prevout (8 workers) | 7.59x |
| Persisted LevelDB, 50,000 contiguous prevouts/block, median of 6 | 129.39 ms/block | 153.07 ms/block (8 workers) | 0.85x |
| Persisted LevelDB, 20,000 contiguous prevouts/block, median of 6 | 47.31 ms/block | 39.79 ms/block (2 workers) | 1.19x |
| Persisted LevelDB, 20,000 scattered prevouts/block, median of 6 | 52.39 ms/block | 39.72 ms/block (2 workers) | 1.32x |
| Reindex-chainstate wall time, median of 5 | 1.85 s | 1.79 s (8 workers) | 1.03x |

The first persisted workload deliberately exposes the fast-storage downside:
all prevouts share one transaction ID and contiguous database-key range, so
eight-way scheduling costs more than it can overlap. The scattered workload
first fans the coins into distinct transaction IDs and is closer to IBD's
non-contiguous UTXO access. It is the basis for BTX's conservative two-worker
default. Operators should still compare `0`, `2`, and higher values on their
own storage before changing the default.

The persisted tests used the same chain and binary, `-dbcache=4` and `-par=1`.
Every serial and parallel block was accepted and all three nodes ended at the
same tip. With controlled lookup latency, the overlay scaled as expected: 2,
4, 8, and 16 workers processed 25.2k, 49.7k, 95.8k, and 187.3k prevouts per
second respectively.

Five paired `-reindex-chainstate` runs over the same 108-block corpus provided
an additional full-node-path check. Across the 30 spend-heavy block samples,
the serial and parallel median connect times were 80.11 ms and 79.20 ms
respectively (1.01x), with the parallel run faster in 25 of 30 pairs. The
requested 4 MiB cache still reported 42.1 MiB in use for this small corpus, so
this was predominantly a memory-resident reindex and the 1% to 3% improvement is
modest. As the node warns, BTX `-reindex-chainstate` does not rerun every MatMul
Phase 2 contextual check; that limitation does not bypass the transparent UTXO
connection path measured here.

These results confirm the implementation and its latency-hiding mechanism,
including a 31.9% measured connect-time improvement on scattered persisted
prevouts. They do not establish an unconditional whole-IBD speedup. A broad
public IBD claim should still be based on an actual BTX 0.33.2 IBD or reindex
run whose UTXO set exceeds memory on intended release hardware.
