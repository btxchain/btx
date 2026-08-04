# CUDA Nonce-Seed Scan Multiplier

## Summary

`BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER` controls how far the GPU nonce-seed prehash scanner looks ahead when building a batch of MatMul digest candidates. It is a miner batching heuristic only. It does not change consensus, difficulty, nonce validity, the prehash predicate, or the final digest target.

As of this optimization pass, the default is `1`. Explicit values are clamped to `1..8`, and malformed or non-positive values fall back to `1`.

## What The Multiplier Does

After `nMatMulNonceSeedHeight`, each nonce changes the MatMul seeds. For CUDA mining, the solver first uses a GPU prehash scan to reject most nonces before preparing and digesting full MatMul candidates.

The scan window is sized approximately as:

```text
scan_count = nonce_seed_batch_size * estimated_prehash_spacing * multiplier
```

Where:

- `nonce_seed_batch_size` is the number of passing nonces the solver wants for one digest batch.
- `estimated_prehash_spacing` is derived from `nBits << epsilon_bits`; higher difficulty means larger spacing.
- `multiplier` is `BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER`.

For CUDA, the scan kernel launches one nonce check per thread over the requested scan window. With compact CUDA pass offsets, the GPU returns only passing nonce offsets. The host then rechecks the prehash gate before digest work and stops once the digest batch is full.

A larger multiplier scans farther ahead. That can reduce underfilled batches, but it can also scan past the offset needed to fill the current batch. Those later passing offsets are discarded for the current window and may be scanned again later. The RTX 5060 benchmarks showed that the overscan cost dominates for the current mainnet shape.

## Benchmark Environment

Benchmarks were performed on:

- GPU: NVIDIA GeForce RTX 5060
- CUDA compute capability: `12.0`
- CUDA driver/runtime reported by the build: `13020`
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

The difficulty sweep used this live-chain base:

```json
{
  "next": {
    "height": 142378,
    "bits": "1d013a61",
    "difficulty": 0.8142915719238081,
    "target": "000000013a610000000000000000000000000000000000000000000000000000"
  }
}
```

Raw records are under `../../_audit/benchmarks/`.

## Main Benchmark Results

Initial optimization benchmark at live shape and difficulty. This baseline was taken earlier in the same session at next height `142340`, bits `1d01433a`, difficulty `0.7920020303096222`.

| Run | Mean nonces/sec | Versus baseline | Steady power | Steady efficiency |
| --- | ---: | ---: | ---: | ---: |
| Baseline before compact offsets | `44.23M` | - | `98.75 W` | `434.5k` nonces/J |
| Compact CUDA prehash offsets | `48.49M` | `+9.64%` | `105.31 W` | `460.4k` nonces/J |
| Compact offsets plus multiplier `1` | `52.16M` | `+17.94%` | `105.67 W` | `493.6k` nonces/J |

The multiplier `1` trial was layered on top of compact CUDA prehash offsets.

## Difficulty Sweep

A synthetic difficulty sweep divided the live next-block target by increasing factors and converted the result back to compact `nBits`.

The first sweep used `--tries 200000000`. It showed multiplier `1` winning through roughly `58x`, then apparent convergence around `60x-64x`. A follow-up high-tries sweep used `--tries 600000000` for factors `50x-64x`, so multiplier `2` was no longer capped by the benchmark try count.

High-tries sweep result:

| Factor | nBits | Multiplier 1 scan | Multiplier 2 scan | m1 mean n/s | m2 mean n/s | m1 vs m2 |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 50 | `0x1c06499e` | `170,772,224` | `341,544,448` | `533.27M` | `344.06M` | `+54.99%` |
| 52 | `0x1c060bb6` | `177,602,816` | `355,205,632` | `533.13M` | `345.64M` | `+54.25%` |
| 54 | `0x1c05d263` | `184,433,920` | `368,867,840` | `531.20M` | `346.96M` | `+53.10%` |
| 56 | `0x1c059d29` | `191,264,512` | `382,529,024` | `534.33M` | `348.59M` | `+53.28%` |
| 58 | `0x1c056b9a` | `198,095,616` | `396,191,232` | `538.65M` | `351.39M` | `+53.29%` |
| 60 | `0x1c053d59` | `204,926,464` | `409,852,928` | `542.58M` | `356.72M` | `+52.10%` |
| 62 | `0x1c051214` | `211,757,568` | `423,515,136` | `545.61M` | `356.28M` | `+53.14%` |
| 64 | `0x1c04e984` | `218,587,904` | `437,175,808` | `551.45M` | `367.80M` | `+49.93%` |

In every high-tries case:

- CUDA fallbacks to CPU: `0`
- GPU input generation failures: `0`
- Prepared input counts matched between multipliers.
- Digest batch counts matched between multipliers.
- Steady power was effectively the same, roughly `104-110 W`.

This confirms that the earlier convergence was caused by the `200M` benchmark cap. With the cap removed, multiplier `2` scanned much farther without producing more useful candidate work.

## Review Thresholds

These thresholds are estimates for the observed RTX 5060 configuration, where CUDA auto-selected nonce-seed batch size `256`.

The current data supports multiplier `1` through at least:

```json
{
  "reviewed_through": {
    "factor_vs_2026_06_26_next": 64,
    "bits": "1c04e984",
    "difficulty": 52.11466060312372,
    "target": "0000000004e98400000000000000000000000000000000000000000000000000"
  }
}
```

A conservative soft review point is where multiplier `1` would request about `600M` scanned nonces per batch, matching the largest benchmark try window used in this sweep:

```json
{
  "soft_review": {
    "bits": "1c01ca1c",
    "difficulty": 143.05535659469968,
    "target": "0000000001ca1c00000000000000000000000000000000000000000000000000",
    "reason": "multiplier 1 scan window is approximately 600M nonces at CUDA nonce-seed batch size 256"
  }
}
```

A harder engineering review point is where multiplier `1` reaches the current 32-bit CUDA scan-count ceiling:

```json
{
  "hard_review": {
    "bits": "1b3fff51",
    "difficulty": 1024.027100740106,
    "target": "00000000003fff51000000000000000000000000000000000000000000000000",
    "reason": "multiplier 1 scan window reaches the uint32 scan-count ceiling at CUDA nonce-seed batch size 256"
  }
}
```

These are review triggers, not predicted crossover points. The high-tries data did not show multiplier `2` becoming better. The likely future work at very high difficulty is adaptive scan continuation or larger scan-count plumbing, not simply returning to multiplier `2`.

For other CUDA batch sizes, the review difficulties scale roughly by:

```text
review_difficulty_for_batch ~= review_difficulty_for_batch_256 * 256 / nonce_seed_batch_size
```

For example, if a larger GPU auto-selects batch size `512`, the soft review point moves from difficulty `~143` to `~71.5`; with batch size `1024`, it moves to `~35.8`. Larger batches also reduce relative prehash pass-rate variance, so this scaling is only a trigger to remeasure, not a reason to prefer multiplier `2`.

## Operator Guidance

Normal operation should leave `BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER` unset and use the default `1`.

Use an explicit override only for controlled benchmarking:

```bash
BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER=2 \
build-cuda/bin/btx-matmul-solve-bench --backend cuda ...
```

When benchmarking high-difficulty scenarios, choose `--tries` large enough that the requested scan windows are not accidentally capped. Otherwise multiplier values can look artificially similar.
