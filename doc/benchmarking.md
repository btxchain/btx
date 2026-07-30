Benchmarking
============

Bitcoin Core has an internal benchmarking framework, with benchmarks
for cryptographic algorithms (e.g. SHA1, SHA256, SHA512, RIPEMD160, Poly1305, ChaCha20), rolling bloom filter, coins selection,
thread queue, wallet balance.

Running
---------------------

For benchmarking, you only need to compile `bench_btx`.  The bench runner
warns if you configure with `-DCMAKE_BUILD_TYPE=Debug`, but consider if building without
it will impact the benchmark(s) you are interested in by unlatching log printers
and lock analysis.

    cmake -B build -DBUILD_BENCH=ON
    cmake --build build -t bench_btx

After compiling bitcoin-core, the benchmarks can be run with:

    build/bin/bench_btx

The output will look similar to:
```
|               ns/op |                op/s |    err% |     total | benchmark
|--------------------:|--------------------:|--------:|----------:|:----------
|       57,927,463.00 |               17.26 |    3.6% |      0.66 | `AddrManAdd`
|          677,816.00 |            1,475.33 |    4.9% |      0.01 | `AddrManGetAddr`

...

|             ns/byte |              byte/s |    err% |     total | benchmark
|--------------------:|--------------------:|--------:|----------:|:----------
|              127.32 |        7,854,302.69 |    0.3% |      0.00 | `Base58CheckEncode`
|               31.95 |       31,303,226.99 |    0.2% |      0.00 | `Base58Decode`

...
```

MatMul v4.7 ExactReplay campaigns
---------------------------------

`bench_btx` microbenchmarks do not establish the Epoch-A latency gate.
Profile 1 ExactReplay must be measured end to end with production dimensions,
a real accelerator, and dimension-bound headers:

```bash
BTX_MATMUL_V4_BACKEND=metal \
  build-metal/bin/matmul-v4-rc-harness \
  --base-production --episodes 100 --backend metal \
  --source-revision "$(git rev-parse --short=12 HEAD)" \
  --out profile1-metal-loaded-100.json
```

Use the equivalent strict CUDA build/backend invocation on NVIDIA. A p99 claim
requires at least 100 continuous samples; a 12-sample tail is useful
cross-backend evidence but is not a stable p99. Reports used for activation
review must record 100 distinct `matmul_dim=4096` headers, exact device
coverage, zero unintended CPU fallback, the maximum and nearest-rank
percentiles, worst adjacent pair, and ending queue depth at 90-second arrivals.

Also run the actual-consensus two-winner/back-to-back and three-branch reorg
campaigns with one device submitter. Cross-machine certification requires
byte-identical digests for the same frozen headers across Metal, CUDA, and the
portable oracle. Profile 2 timing is research evidence for Epoch D; it is not
an Epoch-A ExactReplay acceptance result. See
[the transition roadmap](btx-matmul-v4.7-transition-roadmap.md) and
[launch-candidate gates](matmul-v4-exact-replay-launch-candidate.md).

Help
---------------------

    build/bin/bench_btx -h

To print the various options, like listing the benchmarks without running them
or using a regex filter to only run certain benchmarks.

Notes
---------------------

Benchmarks help with monitoring for performance regressions and can act as a
scope for future performance improvements. They should cover components that
impact performance critical functions of the system. Functions are performance
critical if their performance impacts users and the cost associated with a
degradation in performance is high. A non-exhaustive list:

- Initial block download (Cost: slow IBD results in full node operation being
  less accessible)
- Block template creation (Cost: slow block template creation may result in
  lower fee revenue for miners)
- Block propagation (Cost: slow block propagation may increase the rate of
  orphaned blocks and mining centralization)

A change aiming to improve the performance may be rejected when a clear
end-to-end performance improvement cannot be demonstrated. The change might
also be rejected if the code bloat or review/maintenance burden is too high to
justify the improvement.

Benchmarks are ill-suited for testing denial-of-service issues as they are
restricted to the same input set (introducing bias). [Fuzz
tests](/doc/fuzzing.md) are better suited for this purpose, as they are
specifically aimed at exploring the possible input space.

MatMul Proof-of-Work Benchmarking
----------------------------------

The `bench_btx` framework above covers general node/wallet microbenchmarks. It
does **not** cover the MatMul proof-of-work workload — that has its own
dedicated benchmark tool.

The proposed MatMul v4.7 workload is integrated but **not activated on any
public network**. Its Epoch-A benchmark is Profile 1 ExactReplay, using
`matmul-v4-rc-harness --base-production` as described above. Profile 2 is
measured only for later Epoch-D engineering. Legacy carrier, coupled-puzzle,
and `run-full-benchmark.py --shape profile2-production` reports remain useful as dated
component evidence, but they do not substitute for the corrected Profile 1
activation campaign.

Going Further
--------------------

To monitor Bitcoin Core performance more in depth (like reindex or IBD): https://github.com/bitcoin-dev-tools/benchcoin
