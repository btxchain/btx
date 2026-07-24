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

The current MatMul PoW is **ENC_RC v4.6**, a two-stage design: the profile-2
ENC_RC datacenter episode (`nMatMulRCProfile = 2`) plus the profile-3
ENC_RC_COUPLED V3 production puzzle (`nMatMulRCCoupledProfile = 3`). It is
integrated and code-complete but **not activated on any public network**
(`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

The turnkey, recommended way to benchmark it is
[`contrib/matmul-v4/run-full-benchmark.py`](../contrib/matmul-v4/run-full-benchmark.py):
a single verbose command that describes the full workload, labels each
component `[OPTIMIZED]` vs `[FALLBACK]` for your hardware, decides
resident-vs-streamed from actual free VRAM, and reports every phase
separately plus the combined total.

```sh
cmake --build build --target matmul-v4-rc-harness
contrib/matmul-v4/run-full-benchmark.py --shape production --json report.json

# fast sanity pass, no GPU or built binary needed
contrib/matmul-v4/run-full-benchmark.py --quick
```

For targeted measurements (relay-path verify-carrier timing, CUDA episode
probes, Stage-G CPU campaigns aggregated via `rc-gate.py`), see
`contrib/matmul-v4/measure-enc-rc-v46.sh`, which drives the same
`matmul-v4-rc-harness` binary.

The legacy `matmul-v4-report` tool and the v4.1/v4.2/v4.4-era
`btx-matmul-{cost,solve,metal}-bench`, `verify-backend.sh`, `lt-gate.py`, and
`k2b-gate.py` scripts (and the `--profile bmx4c` / `bmx4c-lt` paths they took)
have been removed — they measured superseded workloads and no longer reflect
the shipping PoW. Do not reference them in new documentation.

Going Further
--------------------

To monitor Bitcoin Core performance more in depth (like reindex or IBD): https://github.com/bitcoin-dev-tools/benchcoin
