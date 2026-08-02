# M4 Max Profile 1 loaded ExactReplay evidence

This directory records the local-only Profile 1 launch-candidate campaign on a
Mac Studio with an Apple M4 Max, 32 GPU cores, and 36 GB unified memory.
Consensus activation remained disabled and nothing was published.

This is the corrected Metal evidence for the proposed MatMul v4.7 Epoch A,
where Profile 1 ExactReplay is consensus authority and succinct proofs are
optional shadow data only. It does not activate Epoch A, qualify CUDA, or clear
the remaining admission/fault-retry/testnet/IBD gates. Profile 2 remains a
later proof-authoritative workload. See
[`../../btx-matmul-v4.7-transition-roadmap.md`](../../btx-matmul-v4.7-transition-roadmap.md).

## Corrected loaded p99 campaign

- Source revision: `718775a8302c`
- Profile: 1
- Header dimension: 4,096
- Episode: four rounds, 16 FFN layers, `b_seq=16,384`,
  `T_leaf=1,024`
- Backend: exact Metal 4 MPP INT8 tensor operations
- Report: `profile1-metal-loaded-100.json`

```sh
BTX_MATMUL_V4_BACKEND=metal \
  build-metal/bin/matmul-v4-rc-harness \
  --base-production \
  --episodes 100 \
  --backend metal \
  --source-revision 718775a8302c449604d4d6c4f0d447c9e716e5a2 \
  --out doc/evidence/m4-max-profile1-loaded-2026-07-30/profile1-metal-loaded-100.json
```

The process ran 100 distinct headers continuously with no cooldown:

- Mean: **28.171553715 seconds**
- Nearest-rank p50: **28.168290875 seconds**
- Nearest-rank p95: **28.202504625 seconds**
- Nearest-rank p99: **28.210448250 seconds**
- Maximum: **28.362590458 seconds**
- Coefficient of variation: **0.0980%**
- Worst adjacent two-episode drain: **56.495303916 seconds**
- Maximum queue wait at 90-second arrivals: **0 seconds**
- Ending queued work at 90-second arrivals: **0 seconds**
- Peak RSS: **6,972,688 KiB**

All 100 digests were distinct; 51 were below the `0x207fffff` target.
The report records `full_metal_pipeline=true`, 13,600 device calls, 400
resident FFN-chain calls, and 400 device Merkle rounds. The exact expected
14,114,980,521,574,400 MACs all ran on Metal. CPU calls and fallbacks were
zero.

## Actual consensus worker tests

The off-CI tests use production Profile 1, `matmul_dim=4096`, the real
`CheckMatMulProofOfWork_RC` predicate, the target check, single-flight/verdict
memo, one-device scheduler, and worker completion path:

```sh
BTX_MATMUL_V4_BACKEND=metal \
BTX_RUN_PROFILE1_METAL_SCHEDULER_TESTS=1 \
  build-metal/bin/test_btx \
  --run_test=matmul_verify_worker_tests \
  --log_level=message \
  --report_level=detailed
```

Results:

- Two valid winners were queued with zero arrival gap. The first completed in
  **28.304562958 seconds**, the second required **28.102502667 seconds**, and
  both drained in **56.407940500 seconds** with ending queue depth zero.
- A cryptographically ticketed invalid competing candidate was already
  replaying when two more ticketed invalid candidates and an authenticated-tip
  winner arrived. The in-flight invalid replay was preempted in
  **1.528641959 seconds**; the honest verdict completed
  **30.207028375 seconds** after the flood began. No invalid completion or peer
  punishment fired, and the remaining two invalid jobs were canceled after
  the honest verdict.
- In the three-branch reorg, one correctly claimed stale branch was already
  replaying and another was queued. `CancelIf` canceled both stale jobs. The
  running replay exited **1.566106083 seconds** after cancellation, and the
  distinct valid canonical winner completed **29.708123583 seconds** after the
  reorg.
- The complete worker suite passed all **360 assertions**.

The deterministic device-fault test supplies an explicitly faulty exact-GEMM
backend to the first replay pass. Two repeated runs recovered the honest
header through the unchanged portable oracle with identical telemetry; a
genuinely false claim was rejected after the retry. The test uses no
environment switch or mutable process-global fault flag and passed all
**31 assertions**.

The eight-header file `profile1-metal-consensus-goldens-8.json` preserves the
dimension-bound corpus used to choose three under-target golden winners for
these tests.

## Harness defect found and fixed

The first 100-run corpus left `CBlockHeader::matmul_dim` at its zero default.
That corpus measured the correct production workload and produced nearly
identical timings, but its digests cannot be claimed by a consensus-valid
4,096-dimension header. Feeding one of those claims to the real predicate
correctly caused a digest mismatch and invoked the portable device-mismatch
retry.

The launch-candidate source at revision `718775a8302c` binds
`matmul_dim=4096` and records a machine-readable `header_matmul_dim` field.
The diagnostic corpus is retained as
`profile1-metal-loaded-100-pre-dimension-bind.json`; it is not launch
evidence. Its p99 was 28.186119792 seconds versus 28.210448250 seconds for the
corrected corpus, confirming that the defect affected claim binding rather
than the measured workload cost.

## Conclusion

On this host, Profile 1 passes the loaded p99, immediate back-to-back,
three-branch reorg/cancellation, ticketed-invalid starvation, and deterministic
device-mismatch recovery gates for 90-second blocks. This does not by itself
authorize activation: cross-machine golden parity, repetition on the final
CUDA path, multi-day testnet load, and the IBD trust-window disclosures remain
separate gates.

## Provenance status

`profile1-metal-loaded-100-pre-dimension-bind.json` declares `source_revision
ca6e351f8d`, which does not resolve to a commit in this repository. It is the
superseded pre-dimension-bind artifact and is retained for comparison only; it
is not admissible as production-golden evidence.
`contrib/matmul-v4/verify-evidence-provenance.py` fails on it until it is
regenerated under the current provenance rules.
