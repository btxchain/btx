# MatMul Mining Memory Investigation Tracker

Last updated: 2026-03-10 20:00 (Asia/Tokyo)
Owner: Codex session (handoff-safe tracker)
Priority: P0 (production confidence / operator trust)

## Scope and constraints

- Problem report: repeated mining RPC loops (`generatetoaddress` / `generatetodescriptor`) show net RSS growth after each batch (example report: `+40 MB`, then `-20 MB`, net `+20 MB` after `25` blocks).
- Scope: diagnose and resolve true leak(s), if any, in mining path (MatMul CPU/Metal and surrounding node/wallet interactions).
- Hard constraint: **do not disable existing functionality** as a “fix”.
- Hard constraint: retain deterministic consensus behavior and compatibility.

## Repro harness (current canonical)

Use the same binary and loop structure for all comparisons:

```bash
BIN=/Users/admin/Documents/btxchain/btx-node/build-btx/bin
DATADIR=/tmp/btx-memtest-<tag>

# Start regtest node
$BIN/btxd -datadir="$DATADIR" -daemon -daemonwait

# Wallet path
$BIN/btx-cli -datadir="$DATADIR" createwallet memtest
ADDR=$($BIN/btx-cli -datadir="$DATADIR" -rpcwallet=memtest getnewaddress)

# 10 iterations x 25 blocks each
for i in $(seq 1 10); do
  RSS_BEFORE=$(ps -o rss= -p "$(pgrep -f "btxd -datadir=$DATADIR" | head -n1)")
  $BIN/btx-cli -datadir="$DATADIR" -rpcwallet=memtest generatetoaddress 25 "$ADDR" >/dev/null
  RSS_AFTER=$(ps -o rss= -p "$(pgrep -f "btxd -datadir=$DATADIR" | head -n1)")
  echo "$i $RSS_BEFORE $RSS_AFTER"
done
```

## Diagnostics captured so far

### A) Wallet-enabled baseline (regtest, no backend override)

- Start RSS: ~`148400 KB`
- End RSS after `250` blocks: ~`179856 KB`
- Net: ~`+31456 KB`

Observed pattern: first call large jump, later calls smaller but cumulative growth.

### B) Wallet disabled (`disablewallet=1`, `generatetodescriptor raw(51)`)

- Start RSS: ~`145520 KB`
- End RSS after `250` blocks: ~`167296 KB`
- Net: ~`+21776 KB`

Interpretation: wallet contributes part of growth, but not all.

### C) Explicit CPU backend (`BTX_MATMUL_BACKEND=cpu`, wallet enabled)

- Start RSS: ~`148112 KB`
- End RSS after `250` blocks: ~`170592 KB`
- Net: ~`+22480 KB`

Interpretation: Metal path adds overhead to the observed growth envelope, but CPU path still shows cumulative RSS rise.

### D) `vmmap` class breakdown (wallet disabled path)

From before/after `25`/`250` blocks:

- `MALLOC_LARGE` remained ~`128.0M` (flat)
- Growth primarily in `MALLOC_MEDIUM`/`MALLOC_SMALL` physical pages and allocator zone residency
- Physical footprint moved from ~`136.1M` to ~`151.2M` over `250` blocks

Interpretation: currently points more to allocator high-water/retained pages and live object growth, not a single obvious runaway heap bucket.

### E) Post-fix measurements (root-cause patch set)

Patch set validated:

- `src/pow.cpp`: replaced per-batch `std::async` thread churn with a bounded reusable prepare executor (`BTX_MATMUL_PREPARE_WORKERS` tunable).
- `src/metal/matmul_accel.mm`: changed `UploadBaseMatrices()` to reuse resident Metal base buffers when `n` is unchanged, updating contents in-place instead of reallocating every new block.

Measured with `contrib/devtools/matmul_memory_bench.sh` (10x25 blocks):

- Default backend, wallet mode:
  - Before patch: `148400 -> 179856 KB` (`+31456 KB`)
  - After patch (`/tmp/btx-membench-12000`): `148272 -> 168032 KB` (`+19760 KB`)
- Default backend, descriptor mode:
  - Before patch: `145520 -> 167296 KB` (`+21776 KB`)
  - After patch (`/tmp/btx-membench-14777`): `144464 -> 157568 KB` (`+13104 KB`)
- CPU backend control (`BTX_MATMUL_BACKEND=cpu`):
  - Descriptor (`/tmp/btx-membench-20871`): `145216 -> 150176 KB` (`+4960 KB`)
  - Wallet (`/tmp/btx-membench-28972`): `148256 -> 160032 KB` (`+11776 KB`)

Interpretation:

- Most of the prior Metal-specific RSS ratchet was due to repeated resident base-buffer reallocation, now removed.
- Remaining growth tracks chain/wallet live-state growth plus allocator retention, with materially reduced Metal overhead.
- Async prepare worker count stabilizes after warm-up (for example `48 -> 51` threads then flat), confirming no unbounded thread fan-out.

## Code changes currently in working tree (not merged)

- `src/metal/matmul_accel.mm`
  - Root-cause fix: resident base matrix buffers are reused in-place when dimension is unchanged (`n` constant), avoiding repeated per-block Metal buffer allocations.
- `src/pow.cpp`, `src/pow.h`
  - Root-cause fix: replaced `std::async` fan-out with reusable bounded executor for prepared digest inputs.
  - Added pipeline diagnostics counters:
    - `async_prepare_submissions`
    - `async_prepare_completions`
    - `async_prepare_worker_threads`
  - Kept async functionality enabled; no feature disablement.
- `src/matmul/matrix.{h,cpp}`
  - Added memory telemetry APIs (`ProbeMatrixMemoryStats`, `ResetMatrixMemoryStats`) and tracked live/peak bytes with ctor/dtor counters.
- `src/test/matmul_matrix_tests.cpp`
  - Added lifecycle/live-bytes invariant test for matrix telemetry.
- `src/test/pow_tests.cpp`
  - Extended async pipeline test to assert executor usage and completion accounting.
- `contrib/devtools/matmul_memory_bench.sh`
  - Added durable benchmark harness with CSV output, thread-count tracking, `vmmap` snapshots on macOS, and net RSS summary.
  - Added portable mined-hash extraction fallback (`jq` / `rg` / `grep`) so fixed-cycle invalidation works in minimal Linux containers.
  - Added `DAEMONIZE=0` mode so sanitizer runs can keep `btxd` in foreground and preserve sanitizer stderr diagnostics.

## Root-cause hypotheses (ordered)

1. **Allocator residency / fragmentation under repeated large MatMul temporaries**
   - `Matrix` and transcript intermediate allocations may not return pages quickly on macOS allocator.
2. **Metal driver/runtime residency (pipelines, command buffers, staging)**
   - One-time and recurring retained memory can appear as leak from RSS perspective.
3. **Wallet and chain live-state growth under generated-block workload**
   - Real live objects (wallet tx map, indexes, caches) may account for part of monotonic increase.
4. **Actual leak in MatMul fast path**
   - **Not supported by current evidence** (Linux ASAN/LSAN runs completed without leak reports).

## Additional diagnostics completed in this cycle

### F) Fixed-state cycle runs (height held constant)

`contrib/devtools/matmul_memory_bench.sh` executed with:

- `FIXED_CYCLE=1`
- `BLOCKS_PER_ITER=1`
- `DISABLE_WALLET=1`
- `MODE=descriptor`

Results:

- Default backend (macOS, Metal path available): `/tmp/btx-membench-28455`
  - Iterations: `120`
  - Height progression: always `0 -> 0`
  - RSS: `144864 -> 157008 KB` (`+12144 KB`)
  - Last 10 iteration sum of RSS deltas: `0 KB`
  - Observation: clear warm-up then plateau (no monotonic per-iteration climb).
- Explicit CPU backend: `/tmp/btx-membench-17310`
  - Iterations: `120`
  - Height progression: always `0 -> 0`
  - RSS: `144848 -> 148720 KB` (`+3872 KB`)
  - Last 10 iteration sum of RSS deltas: `16 KB`
  - Observation: warm-up with stable steady state.

Interpretation:

- The fixed-cycle mode isolates mining work from chain-growth effects.
- After warm-up, RSS deltas converge near zero for both default and CPU runs.

### G) Linux ASAN/LSAN mining-loop validation (foreground daemon)

Ran in Ubuntu 24.04 container against ASAN build (`build-linux-asan`):

- `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1`
- `DAEMONIZE=0` to avoid detached-daemon stderr loss
- `FIXED_CYCLE=1`, `BLOCKS_PER_ITER=1`, `DISABLE_WALLET=1`, `MODE=descriptor`, `BACKEND=cpu`

Evidence:

- Quiet validation log: `.btx-asan-run-foreground-quiet.log`
- Extracted rows: `5`
- Net RSS under ASAN allocator/quarantine: `+49016 KB` (expected instrumentation overhead)
- Leak/error signatures searched:
  - `ERROR: LeakSanitizer`
  - `ERROR: AddressSanitizer`
  - `SUMMARY: LeakSanitizer`
  - `SUMMARY: AddressSanitizer`
  - `detected memory leaks`
- Result: **no matches**

Interpretation:

- No sanitizer evidence of true heap leaks in the mining loop under tested path.
- Observed growth is consistent with allocator/runtime behavior plus warm-up/high-water effects.

### H) Per-call `SolveMatMul` memory telemetry

`BTX_MATMUL_MEM_DIAG=1` spot checks captured for both CPU and default backend.

Representative log fields (from `debug.log`):

- `matrix_live_before=0`
- `matrix_live_after=0`
- `matrix_live_delta=0`
- `matrix_constructed == matrix_destroyed` at call boundaries
- backend counters present (`backend_digest_requests_delta`, `backend_metal_fallbacks_delta`)

Interpretation:

- No per-call live-byte accumulation signal from matrix objects across solves.
- Instrumentation gives deterministic observability for future regressions.

## Required next diagnostics (no workaround shortcuts)

- [x] Add a dedicated reproducible benchmark script under `contrib/devtools` that outputs:
  - RSS series
  - `vmmap` snapshots (macOS) or `/proc/<pid>/smaps_rollup` (Linux)
  - backend stats from `ProbeMatMulBackendRuntimeStats()`
- [x] Add a **fixed-state cycle test**:
  - mine N blocks
  - invalidate/reconsider to return to same logical height
  - repeat cycles and compare RSS deltas
  - goal: separate chain-growth memory from leak memory
- [x] Linux ASAN/LSAN run for mining loop executable path (regtest)
  - collect definitive leak traces if present
- [x] Add temporary per-call allocation telemetry around `SolveMatMul` hotspots:
  - matrix dimensions
  - allocation sizes/counts via `ProbeMatrixMemoryStats()`
  - backend used
  - elapsed time + RSS deltas
- [x] Decide final fix only after root cause is proven.

## Final diagnostic conclusion (this issue)

- The major mining-path RSS ratchet was caused by:
  - repeated Metal resident base-buffer reallocations during base-matrix uploads, and
  - avoidable async preparation thread/task churn.
- Those are now fixed with:
  - resident buffer reuse in Metal upload path,
  - bounded reusable async prepare executor.
- Fixed-cycle runs show post-warm-up RSS stabilization.
- Linux ASAN/LSAN runs show no leak sanitizer errors for the tested mining loop.
- Therefore this issue is treated as **resolved for code-level leak/root-cause scope**.

## Acceptance criteria for closure

- Repro script shows bounded RSS over repeated fixed-state cycles (no monotonic growth beyond defined tolerance).
- No functionality removed or disabled by default as a “fix”.
- Tests added for regression protection and all relevant CI suites pass.
- PR includes diagnostic evidence and rationale.

## Session notes / decisions

- Rejected approach: silently forcing CPU backend by default on dev networks (considered too behavior-changing for this issue).
- Current posture: proceed to PR/merge/deploy with these fixes and keep `matmul_memory_bench.sh` as a standing regression harness.
