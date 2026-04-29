# BTX Production Readiness Verification

This runbook defines the executable verification checklist used before BTX
production deployment.

For shielded launch scope, this runbook must be read together with
`doc/btx-shielded-production-status-2026-03-20.md` and
`doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md`, plus the stable
security index in `doc/security/README.md`. A passing run of
the scripts below complements those shielded status docs; it does not replace
their current-main launch sign-off or benchmark tables.

## Verification Script

- `scripts/verify_btx_production_readiness.sh`
- `scripts/verify_btx_production_loop.sh` (retry wrapper with bounded rounds)
- `scripts/m10_validation_checklist.sh` (consolidated checklist generator)
- `test/util/verify_btx_production_readiness_timeout_guard_test.sh` (anti-hang timeout regression)

The script runs a checklist and writes a JSON artifact with per-check status,
duration, and log paths.

Anti-hang tuning:
- `--check-timeout-seconds <n>` on `scripts/verify_btx_production_readiness.sh`
- `--verify-timeout-seconds <n>` on `scripts/m10_validation_checklist.sh`

Reference analysis:
- `doc/btx-pow-scaling-analysis.md`

## Checklist

1. Required BTX binaries and validation scripts are present.
2. Lint checks pass.
3. Parallel BTX gate passes (`pow_tests`, `kawpow_tests`, functional BTX
   consensus test, M7 script unit tests, M5 swarm harness test).
4. Strict regtest M7 readiness checks pass.
5. Strict regtest M7 pool submission path passes and emits an artifact.
6. Benchmark/latency suite passes (`scripts/m9_btx_benchmark_suite.sh`).
7. PoW scaling simulation suite passes (long-horizon DGW/KAWPOW checks).
8. M7 scripts pass while running concurrently (port-isolation anti-hang check).
9. Swarm timeout guard catches and terminates hanging Codex worker processes.
10. Live strict regtest mining flow succeeds:
   - `getblocktemplate` exposes BTX nonce range.
   - `generateblock submit=false` + `submitblock` succeeds.
   - Accepted block becomes chain tip.
   - Header includes BTX `nonce64` and non-zero `mixhash`.
   - Additional blocks mine successfully after submission.

## Example

```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact .codex-swarm/production-readiness-report.json
```

To run a faster local test pass (skip parallel gate):

```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-smoke.json \
  --skip-parallel-gate \
  --skip-pow-scaling-suite
```

Continuous retry loop example:

```bash
scripts/verify_btx_production_loop.sh \
  --max-rounds 20 \
  --round-delay 30 \
  -- --build-dir build-btx --artifact /tmp/btx-production-readiness-latest.json
```

Consolidated checklist generation:

```bash
scripts/m10_validation_checklist.sh \
  --build-dir build-btx \
  --artifact-json /tmp/btx-validation-checklist.json \
  --checklist-md /tmp/btx-validation-checklist.md
```

---

## 2026-03-07 Runtime Hardening Update

The following production-path regressions were found and fixed during live
runtime validation on `codex/shielded-pool-overhaul`:

1. `missing-product-payload` enforcement was incorrectly executed in
   `ContextualCheckBlockHeader(const CBlockHeader&)`, where Freivalds payload
   data is unavailable.
2. `submitSolution()` on MatMul networks recomputed PoW but did not populate
   the required Freivalds product payload before `ProcessNewBlock()`.
3. Tests that mine full `CBlock` instances did not consistently attach
   Freivalds payloads.

Fixes applied:

- Move `missing-product-payload` enforcement to `ContextualCheckBlock(const CBlock&)`.
- Populate Freivalds payload in `node::interfaces::BlockTemplate::submitSolution()`.
- Add `MineHeaderForConsensus(CBlock&)` helper overload that auto-populates
  Freivalds payload for mined full blocks.
- Bind Freivalds challenge derivation to `(A, B, C, sigma)` in
  `src/matmul/freivalds.cpp` to reduce adaptive matrix-selection risk when
  deriving verifier vectors.
- Add explicit consensus regression test:
  `processnewblock_rejects_missing_required_freivalds_payload`
  (`src/test/matmul_mining_tests.cpp`).

Verification reruns after fixes:

- Unit tests: `ctest -j8 --output-on-failure` => `205/205 passed`
- Targeted mining tests:
  - `matmul_mining_tests`
  - `mining_crash_guard_tests`
  - `miner_tests`
- Host + container lifecycle matrix:
  - Artifact: `.btx-validation/m15-full-lifecycle-matrix.json`
  - Includes:
    - macOS single-node lifecycle pass
    - CentOS container single-node lifecycle pass
    - macOS <-> CentOS bridge sync/transfer pass
- Live runtime regtest validation:
  - Artifact: `/tmp/btx-live-regtest-runtime-validation.json`

## 2026-03-07 Extended Real-World Validation (Round 15)

Branch/context refresh:
- Verified latest analysis branch head:
  - `origin/claude/btx-privacy-analysis-8CN3q = 98462409dc`
- Verified working branch head:
  - `origin/codex/shielded-pool-overhaul = 918d988780`
- Confirmed no newer commits on `claude/btx-privacy-analysis-8CN3q` beyond
  its previously imported analysis docs.

Fresh runtime/e2e evidence:

1) Host + container + cross-OS bridge lifecycle:
```bash
timeout 1800 ./scripts/m15_full_lifecycle_matrix.sh
```
- result: `pass`
- artifact: `.btx-validation/m15-full-lifecycle-matrix.json`
- phases:
  - `mac_host_lifecycle`: pass
  - `centos_container_lifecycle`: pass
  - `mac_centos_bridge_lifecycle`: pass

2) Targeted mining/wallet/p2p functional checks:
```bash
test/functional/test_runner.py --combinedlogslen=0 \
  mining_matmul_basic.py \
  feature_btx_fast_mining_phase.py \
  feature_btx_dgw_convergence.py \
  wallet_multisig_descriptor_psbt.py \
  wallet_send.py \
  p2p_1p1c_network.py
```
- result: `pass`
- passed:
  - `feature_btx_dgw_convergence.py`
  - `mining_matmul_basic.py`
  - `feature_btx_fast_mining_phase.py`
  - `p2p_1p1c_network.py`
- expected policy/build skips:
  - `wallet_send.py --legacy-wallet` (no BDB build)
  - `wallet_send.py --descriptors` (BTX PQ descriptor policy)
  - `wallet_multisig_descriptor_psbt.py --descriptors` (BTX PQ descriptor policy)

3) Shielded lifecycle functional checks:
```bash
test/functional/test_runner.py --combinedlogslen=0 \
  wallet_shielded_send_flow.py \
  wallet_shielded_rpc_surface.py \
  wallet_shielded_cross_wallet.py \
  wallet_shielded_reorg_recovery.py \
  p2p_shielded_relay.py
```
- result: `pass`
- passed:
  - `wallet_shielded_rpc_surface.py`
  - `wallet_shielded_cross_wallet.py`
  - `wallet_shielded_reorg_recovery.py`
  - `p2p_shielded_relay.py`
  - `wallet_shielded_send_flow.py`

4) Extended live regtest runtime cycle:
```bash
timeout 2400 python3 scripts/live_regtest_realworld_validation.py --mine-blocks 2400
```
- result: `pass`
- artifact: `/tmp/btx-live-regtest-runtime-validation.json`

5) Mixed-load live stress (bounded wall-clock):
```bash
python3 scripts/live_regtest_load_stress.py \
  --rounds 600 \
  --max-runtime-seconds 1800
```
- result: `partial` (bounded stop as designed)
- artifact: `/tmp/btx-live-load-stress.json`
- termination: `max_runtime_seconds_exceeded`
- counters:
  - rounds completed: `237`
  - transparent tx: `123`
  - shield success: `62`
  - unshield success: `36`
  - multisig success: `23`
  - failures recorded: `0`

Operational cleanup:
- Removed stale debug daemons (`/tmp/btx-debug-submit*`) after validation to
  reduce background process pressure during subsequent runs.

Additional miner hardening applied after advisory cross-check:
- file: `src/node/miner.cpp`
- change:
  - replaced near-full checks in `addPackageTxs()` with overflow/underflow-safe
    arithmetic (`IsNearLimit(...)`) for block size/weight cutoffs.
  - avoids pathological unsigned arithmetic behavior in edge/fuzzed states while
    preserving normal template assembly semantics.
- verification:
  - rebuild target: `test_btx`
  - tests: `miner_tests`, `matmul_mining_tests`, `pow_tests` => pass
  - full suite rerun: `ctest --test-dir build-btx -j8 --output-on-failure`
    => `205/205` passed (`Total Test time (real) = 131.88 sec`)

## 2026-03-07 Extended Real-World Validation (Round 16)

Branch/doc sync:
- Re-fetched `origin/claude/btx-privacy-analysis-8CN3q` and rechecked head:
  - `98462409dc`
- Confirmed no additional commits on `claude/btx-privacy-analysis-8CN3q`
  that are newer than already merged development work on
  `codex/shielded-pool-overhaul`.

Real-world runtime execution:

1) Host + Linux container + bridge lifecycle:
```bash
timeout 1800 ./scripts/m15_full_lifecycle_matrix.sh
```
- result: `pass`
- artifact: `.btx-validation/m15-full-lifecycle-matrix.json`
- phases:
  - `mac_host_lifecycle`: pass
  - `centos_container_lifecycle`: pass
  - `mac_centos_bridge_lifecycle`: pass

2) Long mining + wallet + shielded + multisig runtime:
```bash
timeout 3600 python3 scripts/live_regtest_realworld_validation.py --mine-blocks 3000
```
- result: `pass`
- artifact: `/tmp/btx-live-regtest-runtime-validation.json`
- highlights:
  - final height: `3000`
  - best block:
    `681ff02fff30885676852f945e7bed08429fb8493204a5e6a7e325f2439a983f`
  - ASERT observation: `bits_change_count=1`
  - shield/unshield/multisig flow: pass with txids recorded in artifact

3) Mining + ASERT + multisig + P2P functional matrix:
```bash
test/functional/test_runner.py --combinedlogslen=0 \
  mining_matmul_basic.py \
  feature_btx_fast_mining_phase.py \
  feature_btx_dgw_convergence.py \
  feature_pq_multisig.py \
  rpc_pq_multisig.py \
  p2p_1p1c_network.py \
  mining_basic.py
```
- result: `pass`

4) Shielded runtime functional + stress matrix:
```bash
test/functional/test_runner.py --combinedlogslen=0 \
  wallet_shielded_send_flow.py \
  wallet_shielded_cross_wallet.py \
  wallet_shielded_reorg_recovery.py \
  wallet_shielded_mixed_stress.py \
  wallet_shielded_sendmany_stress.py \
  p2p_shielded_relay.py
```
- result: `pass`

5) Long mixed-load single-node stress (completed, not partial):
```bash
python3 scripts/live_regtest_load_stress.py \
  --artifact /tmp/btx-live-load-stress-round16.json \
  --rounds 260 \
  --max-runtime-seconds 2400 \
  --progress-every-rounds 20
```
- result: `completed=true` (`termination_reason=rounds_completed`)
- counters:
  - rounds: `260`
  - transparent sent: `133`
  - shield success/skipped: `65 / 10`
  - unshield success/skipped: `38 / 8`
  - multisig success/skipped: `27 / 0`
  - mined blocks: `553`
  - max mempool size: `3`
  - failures: `0`

Benchmark refresh:
```bash
build-btx/bin/bench_btx -filter='MatMulFreivalds.*|Shielded.*|RingCT.*|MatMul.*' -min-time=50
```
- representative outputs:
  - `MatMulFreivaldsN256R2`: `147,721.08 ns/round` (`6,769.51 round/s`)
  - `MatMulFreivaldsN512R2`: `569,822.87 ns/round` (`1,754.93 round/s`)
  - `MatMulSolveMainnetDimensions`: `3,125,109,167.00 ns/op`
  - `ShieldedTurnstileApply`: `4.35 ns/op`

External security/advisory cross-check (web):
- Sources reviewed:
  - `https://bitcoincore.org/en/security-advisories/`
  - `https://bitcoincore.org/en/releases/29.3/`
  - `https://bitcoincore.org/en/releases/30.2/`
  - `https://eprint.iacr.org/2021/545`
  - `https://arxiv.org/abs/2410.00927`
  - `https://github.com/monero-project/monero/issues/13186`
- Mapping notes:
  - miner unsigned arithmetic edge hardening from upstream 29.3 concerns is
    applied in this branch (`src/node/miner.cpp`, commit `24036e5a02`).
  - script execution cache keys include witness hash in
    `CheckInputScripts()` (`src/validation.cpp`), covering the witness-stripping
    cache-key class of DoS concern.
  - migration-specific functional regression `wallet_migration.py` could not run
    in this environment due missing previous-release fixtures (`skipped`).

## Post-Launch Maintenance Items

The following items are tracked for post-launch updates. They are not launch
blockers but should be addressed within 30 days of mainnet operation.

### DNS Seed Infrastructure Verification

Before launch, confirm that the following DNS seed domains are live and serving
peer addresses on their respective networks:

| Network | DNS Seeds |
|---|---|
| Mainnet | `node.btx.tools` |
| Testnet | `testnet.btxchain.org`, `testnet.btx.dev`, `testnet.btx.tools` |
| Testnet4 | `testnet4.btxchain.org`, `testnet4.btx.dev`, `testnet4.btx.tools` |

Verification: `dig +short <seed-domain>` should return IPv4/IPv6 addresses of
running BTX nodes. The `localhost` mainnet entry is an intentional fallback for
single-machine bootstrap and does not require DNS infrastructure.

Hardcoded fixed seeds (BIP155 format in `src/chainparamsseeds.h`) provide
additional fallback when DNS seeds are unreachable. These are loaded at startup
for mainnet, testnet, and testnet4.

### Binary Naming Status

BTX command aliases are live and should be used in operations docs:

- `btxd`
- `btx-cli`
- `btx-tx`
- `btx-wallet`
- `btx-util`

Some upstream-compatible names (`bitcoind`, `bitcoin-cli`, etc.) may still be
present in the build output for compatibility, but production BTX runbooks
should treat `btx*` commands as canonical.

### CUDA Mining Backend

The CUDA MatMul mining backend is production-ready on Linux with NVIDIA GPUs,
but it remains an opt-in build because CUDA is not a universal host
dependency. Enable it at configure time with
`-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON`.

The current supported backends are:

| Backend | Status | Platform |
|---|---|---|
| CPU | Production | All platforms |
| Apple Metal | Production | macOS (Apple Silicon) |
| MLX | Experimental | macOS (Apple Silicon) |
| CUDA | Production | Linux (NVIDIA GPUs, opt-in build) |

Build example:

```bash
cmake -B build \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
  -DCUDAToolkit_ROOT=/usr/local/cuda \
  -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
  -DBTX_CUDA_ARCHITECTURES=120
cmake --build build -j"$(nproc)"
```

The Linux CUDA backend work on this branch was developed and validated against
CUDA Toolkit `13.2`, the current CUDA Toolkit documentation line as of April
2026, installed at `/usr/local/cuda`.

Run `btxd` with CUDA selected:

```bash
BTX_MATMUL_BACKEND=cuda ./build/bin/btxd -server=1
```

### Checkpoint and Chain-State Updates

After mainnet accumulates sufficient depth, update in subsequent releases:

1. **Checkpoints**: Add post-genesis checkpoints at key difficulty transition
   heights (50,654, 50,725, 51,000+) once mainnet reaches those heights.
2. **`nMinimumChainWork`**: Update from bootstrap floor to actual accumulated
   chain work after the first difficulty period.
3. **`defaultAssumeValid`**: Update to a well-buried block hash to accelerate
   initial sync for new nodes.
4. **`chainTxData`**: Update `nTime`, `tx_count`, and `dTxRate` with real
   mainnet transaction statistics.
5. **`m_assumeutxo_data`**: Generate and publish UTXO snapshot metadata at
   stable heights to enable fast UTXO-snapshot-based sync.
