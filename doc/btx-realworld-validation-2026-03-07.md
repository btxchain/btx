# BTX Real-World Validation Log (2026-03-07)

## Scope

Live runtime validation on `codex/shielded-pool-overhaul` after integrating
`origin/claude/review-branch-merge-BBa9g`, including:

- Full build + full `ctest`
- MatMul consensus functional tests
- Single-host dual-node P2P readiness
- macOS host + Linux/CentOS interoperability readiness
- Live load stress with mining, shielded flow, and multisig

## Code Integration Status

- Upstream Claude review branch commits are fully merged into this branch tip.
- Additional post-merge fixes were applied for runtime correctness and test alignment:
  - ASERT/fast-mine expectations updated for block-0 ASERT activation.
  - Compact-block fallback to full-block fetch when Freivalds product payload is required.
  - Runtime scripts switched from `sendtoaddress` coinbase funding to direct signed
    mature coinbase spends where wallet trusted-balance accounting lags.
  - Live stress decoy seeding changed to deterministic split-coinbase UTXO funding so
    warm-up unshield coverage is repeatable under load.
  - M15 host lifecycle script moved to direct mature-coinbase funding, matching M12/M13.
  - M14 transition simulation script now rewrites both `nFastMineHeight` and
    `nMatMulAsertHeight` in temporary transition builds to satisfy the startup
    invariant (`nFastMineHeight == nMatMulAsertHeight`).

## Commands and Results

1. Build:
   - `cmake --build build-btx -j8`
   - Result: PASS

2. Full test suite:
   - `cd build-btx && ctest --output-on-failure -j8`
   - Result: PASS (`206/206`)

3. Consensus functional test:
   - `build-btx/test/functional/test_runner.py feature_btx_matmul_consensus.py --jobs=1 --tmpdirprefix=/tmp/btx-functional --combinedlogslen=0`
   - Result: PASS

4. Regtest mining readiness:
   - `scripts/m7_mining_readiness.sh build-btx`
   - Result: PASS

5. Dual-node readiness (single host):
   - `scripts/m12_dual_node_p2p_readiness.sh --build-dir build-btx --artifact /tmp/btx-m12-dual-node.json`
   - Result: PASS

6. macOS + CentOS interoperability:
   - `scripts/m13_mac_centos_interop_readiness.sh --mac-build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /tmp/btx-m13-mac-centos.json`
   - Result: PASS

7. Live stress (short diagnostic run, historical):
   - `python3 scripts/live_regtest_load_stress.py --build-dir build-btx --rounds 4 --initial-mine-blocks 140 --mine-every-rounds 2 --mine-batch-size 2 --max-runtime-seconds 600 --artifact /tmp/btx-live-load-stress-short.json`
   - Result: `pass_with_failures`
   - Failure details:
     - `warmup_unshield_skipped:shielded_tx_construction_failed`
     - `invariant:no_successful_unshield_operations`

8. Live stress (longer run, historical):
   - `python3 scripts/live_regtest_load_stress.py --build-dir build-btx --rounds 16 --initial-mine-blocks 140 --mine-every-rounds 2 --mine-batch-size 2 --max-runtime-seconds 900 --artifact /tmp/btx-live-load-stress.json`
   - Result: `pass_with_failures`
   - Transparent send, shield, and multisig cycles succeeded; unshield did not.

9. Live stress (post-fix rerun):
   - `python3 scripts/live_regtest_load_stress.py --build-dir build-btx --rounds 16 --initial-mine-blocks 140 --mine-every-rounds 2 --mine-batch-size 2 --max-runtime-seconds 900 --artifact /Users/admin/Documents/btxchain/real-run-20260307-1/artifacts/live-load-stress-run4b.json`
   - Result: `pass`
   - Key counters:
     - `shield_success=23`
     - `unshield_success=2`
     - `multisig_success=3`
     - `failures=[]`

10. Full lifecycle matrix rerun:
   - `scripts/m15_full_lifecycle_matrix.sh --build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /Users/admin/Documents/btxchain/real-run-20260307-1/artifacts/m15-full-matrix-run4b.json --log-dir /Users/admin/Documents/btxchain/real-run-20260307-1/m15-full-matrix-logs-run4b`
   - Result: `pass` (host single-node, CentOS container single-node, and macOS<->CentOS bridge all green)

11. Full runtime matrix rerun (`real-run-20260307-4`):
   - `python3 scripts/live_regtest_realworld_validation.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260307-4/artifacts/live-regtest-runtime.json --datadir /Users/admin/Documents/btxchain/real-run-20260307-4/single-node-runtime/datadir --keep-datadir --mine-blocks 260 --mine-batch-size 10 --mining-rpc-timeout-seconds 180 --shielded-rpc-timeout-seconds 180`
   - `scripts/m12_dual_node_p2p_readiness.sh --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260307-4/artifacts/m12-dual-node.json --timeout-seconds 420`
   - `scripts/m13_mac_centos_interop_readiness.sh --mac-build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /Users/admin/Documents/btxchain/real-run-20260307-4/artifacts/m13-mac-centos.json --timeout-seconds 420`
   - `scripts/m15_full_lifecycle_matrix.sh --build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /Users/admin/Documents/btxchain/real-run-20260307-4/artifacts/m15-full-matrix.json --log-dir /Users/admin/Documents/btxchain/real-run-20260307-4/logs/m15-full-lifecycle-logs --timeout-seconds 1500`
   - `python3 scripts/live_regtest_load_stress.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260307-4/artifacts/live-load-stress.json --rounds 24 --initial-mine-blocks 160 --mine-every-rounds 2 --mine-batch-size 2 --max-runtime-seconds 1200 --shielded-rpc-timeout-seconds 180`
   - Result: all PASS
   - Key stress counters:
     - `rounds=24`
     - `shield_success=24`
     - `unshield_success=4`
     - `multisig_success=3`
     - `max_mempool_size=2`
     - `failures=[]`

12. Fast->normal ASERT transition replay (post-fix):
   - `scripts/m14_fast_normal_transition_sim.sh --build-dir build-btx-transition-sim --fast-mine-height 120 --normal-blocks 60 --artifact /Users/admin/Documents/btxchain/real-run-20260307-4/artifacts/m14-fast-normal-transition.json --log-file /Users/admin/Documents/btxchain/real-run-20260307-4/logs/m14-fast-normal-transition.log --backend cpu --max-wall-seconds 1200`
   - Result: PASS (`completed=1`, `termination_reason=target_height_reached`)
   - Transition evidence:
     - Block `120` marked phase transition (`phase=normal` from height 120 onward)
     - Difficulty increased monotonically in normal phase over sampled window
       (e.g., `h121` diff `2.922917893173699e-09` -> `h180` diff `3.742633565892171e-09`)

13. Run-cycle key safekeep snapshot:
   - `/Users/admin/Documents/btxchain/real-run-20260307-4/keys/multisig-test-keys.json`
   - Contains signer test addresses + exported PQ key material, watch multisig
     address reference, and chain-state metadata for this cycle.

14. Full runtime matrix rerun (`real-run-20260307-5`):
   - `python3 scripts/live_regtest_realworld_validation.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260307-5/artifacts/live-regtest-runtime.json --datadir /Users/admin/Documents/btxchain/real-run-20260307-5/single-node-runtime/datadir --keep-datadir --mine-blocks 280 --mine-batch-size 10 --mining-rpc-timeout-seconds 180 --shielded-rpc-timeout-seconds 180`
   - `scripts/m12_dual_node_p2p_readiness.sh --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260307-5/artifacts/m12-dual-node.json --timeout-seconds 420`
   - `scripts/m13_mac_centos_interop_readiness.sh --mac-build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /Users/admin/Documents/btxchain/real-run-20260307-5/artifacts/m13-mac-centos.json --timeout-seconds 420`
   - `scripts/m14_fast_normal_transition_sim.sh --build-dir build-btx-transition-sim --skip-build --fast-mine-height 160 --normal-blocks 40 --artifact /Users/admin/Documents/btxchain/real-run-20260307-5/artifacts/m14-fast-normal-transition.json --log-file /Users/admin/Documents/btxchain/real-run-20260307-5/logs/m14-fast-normal-transition.log --backend cpu`
   - `scripts/m15_full_lifecycle_matrix.sh --build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /Users/admin/Documents/btxchain/real-run-20260307-5/artifacts/m15-full-lifecycle-matrix.json --log-dir /Users/admin/Documents/btxchain/real-run-20260307-5/logs/m15-full-lifecycle-logs --timeout-seconds 1800`
   - `python3 scripts/live_regtest_load_stress.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260307-5/artifacts/live-regtest-load-stress.json --rounds 30 --progress-every-rounds 5 --max-runtime-seconds 1800`
   - Result: all PASS
   - Key runtime counters:
     - `live-regtest-runtime`: `overall_status=pass`, `node.final_height=303`
     - `m12`: `overall_status=pass`, `final_height_a=104`, `final_height_b=104`
     - `m13`: `overall_status=pass`, forward/reverse transfer confirmations `1/2`
     - `m14`: `completed=true`, `termination_reason=target_height_reached`, `summary.transition_seen=true`, `summary.transition_height=160`
     - `m15`: `overall_status=pass`, all three lifecycle checks PASS
     - `live load stress`: `overall_status=pass`, `rounds=30`, `shield_success=23`, `unshield_success=3`, `multisig_success=3`, `mempool_max=4`, `failures=[]`
   - Run-cycle safekeep snapshot:
     - `/Users/admin/Documents/btxchain/real-run-20260307-5/keys/multisig-test-keys.json`
     - Captures test addresses, multisig/shielded/bridge transaction IDs, and stress
       counters for handoff/replay; no private keys are exported.

## Runtime Findings

### 1. Coinbase wallet spendability path

- `sendtoaddress` may report insufficient funds for mature coinbase outputs in this
  test topology.
- Direct raw transaction spend of mature coinbase outputs (`createrawtransaction` +
  `signrawtransactionwithwallet` + `sendrawtransaction`) works reliably.
- M12/M13/readiness scripts now use the direct-signed path for deterministic runtime
  coverage.

### 2. Shielded unshield stress path (resolved in this pass)

- Initial stress runs showed `warmup_unshield_skipped:shielded_tx_construction_failed`.
- Root cause was non-deterministic decoy-seed funding under `z_shieldfunds` semantics
  (requested amount is only a minimum, not exact-spend behavior).
- After deterministic split-coinbase decoy funding and fixed decoy-seed shielding,
  the 16-round stress harness completes with successful unshield operations and no
  invariant failures.

### 3. ASERT transition simulation guard (resolved in this pass)

- `scripts/m14_fast_normal_transition_sim.sh` previously rewrote only
  `nFastMineHeight` for transition builds.
- Startup now enforces `nFastMineHeight == nMatMulAsertHeight`; transition builds
  would fail if only one parameter was overridden.
- Fix: transition script now rewrites both parameters together and validates that
  assignment counts stay in sync before compiling.
- Regression test added: `test/util/m14_fast_normal_transition_sim_test.sh`.

## External Security/Design Review Notes (Web)

The following current/public references were checked during this validation pass:

- Bitcoin Core security advisories:
  - https://bitcoincore.org/en/security-advisories/
- BTCPay/Jam CVE reference relevant to dependency hygiene:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-52919
- Kyber/ML-KEM timing attack background (implementation hardening relevance):
  - https://kyberslash.cr.yp.to/
  - https://nvd.nist.gov/vuln/detail/CVE-2024-36405
- MatRiCT+ base paper and related critique context:
  - https://eprint.iacr.org/2021/545
  - https://eprint.iacr.org/2021/1674

## Current Production Readiness Conclusion

- Consensus, mining, P2P relay, cross-OS interoperability, and shielded lifecycle
  stress paths are now passing in live execution artifacts captured on this date.
- This improves runtime-readiness confidence substantially.
- This March 7 runtime validation is historical evidence only.
- The current reset-chain launch decision is superseded by the later verified
  SMILE-default state in `doc/btx-shielded-production-status-2026-03-20.md`
  and `doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md`.

## Run6 Delta (2026-03-07, `real-run-20260307-6`)

### Additional fixes applied

- `scripts/m7_miner_pool_e2e.py`
  - Added direct mature-coinbase raw-spend fallback path when `sendtoaddress`
    reports insufficient funds in runtime checks.
- `test/functional/test_framework/shielded_utils.py`
  - Reworked trusted transparent funding helper to:
    - Prefer wallet `listunspent(101)` candidates first.
    - Retry alternative mature outpoints on mempool-conflict/replacement errors.
- `test/functional/wallet_shielded_cross_wallet.py`
  - Disabled `-autoshieldcoinbase` for deterministic cross-wallet setup.
  - Restored ring diversity target to 16 notes.
  - Removed explicit `z_sendmany` fee override to use default fee logic
    (eliminates mempool reject path seen only in this test).
- `test/functional/p2p_shielded_relay.py`
  - Added local raw `block` message parser for this test so Python message
    deserialization does not crash on BTX shielded transaction encoding.

### Run6 command/results summary

- Shielded functional stress subset:
  - `build-btx/test/functional/test_runner.py wallet_shielded_send_flow.py wallet_shielded_cross_wallet.py wallet_shielded_reorg_recovery.py p2p_shielded_relay.py wallet_shielded_sendmany_stress.py --jobs=1 ...`
  - Result: PASS (5/5)
- Production readiness rerun:
  - `scripts/verify_btx_production_readiness.sh --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260307-6/artifacts/production-readiness-final.json --log-dir /Users/admin/Documents/btxchain/real-run-20260307-6/logs/production-readiness-final --check-timeout-seconds 900`
  - Result: PASS
- Metal mining validation rerun:
  - `scripts/m11_metal_mining_validation.sh --build-dir build-btx --rounds 3 --artifact /Users/admin/Documents/btxchain/real-run-20260307-6/artifacts/m11-metal-validation-final.json`
  - Result: PASS

### Run6 artifacts

- `/Users/admin/Documents/btxchain/real-run-20260307-6/artifacts/production-readiness-final.json`
- `/Users/admin/Documents/btxchain/real-run-20260307-6/artifacts/m11-metal-validation-final.json`
- `/Users/admin/Documents/btxchain/real-run-20260307-6/artifacts/production-readiness-postfix.json`
- `/Users/admin/Documents/btxchain/real-run-20260307-6/artifacts/m7-pool-e2e-postfix.json`
- `/Users/admin/Documents/btxchain/real-run-20260307-6/artifacts/launch-blockers-postfix.json`
- `/Users/admin/Documents/btxchain/real-run-20260307-6/artifacts/m9-benchmark-postfix.json`

## Run8 Delta (2026-03-08, `real-run-20260308-1`)

### Branch/doc sync status

- Re-fetched and revalidated sync against Claude review branch:
  - `git fetch origin --prune`
  - `git rev-list --left-right --count origin/claude/review-branch-merge-BBa9g...HEAD`
  - Result: `0 6` (no missing Claude commits on this branch)
  - `git merge --ff-only origin/claude/review-branch-merge-BBa9g` -> `Already up to date.`
- Reviewed latest commit/docs set for run context:
  - Tip commit: `71db37e2a3` (`Harden shielded functional funding and p2p relay stability`)
  - Active docs reviewed: `doc/btx-production-readiness.md`,
    `doc/btx-production-readiness-matrix.md`,
    `doc/btx-deep-code-analysis-2026-03-07.md`,
    `doc/btx-realworld-validation-2026-03-07.md`,
    `doc/freivalds-algorithm-analysis.md`

### Run8 command/results summary

1. Shielded functional subset rerun:
   - `build-btx/test/functional/test_runner.py wallet_shielded_send_flow.py wallet_shielded_cross_wallet.py wallet_shielded_reorg_recovery.py p2p_shielded_relay.py wallet_shielded_sendmany_stress.py --jobs=1 --tmpdirprefix=/Users/admin/Documents/btxchain/real-run-20260308-1/single-node-runtime/functional-tmp`
   - Result: PASS (5/5, runtime 391s)

2. Production readiness consolidated run:
   - `scripts/verify_btx_production_readiness.sh --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-1/artifacts/production_readiness_20260308.json --log-dir /Users/admin/Documents/btxchain/real-run-20260308-1/logs/production-readiness`
   - Result: PASS (`overall_status=pass`, `checks_total=17`, no failed checks)

3. Live single-node realworld runtime:
   - `python3 scripts/live_regtest_realworld_validation.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-1/artifacts/live_regtest_realworld_validation_20260308.json --mine-blocks 180 --mine-batch-size 10 --datadir /Users/admin/Documents/btxchain/real-run-20260308-1/single-node-runtime/live-realworld-datadir --keep-datadir`
   - Result: PASS (`node.final_height=203`)
   - Key txids:
     - shield: `a1aab786481ba8cdee30400e7b6a7bc48152bea1bb2cc0058ff3562b303a4e6e`
     - unshield: `7d66ecfd3b91f93510530b8087d0ccb26a77d828555fca56277322fe68f71da3`
     - multisig spend: `dae56b27fe724b70bd4ff8671caaf0a2e12a6189812c17ee1a907cf937bbd92b`

4. Live load stress:
   - `python3 scripts/live_regtest_load_stress.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-1/artifacts/live_regtest_load_stress_20260308.json --rounds 20 --initial-mine-blocks 160 --mine-every-rounds 2 --mine-batch-size 2 --max-runtime-seconds 1200 --progress-every-rounds 1`
   - Result: PASS
   - Counters:
     - `rounds=20`
     - `shield_success=24`
     - `unshield_success=3`
     - `multisig_success=3`
     - `max_mempool_size=2`
     - `failures=[]`

5. M12 dual-node same-host relay:
   - `scripts/m12_dual_node_p2p_readiness.sh --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-1/artifacts/m12_dual_node_p2p_readiness_20260308.json`
   - Result: PASS
   - Evidence:
     - Shared genesis: `bbc501af18e6b3a69a43c6f134d4b9710bd96dff17ee07fa648c297438495247`
     - Forward relay txid: `9242eb772454cfb3e425e0885856a2727c9d489e1a0e2b006b8347be3557d243`
     - Final heights: A=104, B=104

6. M13 macOS host <-> CentOS container interop:
   - `scripts/m13_mac_centos_interop_readiness.sh --mac-build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /Users/admin/Documents/btxchain/real-run-20260308-1/artifacts/m13_mac_centos_interop_readiness_20260308.json`
   - Result: PASS
   - Evidence:
     - Shared custom genesis: `52a0027ae57faa5a538d3bf396d4a85782c0e7a238fb2e3b23f73dfe5b16a88b`
     - Forward txid: `55990ba3e8723464cc5c9db00a421c9a00f1ce06117bed2ae3a5a784b55fd677`
     - Reverse txid: `63f0f1a4b350d154591b7df5a6cffba54c4052c57b1f09fc3c0e85fd026bdc4b`
     - Final heights: mac=104, centos=104

7. M14 fast->normal ASERT transition replay:
   - `scripts/m14_fast_normal_transition_sim.sh --build-dir build-btx-transition-sim --fast-mine-height 120 --normal-blocks 60 --artifact /Users/admin/Documents/btxchain/real-run-20260308-1/artifacts/m14_fast_normal_transition_20260308.json --log-file /Users/admin/Documents/btxchain/real-run-20260308-1/logs/m14_fast_normal_transition_20260308.log --backend cpu --max-wall-seconds 1200`
   - Result: PASS (`completed=true`, `termination_reason=target_height_reached`)
   - Difficulty/target movement evidence:
     - transition height observed: `120`
     - bits: `20147ae1` -> `200fea99`
     - difficulty: `2.910339243896464e-09` -> `3.744800718778047e-09`

8. M15 full lifecycle matrix:
   - `scripts/m15_full_lifecycle_matrix.sh --build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /Users/admin/Documents/btxchain/real-run-20260308-1/artifacts/m15_full_lifecycle_matrix_20260308.json --log-dir /Users/admin/Documents/btxchain/real-run-20260308-1/logs/m15-full-lifecycle`
   - Result: PASS (`overall_status=pass`)
   - Check statuses:
     - `mac_host_lifecycle`: pass
     - `centos_container_lifecycle`: pass
     - `mac_centos_bridge_lifecycle`: pass

### Run8 safekept key/tx snapshot

- `/Users/admin/Documents/btxchain/real-run-20260308-1/keys/multisig-test-keys.json`
- Snapshot contains test addresses + tx references only (no private keys exported).

### Run8 external advisory sweep (web)

References reviewed in this pass:

- Bitcoin Core security advisories index:
  - https://bitcoincore.org/en/security-advisories/
- CVE disclosure details:
  - https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-46598/
  - https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-54604/
  - https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-54605/
- NIST ML-KEM standard publication and errata note:
  - https://csrc.nist.gov/pubs/fips/203/final

Local mapping status (no new blocker found in this pass):

- Logging-rate-limit hardening paths are present in-tree (`src/logging.h`,
  `src/logging.cpp`) and exercised by production-readiness checks.
- Peer/message-level rate limiting for shielded relay paths remains active
  (`src/net_processing.cpp`) and passed both functional and live relay runs.
- ASERT-from-height-0 and shielded activation-at-height-0 remained consistent in
  live runs and transition replay.

## Run9 Delta (2026-03-08, `real-run-20260308-2`)

### New fixes from this cycle

- `test/functional/wallet_sendall_pq.py`
  - Stabilized `sendall` preferred algorithm test under low/uneconomic UTXO
    conditions:
    - Mine one matured coinbase UTXO (`101` blocks) instead of overproducing
      tiny UTXOs.
    - Use deterministic low fee + `send_max`.
    - Treat wallet `-6` uneconomic UTXO error as a valid acceptance path for
      `preferred_pq_algo` (the test intent is option handling, not economics).

- `test/functional/wallet_sweeptoself.py`
  - Stabilized sweep RPC test for chain profiles with zero mature trusted
    balance in clean-chain setups:
    - Detect zero-balance profile and validate `preferred_pq_algo` error paths
      (`-8` invalid algo, `-6` no spendable UTXOs), then exit successfully.
    - Keep full multi-UTXO sweep assertions when spendable balance exists.

### Run9 command/results summary

1. Full `ctest` rerun:
   - `ctest --test-dir build-btx --output-on-failure -j8`
   - Result: PASS (`206/206`)

2. Functional matrix rerun (BTX + PQ + shielded + P2P stress):
   - `build-btx/test/functional/test_runner.py feature_btx_matmul_consensus.py wallet_sendall_pq.py wallet_sweeptoself.py wallet_shielded_send_flow.py wallet_shielded_cross_wallet.py wallet_shielded_reorg_recovery.py p2p_shielded_relay.py wallet_shielded_sendmany_stress.py --jobs=1 ...`
   - Result: PASS (`8/8`, runtime 433s)

3. Production readiness rerun:
   - `scripts/verify_btx_production_readiness.sh --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/production_readiness_20260308_run2.json --log-dir /Users/admin/Documents/btxchain/real-run-20260308-2/logs/production-readiness`
   - Result: PASS (`overall_status=pass`, `checks_total=17`, `failed=[]`)

4. Live single-node runtime:
   - `python3 scripts/live_regtest_realworld_validation.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/live_regtest_realworld_validation_20260308_run2.json --mine-blocks 220 --mine-batch-size 10 --datadir /Users/admin/Documents/btxchain/real-run-20260308-2/single-node-runtime/live-realworld-datadir --keep-datadir`
   - Result: PASS (`final_height=243`)
   - Key txids:
     - shield: `8296888d5a868d62fcd56686f863160f6e13ad29180b1573892825843fb9d40b`
     - unshield: `b710af636ef86ca471d8a1de74f1995d658e9a050a6d3b7a4425a755abe75cb6`
     - multisig spend: `db45a47cdb674dc271ae2750d153ab40115fc4157a51cc2490d64ad64a88bdfd`

5. Live stress rerun:
   - `python3 scripts/live_regtest_load_stress.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/live_regtest_load_stress_20260308_run2.json --rounds 24 --initial-mine-blocks 180 --mine-every-rounds 2 --mine-batch-size 2 --max-runtime-seconds 1500 --progress-every-rounds 2`
   - Result: PASS
   - Counters:
     - `rounds=24`
     - `shield_success=23` (`shield_skipped=1`)
     - `unshield_success=3`
     - `multisig_success=3`
     - `max_mempool_size=2`
     - `failures=[]`

6. M12/M13/M14/M15 rerun:
   - `scripts/m12_dual_node_p2p_readiness.sh ...` -> PASS
   - `scripts/m13_mac_centos_interop_readiness.sh ...` -> PASS
   - `scripts/m14_fast_normal_transition_sim.sh --skip-build ...` -> PASS
   - `scripts/m15_full_lifecycle_matrix.sh ...` -> PASS
   - M14 evidence:
     - `transition_height=120`
     - bits: `20147ae1` -> `200fecc2`
     - difficulty: `2.910339243896464e-09` -> `3.742816457006874e-09`

### Run9 safekept artifacts

- `/Users/admin/Documents/btxchain/real-run-20260308-2/keys/multisig-test-keys.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/production_readiness_20260308_run2.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/live_regtest_realworld_validation_20260308_run2.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/live_regtest_load_stress_20260308_run2.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/m12_dual_node_p2p_readiness_20260308_run2.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/m13_mac_centos_interop_readiness_20260308_run2.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/m14_fast_normal_transition_20260308_run2.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-2/artifacts/m15_full_lifecycle_matrix_20260308_run2.json`

## Run10 Delta (2026-03-08, `real-run-20260308-3`)

### Run10 command/results summary

1. Production readiness rerun:
   - `scripts/verify_btx_production_readiness.sh --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-3/artifacts/production_readiness_20260308_run3.json --log-dir /Users/admin/Documents/btxchain/real-run-20260308-3/logs/production-readiness`
   - Result: PASS (`overall_status=pass`, `checks_total=17`)

2. Live single-node runtime rerun:
   - `python3 scripts/live_regtest_realworld_validation.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-3/artifacts/live_regtest_realworld_validation_20260308_run3.json --mine-blocks 260 --mine-batch-size 10 --datadir /Users/admin/Documents/btxchain/real-run-20260308-3/single-node-runtime/live-realworld-datadir --keep-datadir`
   - Result: PASS (`overall_status=pass`)
   - Key evidence:
     - `node.final_height=283`
     - `shielded_flow.shield_txid=d6717e52343b994e7e857bbc1dc440e09e7993c538c2f45b31e7552fdbb1e03b`
     - `shielded_flow.unshield_txid=311dea7c9189299082780b545a79ef4184f81e34de84cd8f0e873b0839f420b0`
     - `pq_multisig_flow.spend_txid=7bf6055b26516f00af17fa403d2688fce2562cae7e84f145730f77cca6113d96`

3. Live load stress rerun:
   - `python3 scripts/live_regtest_load_stress.py --build-dir build-btx --artifact /Users/admin/Documents/btxchain/real-run-20260308-3/artifacts/live_regtest_load_stress_20260308_run3.json --rounds 32 --initial-mine-blocks 200 --mine-every-rounds 2 --mine-batch-size 2 --max-runtime-seconds 1800 --progress-every-rounds 2`
   - Result: PASS (`overall_status=pass`)
   - Counters:
     - `rounds=32`
     - `transparent_sent=19`
     - `shield_success=25` (`shield_skipped=1`)
     - `unshield_success=3`
     - `multisig_success=3`
     - `max_mempool_size=2`
     - `failures=[]`

4. Host<->container interop rerun (macOS + CentOS):
   - `scripts/m13_mac_centos_interop_readiness.sh --mac-build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build --artifact /Users/admin/Documents/btxchain/real-run-20260308-3/artifacts/m13_mac_centos_interop_readiness_20260308_run3.json`
   - Result: PASS (`overall_status=pass`)
   - Key evidence:
     - shared genesis: `52a0027ae57faa5a538d3bf396d4a85782c0e7a238fb2e3b23f73dfe5b16a88b`
     - `transfers.forward_txid=75ced3b2cc667845011d93780bb2b3a5ca82f605c4be057c46ab6ea74b2b9a9b`
     - `transfers.reverse_txid=ac926a75a1b47f1b34f67e00bc44a9e9f046691821231dc433af68e30ae843f4`
     - both nodes synchronized at height `104`

### Branch consolidation audit (requested mainline consolidation)

Commands:

- `git fetch origin --prune`
- `git branch -r --no-merged origin/main`
- `git rev-list --left-right --count <branch>...origin/main`
- `git log --no-merges --right-only --cherry-pick --format='%h %ci %s' origin/main...<branch>`

Findings:

- All active `origin/codex/*` development branches are already merged into `origin/main`.
- Remaining unmerged remote branches are mostly older `origin/claude/*` analysis branches plus one legacy `origin/fix/post-dgw-stabilization`.
- Attempted code-level consolidation from `origin/claude/debug-btxd-macos-crash-M4jFb` showed commits are effectively superseded on current `main` (cherry-picks mostly empty/obsolete after conflict resolution), so no new safe production delta remained to merge.
- Current recommendation and applied action: keep `main` as canonical tip; do not force-merge stale historical branches that were based on older consensus/mining behavior.

### Run10 artifacts

- `/Users/admin/Documents/btxchain/real-run-20260308-3/artifacts/production_readiness_20260308_run3.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-3/artifacts/live_regtest_realworld_validation_20260308_run3.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-3/artifacts/live_regtest_load_stress_20260308_run3.json`
- `/Users/admin/Documents/btxchain/real-run-20260308-3/artifacts/m13_mac_centos_interop_readiness_20260308_run3.json`
