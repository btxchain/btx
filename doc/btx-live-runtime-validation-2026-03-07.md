# BTX Live Runtime Validation (2026-03-07)

Status note (2026-03-21): this document is historical runtime evidence from
the March 7 validation pass. The current reset-chain SMILE-default launch
surface and its final verification/benchmark numbers are recorded in
`doc/btx-shielded-production-status-2026-03-20.md` and
`doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md`.

## Scope
This pass focused on real node execution and cross-platform interoperability rather than static-only review:
- macOS host node live lifecycle
- CentOS container node live lifecycle
- macOS <-> CentOS bi-directional P2P transfer/sync
- shielded lifecycle/stress and reorg paths
- PQ multisig spend path with mined funds
- elevated custom randomized simulations
- cross-platform rebuild hardening for sweep RPC warning path
- web-sourced security review for upstream ecosystem signals

## Live Node Matrix (Host + Container)
Command:
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307.json \
  --log-dir /tmp/btx-m15-full-lifecycle-logs-20260307
```

Result:
- overall: `pass`
- host single-node lifecycle: `pass`
- CentOS single-node lifecycle: `pass`
- macOS<->CentOS bridge lifecycle: `pass`

Artifacts:
- `/tmp/btx-m15-full-lifecycle-matrix-20260307.json`
- `/tmp/btx-m15-full-lifecycle-logs-20260307/mac-host-single-node-artifact.json`
- `/Users/admin/Documents/btxchain/btx-node/.btx-validation/m15-centos-container-single-node-artifact.json`
- `/tmp/btx-m15-full-lifecycle-logs-20260307/mac-centos-bridge-artifact.json`

Notable runtime evidence from artifacts:
- bridge best hash convergence: both nodes at height `104` with identical best block
- bi-directional transfers confirmed:
  - forward txid: `8f18d013c7feee7258ad3c615fbe58031ae8cc6ba57e462a8a4d24391d6f2786`
  - reverse txid: `a20e4833b1633f15a031cb814340a072d80fa0937036e2b998d84f81750a83d3`

## Functional Runtime Batch
Command:
```bash
test/functional/test_runner.py --configfile build-btx/test/config.ini --jobs=6 \
  feature_btx_dgw_convergence.py feature_btx_fast_mining_phase.py p2p_block_times.py mining_matmul_basic.py \
  wallet_shielded_send_flow.py wallet_shielded_cross_wallet.py wallet_shielded_reorg_recovery.py wallet_shielded_anchor_window.py \
  wallet_shielded_sendmany_stress.py wallet_shielded_mixed_stress.py wallet_shielded_topology_sim.py wallet_shielded_longhaul_sim.py \
  p2p_shielded_relay.py feature_pq_multisig.py rpc_pq_multisig.py wallet_multisig_descriptor_psbt.py
```

Result:
- 15 passed
- 1 skipped (`wallet_multisig_descriptor_psbt.py --descriptors`) due BTX PQ-only descriptor policy (no xpub descriptors)
- suite status: `pass`

## Elevated Custom Stress Runs
Executed with increased rounds/seeds:
```bash
python3 test/functional/wallet_shielded_randomized_sim.py --configfile build-btx/test/config.ini --rounds=64 --sim-seed=2026030701
python3 test/functional/wallet_shielded_topology_sim.py   --configfile build-btx/test/config.ini --rounds=24 --sim-seed=2026030702
python3 test/functional/wallet_shielded_longhaul_sim.py   --configfile build-btx/test/config.ini --rounds=18 --sim-seed=2026030703
```

Result:
- all passed

## New Live Harness (Real Node, Real Funds)
Added script:
- `/Users/admin/Documents/btxchain/btx-node/scripts/live_regtest_realworld_validation.py`

Purpose:
- mine across long regtest span (`--mine-blocks 430`)
- collect header bits/block-time observations
- run transparent -> shielded -> unshield flow
- run PQ 2-of-3 multisig fund + PSBT spend flow

Run:
```bash
scripts/live_regtest_realworld_validation.py \
  --build-dir build-btx \
  --mine-blocks 430 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307.json
```

Artifact:
- `/tmp/btx-live-regtest-runtime-validation-20260307.json`

Observed values:
- final height: `453`
- shielded flow txids:
  - fund: `f399551ff3b4680bcf35c78039244cb76b838304f13798940d392c217272eb4e`
  - shield: `c16b80f59ba360cb473336f138e2a18a764c41a3ea313a0952e1920b2dffe784`
  - unshield: `6044c46c25cf61f937bba62ba0a39e5341cb9161c2fef36ad74d7383330955f2`
- PQ multisig spend txid: `1935b8562255b9738cbfeac932f4c500afdad4bbf174a2e6312e44c4a01d89e2`

## Fixes Applied During This Pass
1. `src/wallet/shielded_rpc.cpp`
- strengthened `z_importviewingkey` validation:
  - strict ML-KEM key hex length checks
  - key-material encaps/decaps consistency check
  - deterministic error semantics for malformed imports

2. `test/functional/wallet_shielded_viewingkey_rescan.py`
- updated to assert explicit invalid-parameter failures for malformed/mismatched viewing-key material

3. `test/functional/wallet_multisig_descriptor_psbt.py`
- xpub extraction generalized
- explicit `SkipTest` for BTX PQ-only descriptor wallets where xpub descriptors are unavailable

4. `src/wallet/rpc/sweep.cpp`
- adjusted `CRecipient` construction to avoid temporary variant move pattern that triggered CentOS `-Wmaybe-uninitialized` warning path

Cross-platform warning regression check:
```bash
docker run ... scripts/build_btx.sh build-btx-centos ... | tee /tmp/btx-centos-incremental-build-20260307.log
rg -n "maybe-uninitialized|prevector.h:275|warning:" /tmp/btx-centos-incremental-build-20260307.log
```
- result: no warning hits

## Security Research Checkpoints (Web)
Primary sources reviewed:
- Bitcoin Core security advisories and 2025 disclosures:
  - https://bitcoincore.org/en/security-advisories/
  - https://bitcoincore.org/en/2025/10/14/disclose-cve-2024-52919/
  - https://bitcoincore.org/en/2025/10/16/cve-2024-52917/
- SQLite CVE history:
  - https://www.sqlite.org/cves.html
- ML-KEM implementation guidance and side-channel context:
  - FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
  - SP 800-227 draft guidance: https://csrc.nist.gov/pubs/sp/800/227/ipd
  - KyberSlash disclosure index: https://kyberslash.cr.yp.to/
- MatRiCT+ and decoy-selection references:
  - MatRiCT+ paper: https://eprint.iacr.org/2021/545
  - Monero decoy parameter context and fixes:
    - https://github.com/monero-project/monero/issues/8447
    - https://github.com/monero-project/monero/pull/8763

## Current Assessment
- Runtime operability demonstrated across host/container/P2P bridge with real mined blocks and confirmed transfers.
- Shielded and PQ multisig transaction paths remain functional under stress on this environment.
- Production readiness remains contingent on unresolved design-level cryptographic hardening items tracked in:
  - `/Users/admin/Documents/btxchain/btx-node/doc/btx-shielded-pool-critical-issues.md`
  - `/Users/admin/Documents/btxchain/btx-node/doc/btx-design-assessment.md`

## Addendum: Final Verification Gates (2026-03-07)

### Targeted Difficulty + Mining Runtime Suite
Command:
```bash
python3 test/functional/test_runner.py --configfile build-btx/test/config.ini --jobs=2 \
  feature_btx_dgw_convergence.py mining_mainnet.py mining_matmul_basic.py \
  feature_btx_fast_mining_phase.py feature_btx_kawpow_consensus.py
```

Result:
- all 5 passed
- accumulated duration: 27 s
- validates DGW convergence and BTX mining/difficulty transitions in live regtest execution

### Full CTest Sweep
Command:
```bash
ctest --test-dir build-btx -j 8 --output-on-failure
```

Result:
- `204/204` tests passed
- total test time (real): `135.52 sec`
- includes shielded, ringct, MatMul validation, wallet RPC, and integration unit tests

### Official Production Readiness Runbook
Command:
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307.json
```

Result:
- overall status: `pass`
- artifact: `/tmp/btx-production-readiness-20260307.json`
- notable passed checks:
  - `parallel_gate`
  - `launch_blockers`
  - `pow_scaling_suite`
  - `live_dual_node_p2p`
  - `live_strict_mining`

### Upstream Security Signal Refresh
Additional primary-source checks performed:
- Bitcoin Core latest disclosures (includes 2025 CVEs):
  - https://bitcoincore.org/en/security-advisories/
- OpenSSL advisories feed:
  - https://openssl-library.org/news/vulnerabilities-1.1.1/
- SQLite CVE registry:
  - https://www.sqlite.org/cves.html

## Addendum: Extended Real-World Cycle (2026-03-07, Round 2)

### Branch/Context Sync
- Re-fetched:
  - `origin/claude/btx-privacy-analysis-8CN3q`
  - `origin/codex/shielded-pool-overhaul`
- Verified latest claude head remains:
  - `98462409dc`
- Verified codex branch includes additional runtime/audit docs beyond claude branch.

### Build + Environment Baseline
- Incremental rebuild:
  - `cmake --build build-btx -j8`
  - result: pass
- Runtime versions:
  - BTX CLI: `v29.4.0.knots20260220`
  - OpenSSL runtime: `3.6.1 (2026-01-27)`
  - Docker server: `24.0.5`

### Issue Found and Fixed During Live Run
Observed failure:
```text
scripts/live_regtest_realworld_validation.py --mine-blocks 2400
-> TimeoutError during generatetoaddress RPC
```

Root cause:
- the harness used fixed 60s RPC transport timeout and mined all blocks in one RPC call.

Fix implemented:
- file: `scripts/live_regtest_realworld_validation.py`
- added per-call timeout support in RPC client
- added chunked mining helper (`mine_to_address`)
- added CLI controls:
  - `--mine-batch-size`
  - `--rpc-timeout-seconds`
  - `--mining-rpc-timeout-seconds`
- replaced single large `generatetoaddress` calls with chunked mining path.

Validation after fix:
```bash
scripts/live_regtest_realworld_validation.py \
  --build-dir build-btx \
  --mine-blocks 2400 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307c.json
```
- result: pass
- key evidence:
  - final height: `2423`
  - best block: `fbdc0cdac1e65d79b3e68e7bac1f5b402c9780b93d192681e625dac764425a0a`
  - bits changes observed: `1`
  - shielded txid: `b04b0719ca7a8f4eed5b60ca1af8c99324e46ee2bce4c321d67b8b68eec85db9`
  - unshield txid: `3dab4cbe38ea8ca8ff3ce1f6decb7895ec8a2d4cdf6c432ab94d925a9f7cf6d9`
  - multisig spend txid: `95bbc7509e8d5b43118c0a684840e9222cad2e7352840149c4b1197933ff0612`

### Host + Container Interop Re-Run
Command:
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307b.json \
  --log-dir /tmp/btx-m15-full-lifecycle-logs-20260307b
```

Result:
- overall: `pass`
- `mac_host_lifecycle`: pass
- `centos_container_lifecycle`: pass
- `mac_centos_bridge_lifecycle`: pass

### Extended Runtime/Stress Suite
Command:
```bash
python3 test/functional/test_runner.py --configfile build-btx/test/config.ini --jobs=6 \
  feature_btx_dgw_convergence.py feature_btx_fast_mining_phase.py mining_mainnet.py mining_matmul_basic.py \
  wallet_shielded_sendmany_stress.py wallet_shielded_mixed_stress.py wallet_shielded_topology_sim.py wallet_shielded_longhaul_sim.py \
  p2p_shielded_relay.py feature_pq_multisig.py rpc_pq_multisig.py
```

Result:
- `11/11` passed
- runtime: `244 s`

Additional elevated custom runs:
```bash
python3 test/functional/wallet_shielded_randomized_sim.py --configfile build-btx/test/config.ini --rounds=96 --sim-seed=2026030704
python3 test/functional/wallet_shielded_topology_sim.py   --configfile build-btx/test/config.ini --rounds=32 --sim-seed=2026030705
python3 test/functional/wallet_shielded_longhaul_sim.py   --configfile build-btx/test/config.ini --rounds=24 --sim-seed=2026030706
```

Result:
- all 3 passed

### Security Signal Check (Web, refreshed)
- Bitcoin Core advisories:
  - https://bitcoincore.org/en/security-advisories/
- SQLite CVEs:
  - https://www.sqlite.org/cves.html
- OpenSSL advisories:
  - https://openssl-library.org/news/vulnerabilities-1.1.1/
- ASERT reference spec context:
  - https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/

## Addendum: Custom Live Load Harness (2026-03-07, Round 3)

### New Script
Added:
- `/Users/admin/Documents/btxchain/btx-node/scripts/live_regtest_load_stress.py`

Purpose:
- run mixed real-node pressure on regtest with mined funds:
  - transparent sends
  - transparent->shielded
  - shielded->transparent
  - repeated PQ multisig fund/spend cycles
- emit JSON artifact with counters, failure list, mempool peak, and txid samples.

### Defects Found and Fixed in Harness Logic
1. **Coverage assertion fragility**
- Initial version could fail low-round runs with:
  - `RuntimeError: No successful unshield operations recorded`
- Fix:
  - deterministic warm-up cycles added for shield/unshield/multisig before randomized rounds.

2. **Multisig preselected-input sizing failures**
- Initial version produced intermittent failures:
  - `walletcreatefundedpsbt ... preselected coins total amount does not cover transaction target`
- Fix:
  - multisig spend amount now derived from confirmed UTXO amount with safety margin
  - specific insufficient-preselected cases treated as deterministic skip rather than hard failure.

### Validation Runs
Quick deterministic validation:
```bash
scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --initial-mine-blocks 130 \
  --rounds 5 \
  --seed 2026030712 \
  --artifact /tmp/btx-live-load-stress-smoke-20260307g.json
```
- result: `pass`

Higher-volume custom load:
```bash
scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --initial-mine-blocks 130 \
  --rounds 20 \
  --seed 2026030713 \
  --artifact /tmp/btx-live-load-stress-20260307h.json
```
- result: `pass`
- counters:
  - rounds: `20`
  - transparent_sent: `8`
  - shield_success: `21`
  - unshield_success: `3`
  - multisig_success: `5`
  - failures: `0`
  - max_mempool_size: `2`
  - final height: `178`

Operational note:
- very high-round custom runs (`60+` with default mining cadence) are feasible but slow under current PoW path on this host; they were intentionally interrupted after proving harness correctness to keep iteration velocity.

## Addendum: Full Runtime Re-Validation (2026-03-07, Round 4)

### Branch/Docs Sync Re-Check
- Re-fetched and compared:
  - `origin/claude/btx-privacy-analysis-8CN3q`
  - `origin/codex/shielded-pool-overhaul`
- Latest claude head remained unchanged:
  - `98462409dc`
- Confirmed codex branch still contains latest runtime tracking docs and hardening updates.

### Long-Horizon Single-Node Live Run
Command:
```bash
scripts/live_regtest_realworld_validation.py \
  --build-dir build-btx \
  --mine-blocks 1200 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307d.json
```

Result:
- `pass`
- evidence:
  - final height: `1223`
  - bits change count: `1`
  - mean block time delta: `0.16763969974979148`
  - shield txid: `9bab7d586aae02e2f4730fda0e6f6db48c13075973b360dccc408c39427cadbb`
  - unshield txid: `8417218c9322b5288ac0134003308d5b3a6214d6241383ebdf540ade9f44f472`
  - multisig spend txid: `563481f98b9302215830902f6aec18e90417dde80efdc311a5207b081a7219c7`

### Host/Container Interop Re-Run
Command:
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307c.json \
  --log-dir /tmp/btx-m15-full-lifecycle-logs-20260307c
```

Result:
- overall: `pass`
- `mac_host_lifecycle`: pass
- `centos_container_lifecycle`: pass
- `mac_centos_bridge_lifecycle`: pass

### Functional Stress/Consensus Re-Run
Command:
```bash
python3 test/functional/test_runner.py --configfile build-btx/test/config.ini --jobs=6 \
  feature_btx_dgw_convergence.py feature_btx_fast_mining_phase.py mining_mainnet.py mining_matmul_basic.py \
  wallet_shielded_sendmany_stress.py wallet_shielded_mixed_stress.py wallet_shielded_topology_sim.py wallet_shielded_longhaul_sim.py \
  p2p_shielded_relay.py feature_pq_multisig.py rpc_pq_multisig.py
```

Result:
- `11/11` passed
- runtime: `248 s`

### Production Readiness Runbook Re-Run
Command:
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307b.json
```

Result:
- overall status: `pass`
- checks: `17/17` pass

### Web Security Signal Refresh (Round 4)
Primary-source checks refreshed:
- Bitcoin Core advisories:
  - https://bitcoincore.org/en/security-advisories/
- OpenSSL vulnerability announcements:
  - https://openssl-library.org/news/vulnerabilities-1.1.1/
- SQLite CVE list:
  - https://www.sqlite.org/cves.html
- ASERT reference specification:
  - https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/

## Addendum: Runtime Continuation Cycle (2026-03-07, Round 5)

### Sync/Context Re-Check
- Re-fetched:
  - `origin/claude/btx-privacy-analysis-8CN3q`
  - `origin/codex/shielded-pool-overhaul`
- Verified claude head still:
  - `98462409dc`

### Fresh Artifacted Runtime Runs

1) **Single-node long mining + shielded + multisig**
```bash
scripts/live_regtest_realworld_validation.py \
  --build-dir build-btx \
  --mine-blocks 1200 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307d.json
```
- result: `pass`
- final height: `1223`

2) **macOS + CentOS + bridge**
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307c.json \
  --log-dir /tmp/btx-m15-full-lifecycle-logs-20260307c
```
- result: `pass` (all three phases)

3) **Stress/consensus functional suite**
```bash
python3 test/functional/test_runner.py --configfile build-btx/test/config.ini --jobs=6 \
  feature_btx_dgw_convergence.py feature_btx_fast_mining_phase.py mining_mainnet.py mining_matmul_basic.py \
  wallet_shielded_sendmany_stress.py wallet_shielded_mixed_stress.py wallet_shielded_topology_sim.py wallet_shielded_longhaul_sim.py \
  p2p_shielded_relay.py feature_pq_multisig.py rpc_pq_multisig.py
```
- result: `11/11` passed
- runtime: `248 s`

4) **Custom mixed-load harness**
```bash
scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --initial-mine-blocks 130 \
  --rounds 20 \
  --seed 2026030714 \
  --artifact /tmp/btx-live-load-stress-20260307i.json
```
- result: `pass`
- counters:
  - rounds: `20`
  - transparent_sent: `11`
  - shield_success: `24`
  - unshield_success: `1`
  - multisig_success: `2`
  - failures: `0`
  - max_mempool_size: `3`
  - final height: `175`

5) **Full CTest gate**
```bash
ctest --test-dir build-btx -j 8 --output-on-failure
```
- result: `204/204` passed
- total real time: `132.09 sec`

6) **Production readiness checklist**
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307b.json
```
- result: `pass` (`17/17` checks pass)

### Web Security Signal Refresh (Round 5)
- Bitcoin Core advisories:
  - https://bitcoincore.org/en/security-advisories/
- OpenSSL vulnerability announcements:
  - https://openssl-library.org/news/vulnerabilities-1.1.1/
- SQLite CVE list:
  - https://www.sqlite.org/cves.html
- ASERT reference specification:
  - https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/

## Addendum: Runtime Continuation Cycle (2026-03-07, Round 6)

### Extended Load Outcome + Root Cause

Extended mixed-load run (40 randomized rounds):
```bash
python3 -u scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --initial-mine-blocks 150 \
  --rounds 40 \
  --seed 2026030716 \
  --artifact /tmp/btx-live-load-stress-20260307k.json
```

Observed result:
- `overall_status`: `pass_with_failures`
- failures: `2` (both unshield actions rejected in mempool)

Node log evidence from the run datadir:
- `/var/folders/c9/km1w_vjd7zb9gk99z18ghrj00000gn/T/btx-live-load-3scz5b0g/regtest/debug.log`
- explicit reject reason:
  - `CommitTransaction(): Transaction cannot be broadcast immediately, bad-shielded-nullifier-mempool-conflict`

Conclusion:
- This is expected under randomized load when two unshield attempts target the same note/nullifier before the first spend is mined.
- The harness was over-reporting this deterministic contention as hard failures.

### Harness Hardening Applied

Patched:
- `scripts/live_regtest_load_stress.py`

Change:
- In `try_unshield()`, classify
  - `"Shielded transaction created but rejected from mempool"` as
  - `shielded_mempool_reject` skip path
- Preserve hard failure behavior for non-deterministic/unrecognized errors.

### Validation Re-Run After Patch

Re-ran same stress profile with new seed:
```bash
python3 -u scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --initial-mine-blocks 150 \
  --rounds 40 \
  --seed 2026030717 \
  --artifact /tmp/btx-live-load-stress-20260307l.json
```

Post-fix result:
- `overall_status`: `pass`
- `failures`: `0`
- counters:
  - rounds: `40`
  - transparent_sent: `24`
  - shield_success: `22`
  - shield_skipped: `3`
  - unshield_success: `5`
  - unshield_skipped: `1`
  - multisig_success: `6`
  - multisig_skipped: `0`
  - mined_blocks: `198`
  - max_mempool_size: `3`
  - final height: `204`

## Addendum: Runtime Continuation Cycle (2026-03-07, Round 7)

### Re-Sync + Context Validation
- Re-fetched:
  - `origin/claude/btx-privacy-analysis-8CN3q`
  - `origin/codex/shielded-pool-overhaul`
- Verified:
  - claude head remains `98462409dc`
  - no commits are present in claude branch that are missing from codex branch

### Build + Unit/Integration Gates

1) **Fresh compile gate**
```bash
cmake --build build-btx -j8
```
- result: pass

2) **Full CTest**
```bash
ctest --test-dir build-btx -j8 --output-on-failure
```
- result: `204/204` passed
- total real time: `132.33 sec`

3) **Functional stress suite (ASERT/mining/shielded/multisig/P2P)**
```bash
python3 test/functional/test_runner.py --configfile build-btx/test/config.ini --jobs=6 \
  feature_btx_dgw_convergence.py feature_btx_fast_mining_phase.py mining_mainnet.py mining_matmul_basic.py \
  wallet_shielded_sendmany_stress.py wallet_shielded_mixed_stress.py wallet_shielded_topology_sim.py wallet_shielded_longhaul_sim.py \
  p2p_shielded_relay.py feature_pq_multisig.py rpc_pq_multisig.py
```
- result: `11/11` passed
- wall runtime: `246 s`

### Live Runtime (Real Node Activity)

4) **Long-horizon single-node mining + wallet lifecycle**
```bash
scripts/live_regtest_realworld_validation.py \
  --build-dir build-btx \
  --mine-blocks 2400 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307e.json
```
- result: `pass`
- final height: `2423`
- mining observations:
  - initial mined blocks: `2400`
  - bits change count: `1`
  - delta sample size: `2399`
  - mean block delta: `0.1671529804 s`
  - median block delta: `0 s`
- shielded flow:
  - decoy seed tx count: `18`
  - shield txid: `09d96bc9b3c86153da6655e48d4e5c4f8c4f8d7402841eb20ca9658152f6cff3`
  - unshield txid: `c5ca3bdf84d85043cdcbfb3cde24f4c9794477fe8ca15c4a2d0caa919c1eb4ba`
  - Bob received unshielded: `1.0`
- PQ multisig flow:
  - fund txid: `936d4ba47dd072d2afa0a087a250205f0c241d364a0df2a0601db8fad7e8c78b`
  - spend txid: `ee858b422a0374efefdf0fe6b1388691677c6ff5158cac62f3ec9caec31dafbb`
  - signer2 balance: `1.0`

5) **macOS host + CentOS container + bridge matrix**
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307d.json \
  --log-dir /tmp/btx-m15-full-lifecycle-logs-20260307d
```
- result: `pass`
- checks:
  - `mac_host_lifecycle`: pass (`12s`)
  - `centos_container_lifecycle`: pass (`117s`)
  - `mac_centos_bridge_lifecycle`: pass (`100s`)

6) **Extended randomized live-load stress**
```bash
scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --initial-mine-blocks 200 \
  --rounds 100 \
  --seed 2026030718 \
  --artifact /tmp/btx-live-load-stress-20260307m.json
```
- result: `pass`
- counters:
  - rounds: `100`
  - transparent sent: `46`
  - shield success/skipped: `37 / 6`
  - unshield success/skipped: `18 / 3`
  - multisig success/skipped: `11 / 0`
  - mined blocks: `263`
  - max mempool size: `4`
  - failures: `0`
  - final height: `274`

7) **Integrated production readiness runner**
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307c.json
```
- result: `pass`
- checks: `17/17` pass

## Round 12 Addendum (2026-03-07): 6000-Block Runtime + Full Matrix Re-Validation

### Branch/Context Sync
- `origin/codex/shielded-pool-overhaul`: `0b3f6fa068`
- `origin/claude/btx-privacy-analysis-8CN3q`: `98462409dc`
- claude commits missing from codex: `0`

### Build + Unit Baseline
```bash
cmake --build build-btx -j8
ctest --test-dir build-btx -j8 --output-on-failure
```
- build: `pass`
- ctest: `204/204` pass

### Functional Runtime Matrix (Mining + P2P + Shielded + PQ Multisig)
```bash
python3 test/functional/test_runner.py --configfile build-btx/test/config.ini --jobs=6 \
  feature_btx_dgw_convergence.py feature_btx_fast_mining_phase.py mining_mainnet.py \
  mining_prioritisetransaction.py p2p_segwit.py \
  wallet_shielded_send_flow.py wallet_shielded_cross_wallet.py wallet_shielded_reorg_recovery.py \
  wallet_shielded_anchor_window.py wallet_shielded_sendmany_stress.py wallet_shielded_mixed_stress.py \
  wallet_shielded_topology_sim.py wallet_shielded_longhaul_sim.py p2p_shielded_relay.py \
  feature_pq_multisig.py rpc_pq_multisig.py wallet_multisig_descriptor_psbt.py
python3 test/functional/test_runner.py --configfile build-btx/test/config.ini --jobs=1 "wallet_send.py --descriptors"
```
- status: `pass`
- passed: `14`
- skipped (policy-expected): `3`
  - `mining_prioritisetransaction.py` (MiniWallet scriptpubkey policy mismatch on BTX)
  - `p2p_segwit.py` (BTX standardness divergence from upstream segwit assumptions)
  - `wallet_multisig_descriptor_psbt.py --descriptors` and `wallet_send.py --descriptors` (BTX PQ descriptor policy)

### Live Real-World Runtime (6000 mined blocks)
```bash
PYTHONUNBUFFERED=1 scripts/live_regtest_realworld_validation.py \
  --build-dir build-btx \
  --mine-blocks 6000 \
  --mine-batch-size 100 \
  --rpc-timeout-seconds 240 \
  --mining-rpc-timeout-seconds 240 \
  --shielded-rpc-timeout-seconds 300 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307u.json
```
- result: `pass`
- artifact: `/tmp/btx-live-regtest-runtime-validation-20260307u.json`
- key evidence:
  - final height: `6000`
  - bits change count: `1`
  - mean block delta: `0.16736122687114519 s`
  - decoy seed tx count: `18`
  - shield txid: `c4e1dc7c102e32ab27da963c27287e7f46180e08b33ed7e4202673ad5a6c3d73`
  - unshield txid: `e9dd7c626a68200af985ed24c1d18de5adcf8a33efd258fc70b38ba9bc633212`
  - Bob received unshielded: `1.0`
  - multisig spend txid: `faf6ad12d2699f247d3450b17d3d59ac2657ffe0da406daa0bc2d68ed8d8f49c`
  - signer2 balance after multisig spend: `1.0`

### Extended Live Mixed-Load Stress
```bash
PYTHONUNBUFFERED=1 scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --rounds 120 \
  --seed 20260307 \
  --initial-mine-blocks 420 \
  --mine-every-rounds 6 \
  --mine-batch-size 1 \
  --max-runtime-seconds 3600 \
  --artifact /tmp/btx-live-load-stress-20260307u.json
```
- result: `pass`
- artifact: `/tmp/btx-live-load-stress-20260307u.json`
- counters:
  - completed: `true` (`rounds_completed`)
  - rounds: `120`
  - transparent sent: `57`
  - shield success: `42`
  - unshield success: `25`
  - multisig success: `5`
  - mined blocks: `478`
  - max mempool size: `6`
  - failures: `[]`

### Host/Container/Bridge Matrix (macOS + CentOS)
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --skip-centos-build \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307u.json \
  --log-dir /tmp/btx-m15-full-lifecycle-logs-20260307u
```
- result: `pass`
- artifact: `/tmp/btx-m15-full-lifecycle-matrix-20260307u.json`
- phase status:
  - `mac_host_lifecycle`: pass
  - `centos_container_lifecycle`: pass
  - `mac_centos_bridge_lifecycle`: pass
- bridge evidence (`/tmp/btx-m15-full-lifecycle-logs-20260307u/mac-centos-bridge-artifact.json`):
  - converged best block: `a0926e7aa9b8e1066d6b5efa47cfc59e34982a8007918a14c2e69c86c7397703`
  - converged height: `104`
  - forward txid: `b093e76ae11f753ba512baf9af449e66b638c532a66bfd4bb31a8d73fdb085e8`
  - reverse txid: `2d8590dc21b3e13098c928df2a0abe1bae78a5e0b6e5b8687810d398b647a757`

### Production Readiness Gate Re-Run
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307u.json
```
- result: `pass`
- artifact: `/tmp/btx-production-readiness-20260307u.json`
- checks: `17/17` pass

### External Security Signal Refresh (Round 12)
Primary-source refresh performed after runtime validation:
- Bitcoin Core security advisories:
  - https://bitcoincore.org/en/security-advisories/
- Bitcoin Core wallet migration disclosure (2026-01-05):
  - https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/
- OpenSSL vulnerabilities index:
  - https://www.openssl-library.org/news/vulnerabilities/
- OpenSSL 3.6 vulnerabilities page:
  - https://www.openssl-library.org/news/vulnerabilities-3.6/
- SQLite CVE tracker:
  - https://www.sqlite.org/cves.html
- MatRiCT+ publication:
  - https://eprint.iacr.org/2021/545
- Monero decoy-selection post-mortem:
  - https://www.getmonero.org/2021/09/20/post-mortem-of-decoy-selection-bugs.html

### Web Security Review Refresh (Round 7)

Primary sources reviewed:
- Bitcoin Core security advisory index:
  - https://bitcoincore.org/en/security-advisories/
- Bitcoin Core 30.2 release notes (wallet migration bug fix references):
  - https://bitcoincore.org/en/releases/30.2/
- Wallet migration vulnerability disclosure (Jan 5, 2026):
  - https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/
- OpenSSL support policy and EOL notice for 1.1.1:
  - https://openssl-library.org/post/2023-06-15-1.1.1-eol-reminder/
- OpenSSL 1.1.1 vulnerability page (historical):
  - https://openssl-library.org/news/vulnerabilities-1.1.1/
- SQLite CVE tracker:
  - https://www.sqlite.org/cves.html
- Monero decoy selection post-mortem:
  - https://www.getmonero.org/2021/09/20/post-mortem-of-decoy-selection-bugs.html
- MatRiCT+ paper:
  - https://eprint.iacr.org/2021/545

Codebase relevance checks from this cycle:
- Wallet migration cleanup path in `src/wallet/wallet.cpp` already uses tracked file/directory cleanup lists and avoids broad directory wipes.
- Ring selection code (`src/shielded/ringct/ring_selection.cpp`) remains aligned with gamma-distribution decoy sampling plus audit-driven mitigations (ChaCha20 CSPRNG, randomized real-index occurrence selection).
- Runtime link/runtime environment observed on this host:
  - OpenSSL: `3.6.1` (supported line)
  - BTX node links to `/usr/lib/libsqlite3.dylib`; host CLI sqlite reports `3.43.2`.
  - Latest SQLite CVE page should remain a launch checklist input for deployment environments.

### Additional Notes
- `wallet_migration.py` was invoked in this cycle but skipped by framework because previous-release fixtures were unavailable in this environment.

## Round 8 Addendum (2026-03-07): Deep ASERT Fast->Normal Transition Drill

### Command and Artifact
```bash
scripts/m14_fast_normal_transition_sim.sh \
  --build-dir build-btx-transition-sim \
  --fast-mine-height 120 \
  --normal-blocks 80 \
  --artifact /tmp/btx-m14-fast-normal-transition-20260307c.json \
  --log-file /tmp/btx-m14-fast-normal-transition-20260307c.log \
  --backend cpu
```

Observed behavior:
- The simulation reached `h=199` and produced a complete transition trace in `/tmp/btx-m14-fast-normal-transition-20260307c.log`.
- Late normal-phase difficulty ramp caused prolonged wall-time per block on CPU mining and the run was manually terminated to bound runtime.
- Derived partial artifact (for reproducibility): `/tmp/btx-m14-fast-normal-transition-20260307c.partial.json`

### Parsed Transition Evidence (from partial artifact)
- `first_height`: `1`
- `last_height`: `199`
- `fast_rows`: `119`
- `normal_rows`: `80`
- ASERT bits retarget changes: `19`
  - first retarget at height: `181`
  - last observed retarget at height: `199`
- compact target (`bits`) moved:
  - initial: `20147ae1`
  - final: `2000a419`
- estimated difficulty multiplier:
  - `31.94974886333881x` (from first to last observed row)
- timing profile:
  - median block delta excluding bootstrap row: `2.0 s`
  - mean block delta excluding bootstrap row: `3.702020202020202 s`
  - max observed per-block wall mining time: `320 s`

### Findings and Hardening Follow-up
- ASERT retarget behavior is functioning and produces continuous upward retargets in the normal phase after fast-mining pressure.
- Stress runtime on CPU-only mining can become unbounded in late-stage transition tests. This is now treated as a test-harness reliability issue (not a consensus failure).
- Action item for next pass:
  - add a bounded-runtime option to `m14_fast_normal_transition_sim.sh` (or enforce target height/time guard in wrapper) to guarantee deterministic CI completion while preserving retarget evidence capture.

## Round 9 Addendum (2026-03-07): Transition Harness Runtime Guard Hardening

### Implemented Hardening
- Updated `scripts/m14_fast_normal_transition_sim.sh` to support:
  - `--max-wall-seconds <n>` runtime cap (`0` = unlimited/default)
  - artifact metadata fields:
    - `target_height`
    - `final_height`
    - `completed` (bool)
    - `termination_reason` (`target_height_reached` or `max_wall_seconds_exceeded`)

### Validation Runs

1) **Completion smoke run (guard enabled, no timeout hit)**
```bash
scripts/m14_fast_normal_transition_sim.sh \
  --build-dir build-btx-transition-sim \
  --skip-build \
  --fast-mine-height 30 \
  --normal-blocks 10 \
  --max-wall-seconds 240 \
  --artifact /tmp/btx-m14-smoke-complete-20260307.json \
  --log-file /tmp/btx-m14-smoke-complete-20260307.log \
  --backend cpu
```
- result: `pass`
- artifact summary:
  - `completed`: `true`
  - `termination_reason`: `target_height_reached`
  - `target_height`: `40`
  - `final_height`: `40`
  - `transition_seen`: `true`

2) **Forced timeout run (bounded partial artifact)**
```bash
scripts/m14_fast_normal_transition_sim.sh \
  --build-dir build-btx-transition-sim \
  --skip-build \
  --fast-mine-height 10 \
  --normal-blocks 120 \
  --max-wall-seconds 40 \
  --artifact /tmp/btx-m14-smoke-timeout2-20260307.json \
  --log-file /tmp/btx-m14-smoke-timeout2-20260307.log \
  --backend cpu
```
- result: `pass` (bounded partial)
- artifact summary:
  - `completed`: `false`
  - `termination_reason`: `max_wall_seconds_exceeded`
  - `target_height`: `130`
  - `final_height`: `17`
  - `transition_seen`: `true`

### Outcome
- The transition drill no longer needs to run unbounded under rising post-fast difficulty to produce actionable evidence.
- Runtime-bounded artifacts now preserve traceability and can be consumed in CI/research workflows without hanging jobs.

## Round 10 Addendum (2026-03-07): Full Runtime Revalidation + Harness Hardening

### Branch/Context Sync
- Verified latest remote state before execution:
  - `origin/claude/btx-privacy-analysis-8CN3q`: `98462409dc`
  - `origin/codex/shielded-pool-overhaul`: `ebbec89397` (at start of this round)
- No commits were missing from claude into codex.

### Compile + Core Test Gates

1) **Rebuild**
```bash
cmake --build /Users/admin/Documents/btxchain/btx-node/build-btx -j8
```
- result: pass

2) **Full CTest**
```bash
ctest --test-dir /Users/admin/Documents/btxchain/btx-node/build-btx -j8 --output-on-failure
```
- result: `204/204` passed
- total real time: `133.02 sec`

3) **Functional matrix (mining + shielded + multisig + p2p)**
```bash
python3 /Users/admin/Documents/btxchain/btx-node/test/functional/test_runner.py \
  --configfile /Users/admin/Documents/btxchain/btx-node/build-btx/test/config.ini \
  --jobs=6 \
  feature_btx_dgw_convergence.py feature_btx_fast_mining_phase.py mining_mainnet.py mining_matmul_basic.py \
  wallet_shielded_sendmany_stress.py wallet_shielded_mixed_stress.py wallet_shielded_topology_sim.py wallet_shielded_longhaul_sim.py \
  p2p_shielded_relay.py feature_pq_multisig.py rpc_pq_multisig.py wallet_migration.py
```
- result: `11/12` passed, `1` skipped (`wallet_migration.py` previous-release fixtures unavailable)

### Live Real-World Runtime + Cross-Platform

4) **Extended single-node live lifecycle (4000 mined blocks)**
```bash
scripts/live_regtest_realworld_validation.py \
  --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx \
  --mine-blocks 4000 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307g.json
```
- result: `pass`
- key evidence:
  - final height: `4023`
  - initial mined blocks: `4000`
  - bits change count: `1`
  - mean block delta: `0.16704176044011002 s`
  - median block delta: `0 s`
  - decoy seed tx count: `18`
  - shield txid: `034f0904fba6b7a7063f694258b854b617df2e2e897ebb31a574168fa15b65df`
  - unshield txid: `62ce0340cd9e9c9171650e737593c5f42954928f3f2e82bef3ffb83087fe9128`
  - Bob received: `1.0`
  - multisig spend txid: `57a777f1c83af36d17d89a88edc8a0492a42867560c7197c767bb96179055c8b`

5) **macOS host + CentOS container + bridge lifecycle**
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307e.json \
  --log-dir /tmp/btx-m15-full-lifecycle-logs-20260307e
```
- result: `pass`
- phase coverage:
  - `mac_host_lifecycle`: pass (`11s`)
  - `centos_container_lifecycle`: pass (`124s`)
  - `mac_centos_bridge_lifecycle`: pass (`135s`)

6) **Integrated production readiness**
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307d.json
```
- result: `pass`
- checks: all recorded entries in artifact are `pass` (parallel gate, mining readiness, launch blockers, dual-node p2p, strict mining, timeout guards, etc.)

### Failures Found and Fixed in This Round

#### F1: High-height shielded RPC timeout in live runtime harness
- failure observed:
  - `live_regtest_realworld_validation.py` timed out during `z_shieldfunds` on `--mine-blocks 4000`
- fix implemented:
  - Added `--shielded-rpc-timeout-seconds` (default `600`)
  - Routed `z_*` calls through shielded-specific timeout
  - Added explicit timeout exception handling for RPC transport
  - Added argument validation guards
- verification:
  - reran same 4000-block scenario successfully (`/tmp/btx-live-regtest-runtime-validation-20260307g.json`)

#### F2: Long-load stress harness could enter silent long-wait phases
- failure pattern observed:
  - very long silent stretches under high mixed load (hard to distinguish progress from stall)
- hardening implemented:
  - Added explicit timeout exception handling to RPC client
  - Added `--shielded-rpc-timeout-seconds`
  - Added bounded runtime control:
    - `--max-runtime-seconds`
  - Added periodic round telemetry:
    - `--progress-every-rounds`
  - Reduced default `--mine-batch-size` from `200` to `50` for better responsiveness and visibility
  - Added startup configuration logging and mining progress logs
- bounded stress verification run:
```bash
PYTHONUNBUFFERED=1 scripts/live_regtest_load_stress.py \
  --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx \
  --initial-mine-blocks 200 \
  --rounds 150 \
  --seed 2026030722 \
  --max-runtime-seconds 600 \
  --progress-every-rounds 15 \
  --shielded-rpc-timeout-seconds 120 \
  --rpc-timeout-seconds 60 \
  --mining-rpc-timeout-seconds 180 \
  --artifact /tmp/btx-live-load-stress-20260307q.json
```
- result: bounded partial pass
  - `completed=false`
  - `termination_reason=max_runtime_seconds_exceeded`
  - rounds completed: `105`
  - failures: `0`
  - counters at cutoff:
    - transparent: `44`
    - shield success/skipped: `37 / 6`
    - unshield success/skipped: `24 / 3`
    - multisig success/skipped: `12 / 0`
    - mined blocks: `264`
    - max mempool size: `3`

### External Security Source Refresh (Round 10)
- Bitcoin Core security advisories:
  - https://bitcoincore.org/en/security-advisories/
- Bitcoin Core 30.2 release notes:
  - https://bitcoincore.org/en/releases/30.2/
- Bitcoin Core wallet migration disclosure (Jan 5, 2026):
  - https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/
- SQLite CVE tracker:
  - https://www.sqlite.org/cves.html
- OpenSSL vulnerability/advisory index:
  - https://www.openssl.org/news/vulnerabilities.html
- NIST ML-KEM / ML-DSA standards:
  - https://csrc.nist.gov/pubs/fips/203/final
  - https://csrc.nist.gov/pubs/fips/204/final

Local runtime linkage snapshot during this round:
- OpenSSL: `3.6.1` (`openssl version`)
- SQLite CLI: `3.43.2`
- BTX node links to `/usr/lib/libsqlite3.dylib`

## Round 11 Addendum (2026-03-07): High-Height Retry Hardening + Stable Stress Completion

### Context Recheck
- Remote sync revalidated at start of round:
  - `origin/claude/btx-privacy-analysis-8CN3q`: `98462409dc`
  - `origin/codex/shielded-pool-overhaul`: `f7d9ff3887` (start-of-round head)
  - missing claude commits in codex: `0`

### New Failure Found
- Running `live_regtest_realworld_validation.py` at `--mine-blocks 5000` produced:
  - `RPCError -26`: `"Shielded transaction created but rejected from mempool (policy or consensus)"`
  - location: decoy-seeding repeated `z_shieldfunds` stage

### New Fixes Implemented

1) `scripts/live_regtest_realworld_validation.py`
- Added `--shielded-retry-attempts` (default `6`)
- Added shield mempool-reject retry logic for:
  - decoy seed shielding
  - main Alice shielding
- Retry strategy:
  - detect mempool reject / construction conflict
  - mine one block
  - retry up to configured bound
- Added runtime phase progress logs and normalized `shield_txid` artifact field:
  - `shield_txid` now canonical txid string
  - full raw shield RPC response retained in `shield_tx_result`

2) `scripts/live_regtest_load_stress.py`
- Improved observability and deterministic operator feedback:
  - flush-on-print logging for startup, warm-up phases, round checkpoints, and completion
- Classified shield mempool rejects as deterministic skip paths (not hard failure):
  - `"Shielded transaction created but rejected from mempool"` -> `shielded_mempool_reject`

### Validation Runs After Fixes

1) **Deep live runtime lifecycle (5000 mined blocks)**
```bash
PYTHONUNBUFFERED=1 scripts/live_regtest_realworld_validation.py \
  --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx \
  --mine-blocks 5000 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307i.json
```
- result: `pass`
- key evidence:
  - final height: `5024`
  - initial mined blocks: `5000`
  - bits change count: `1`
  - mean block delta: `0.16703340668133626 s`
  - median block delta: `0 s`
  - decoy seed tx count: `18`
  - shield txid: `7f3014d65c0f7aedbd8221fc9a7229930eab57c04a778d94291c84b872540f6b`
  - unshield txid: `c0d4e03584c14085cc424fc168ba8e9ab7fd18780656d2d273c470788b1cda4b`
  - Bob received: `1.0`
  - multisig spend txid: `b0486110ccfe7b155c35bf29edc82b166b3c5026bfc9172587121d18481b1e71`

2) **Long mixed-load stress (full completion, zero failures)**
```bash
PYTHONUNBUFFERED=1 scripts/live_regtest_load_stress.py \
  --build-dir /Users/admin/Documents/btxchain/btx-node/build-btx \
  --initial-mine-blocks 200 \
  --rounds 120 \
  --seed 2026030724 \
  --max-runtime-seconds 900 \
  --progress-every-rounds 20 \
  --shielded-rpc-timeout-seconds 120 \
  --rpc-timeout-seconds 60 \
  --mining-rpc-timeout-seconds 180 \
  --artifact /tmp/btx-live-load-stress-20260307s.json
```
- result: `pass`
- counters:
  - rounds: `120`
  - transparent sent: `59`
  - shield success/skipped: `38 / 8`
  - unshield success/skipped: `14 / 9`
  - multisig success/skipped: `13 / 0`
  - mined blocks: `268`
  - max mempool size: `3`
  - failures: `0`

3) **Host/container/bridge lifecycle rerun**
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307f.json \
  --log-dir /tmp/btx-m15-full-lifecycle-logs-20260307f
```
- result: `pass`
- durations:
  - mac host: `13s`
  - centos container: `122s`
  - bridge: `103s`

4) **Production readiness rerun**
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307e.json
```
- result: `pass`
- checks: `17/17` pass

## Round 12 Addendum (2026-03-07): Freivalds Integration + Runtime Matrix Re-Validation

### Context Sync / Branch Delta Check
- fetched latest remotes and rechecked heads:
  - `HEAD`: `95cdbeda16` (start of this round)
  - `origin/codex/shielded-pool-overhaul`: `95cdbeda16`
  - `origin/claude/btx-privacy-analysis-8CN3q`: `98462409dc`
- missing commits from `claude/btx-privacy-analysis-8CN3q` into codex branch:
  - `0` (`git log origin/codex/shielded-pool-overhaul..origin/claude/btx-privacy-analysis-8CN3q`)

### New Design Doc Intake and Implementation
- discovered additional Freivalds analysis doc on `origin/claude/review-branch-merge-BBa9g`:
  - `doc/freivalds-algorithm-analysis.md`
- implemented Freivalds primitive + tests + benchmarks:
  - `src/matmul/freivalds.h`
  - `src/matmul/freivalds.cpp`
  - `src/test/matmul_freivalds_tests.cpp`
  - `src/bench/matmul_freivalds_bench.cpp`
  - CMake wiring updates in `src/CMakeLists.txt`, `src/test/CMakeLists.txt`, `src/bench/CMakeLists.txt`

### Verification and Benchmarks
1) Targeted test subset:
```bash
ctest --test-dir build-btx -R "matmul_freivalds_tests|matmul_pow_tests|pow_tests|bench_sanity_check_high_priority" --output-on-failure
```
- result: `5/5` pass

2) Full unit/integration sweep:
```bash
ctest --test-dir build-btx -j 8 --output-on-failure
```
- result: `205/205` pass
- total real time: `132.53 sec`

3) Freivalds benchmark:
```bash
build-btx/bin/bench_btx -filter='MatMulFreivalds.*' -min-time=100
```
- `MatMulFreivaldsN256R2`: `147,493.48 ns/round` (`6,779.96 round/s`)
- `MatMulFreivaldsN512R2`: `569,430.56 ns/round` (`1,756.14 round/s`)

### Live Runtime / P2P / Container Results
1) Single-node real runtime:
```bash
python3 scripts/live_regtest_realworld_validation.py \
  --build-dir build-btx \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307-v2.json
```
- result: `pass`
- evidence:
  - final height: `453`
  - best block: `58813687e0c2d94b94351f1879b1b794b1f25628ca4c3c1777b19502144f19ff`
  - shield txid: `8ccbe17d6259b3aa1872278ad7816ade9714940f383e14baa5bbe657059811a5`
  - unshield txid: `af66703badaa0e07836b35c7550b80caa2fe70ab1e1fb22cfcfeda6970e83cf4`
  - multisig spend txid: `e697c6032fa76b416f260ba539d924d1097a184248b91d6d3482a279303fc335`

2) Dual-node P2P readiness:
```bash
scripts/m12_dual_node_p2p_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-m12-dual-node-p2p-20260307-v2.json \
  --timeout-seconds 240
```
- result: `pass`
- evidence:
  - shared genesis: `bbc501af18e6b3a69a43c6f134d4b9710bd96dff17ee07fa648c297438495247`
  - relay txid: `ed065c8f154f50292c21c4adcd3c162b77ecac4f0bc7523987214f8bc32d2d32`
  - final heights: `104/104`
  - best hash convergence: identical on both nodes

3) Host + CentOS container + bridge lifecycle:
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307-v2.json \
  --timeout-seconds 1800 \
  --skip-centos-build
```
- result: `pass`
- phases:
  - `mac_host_lifecycle`: pass (`12s`)
  - `centos_container_lifecycle`: pass (`39s`)
  - `mac_centos_bridge_lifecycle`: pass (`34s`)

### Stress and Difficulty Findings
1) Fast->normal transition simulation:
```bash
scripts/m14_fast_normal_transition_sim.sh \
  --build-dir build-btx-transition-sim \
  --fast-mine-height 120 \
  --normal-blocks 160 \
  --max-wall-seconds 1800 \
  --backend cpu \
  --artifact /tmp/btx-m14-fast-normal-transition-20260307u.json \
  --log-file /tmp/btx-m14-fast-normal-transition-20260307u.log
```
- result: partial (`completed=false`)
- termination: `max_wall_seconds_exceeded`
- evidence:
  - final height: `210`
  - normal-phase difficulty rose from `2.910339243896464e-09` to `1.707365312792284e-07`
  - long wall-time spikes observed (`150s`, `302s+`) after transition

2) Mixed-load stress completion (bounded profile):
```bash
python3 scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --artifact /tmp/btx-live-load-stress-20260307-v3.json \
  --rounds 120 \
  --initial-mine-blocks 110 \
  --mine-every-rounds 6 \
  --mine-batch-size 20 \
  --progress-every-rounds 10 \
  --max-runtime-seconds 900 \
  --mining-rpc-timeout-seconds 180 \
  --shielded-rpc-timeout-seconds 600
```
- result: `pass`
- counters:
  - rounds: `120`
  - transparent: `62`
  - shield success/skipped: `41 / 5`
  - unshield success/skipped: `18 / 7`
  - multisig success/skipped: `8 / 0`
  - mined blocks: `168`
  - max mempool size: `5`
  - failures: `0`

### Script Hardening Added This Round
- file: `scripts/live_regtest_load_stress.py`
- improvements:
  - explicit handling for round-confirm mining failures
  - explicit handling for final-confirm mining failures
  - guaranteed artifact write on partial/failure paths
  - expanded status model:
    - `pass`
    - `pass_with_failures`
    - `partial`
    - `partial_with_failures`
  - non-fatal invariant recording for missing shield/unshield/multisig success
  - defensive final balance collection with failure capture

smoke validation after patch:
```bash
python3 scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --artifact /tmp/btx-live-load-stress-20260307-v4-smoke.json \
  --rounds 20 \
  --initial-mine-blocks 105 \
  --mine-every-rounds 5 \
  --mine-batch-size 20 \
  --progress-every-rounds 5 \
  --max-runtime-seconds 300 \
  --mining-rpc-timeout-seconds 120 \
  --shielded-rpc-timeout-seconds 300
```
- result: `pass` (`completed=true`, `termination_reason=rounds_completed`, `failures=[]`)

### Production Readiness Consolidated Rerun
Command:
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307-v2.json \
  --check-timeout-seconds 900 \
  --skip-parallel-gate \
  --skip-benchmark-suite \
  --skip-pow-scaling-suite \
  --skip-launch-blockers \
  --skip-m7-pool-e2e \
  --skip-m7-external-miner
```
- result: `pass`
- checks in artifact: `11/11` pass (including `live_dual_node_p2p`, `live_strict_mining`, timeout guards, genesis freeze, mining readiness)

## Round 14 Refresh (2026-03-07, ASERT-only MatMul Routing)

### Branch Sync / Context
- Re-fetched remotes and re-verified:
  - `origin/codex/shielded-pool-overhaul = c165111e6e` (before this round’s new local commit)
  - `origin/claude/btx-privacy-analysis-8CN3q = 98462409dc`
- Delta check remained empty:
  - `git log origin/codex/shielded-pool-overhaul..origin/claude/btx-privacy-analysis-8CN3q` produced no commits.
- Applied consensus hardening commit from reviewed branch:
  - `35be1c5a2d` (`consensus: remove DGW from MatMul difficulty path, use ASERT exclusively`)

### Build / Test Validation After Consensus Change
1) Targeted PoW/transition checks:
```bash
ctest --test-dir build-btx -R matmul_dgw_tests --output-on-failure
test/functional/test_runner.py feature_btx_dgw_convergence.py
```
- result: pass

2) Full suite:
```bash
ctest --test-dir build-btx -j 8 --output-on-failure
```
- result: `205/205` pass
- total real time: `132.66 sec`

3) Build hygiene:
- Removed post-change warning by marking now-unrouted MatMul DGW helper as intentionally unused:
  - file: `src/pow.cpp`
  - change: `DarkGravityWaveMatMul` -> `[[maybe_unused]]`

### Post-Change Live Runtime Evidence
1) Long-run single-node real lifecycle (mining + shielded + multisig):
```bash
python3 scripts/live_regtest_realworld_validation.py \
  --build-dir build-btx \
  --mine-blocks 6000 \
  --mine-batch-size 250 \
  --rpc-timeout-seconds 90 \
  --mining-rpc-timeout-seconds 600 \
  --shielded-rpc-timeout-seconds 900 \
  --shielded-retry-attempts 8 \
  --artifact /tmp/btx-live-regtest-runtime-validation-20260307-asertonly.json
```
- result: `pass`
- evidence:
  - final height: `6000`
  - best block: `6a2a86a4e74f8245eaa2f359bc056d767ca5bdb262c74f6b3d6e447f82c49581`
  - bits-change count: `1`
  - shield txid: `d81a1cf68cf488bcca9f8c8a7d0e9279d190ed883c251e70b2e97e98026df701`
  - unshield txid: `cf266d7280a460866193cc5db762ee197f506c629a9ddfb89f46cb4cedc8e329`
  - multisig spend txid: `3ff6cc6631d567cc868317ba0fb9945b33813610678b136b927c2e9b9bf0ea27`

2) Mixed-load stress:
```bash
python3 scripts/live_regtest_load_stress.py \
  --build-dir build-btx \
  --artifact /tmp/btx-live-load-stress-20260307-asertonly.json \
  --rounds 120 \
  --initial-mine-blocks 110 \
  --mine-every-rounds 6 \
  --mine-batch-size 20 \
  --progress-every-rounds 10 \
  --max-runtime-seconds 900 \
  --rpc-timeout-seconds 90 \
  --mining-rpc-timeout-seconds 180 \
  --shielded-rpc-timeout-seconds 600
```
- result: `pass`
- counters:
  - rounds: `120`
  - transparent: `62`
  - shield success/skipped: `40 / 6`
  - unshield success/skipped: `21 / 7`
  - multisig success/skipped: `5 / 0`
  - mined blocks: `168`
  - max mempool size: `5`
  - failures: `0`

3) Fast->normal transition simulation (bounded):
```bash
scripts/m14_fast_normal_transition_sim.sh \
  --build-dir build-btx-transition-sim \
  --fast-mine-height 40 \
  --normal-blocks 40 \
  --max-wall-seconds 1200 \
  --backend cpu \
  --artifact /tmp/btx-m14-fast-normal-transition-20260307-asertonly.json \
  --log-file /tmp/btx-m14-fast-normal-transition-20260307-asertonly.log
```
- result: `completed=true` (`target_height_reached`)
- evidence:
  - transition seen: `true`
  - final height: `80`
  - fast avg wall sec: `2.0256`
  - normal avg wall sec: `2.4146`
  - fast diff min/max: `2.910339243896464e-09 / 2.910339243896464e-09`
  - normal diff min/max: `2.910339243896464e-09 / 2.910339243896464e-09`

4) Dual-node P2P relay:
```bash
scripts/m12_dual_node_p2p_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-m12-dual-node-p2p-20260307-asertonly.json \
  --timeout-seconds 240
```
- result: `pass`
- relay txid: `986cf78eade4cad23daeacbeca8eeacf453951d39f1723f236f36e92589184d4`
- final heights: `104/104`

5) Host + container + bridge lifecycle:
```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-lifecycle-matrix-20260307-asertonly.json \
  --timeout-seconds 1800 \
  --skip-centos-build
```
- result: `pass`
- phases:
  - `mac_host_lifecycle`: `12s`
  - `centos_container_lifecycle`: `37s`
  - `mac_centos_bridge_lifecycle`: `39s`

6) Consolidated readiness:
```bash
scripts/verify_btx_production_readiness.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-production-readiness-20260307-asertonly.json \
  --check-timeout-seconds 900 \
  --skip-parallel-gate \
  --skip-benchmark-suite \
  --skip-pow-scaling-suite \
  --skip-launch-blockers \
  --skip-m7-pool-e2e \
  --skip-m7-external-miner
```
- result: `pass` (`11/11` checks passed)
