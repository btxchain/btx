<!-- Copyright (c) 2026 The BTX developers -->
<!-- Distributed under the MIT software license, see the accompanying -->
<!-- file COPYING or http://www.opensource.org/licenses/mit-license.php. -->

# BTX Shielded Online Threat Review (2026-03-06)

## Scope
This review refreshes internet-facing threat intelligence and cross-project disclosures,
maps them to BTX shielded code paths, and records hardening/test actions completed in this pass.

## Branch Context Reconciliation
- Compared `codex/shielded-pool-overhaul` against `claude/btx-privacy-analysis-8CN3q`.
- Confirmed analysis-doc history from the Claude branch is already present on current branch lineage
  (`doc/btx-design-assessment.md`, `doc/btx-shielded-pool-critical-issues.md`).
- Confirmed current branch contains newer tracker/audit artifacts and additional hardening docs.

## Primary Sources Reviewed
1. Bitcoin Core security advisories index:
   - <https://bitcoincore.org/en/security-advisories/>
2. Bitcoin Core disclosure (mutated blocksonly RPC behavior, CVE-2025-46598):
   - <https://bitcoincore.org/en/2025/08/20/disclose-mutated-blocksonly-rpc/>
3. Bitcoin Core disclosure (stale data relay behavior, CVE-2025-54604):
   - <https://bitcoincore.org/en/2025/10/20/disclose-minv_stale_data/>
4. Bitcoin Core disclosure (disk-filling via spoofed self-connections, CVE-2025-54604):
   - <https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-54604/>
5. Bitcoin Core wallet migration incident disclosure:
   - <https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/>
6. Bitcoin Core v30.2 release notes (wallet migration bugfix context):
   - <https://bitcoincore.org/en/releases/30.2/>
7. PQClean security policy:
   - <https://github.com/PQClean/PQClean/security>
8. NIST SP 800-227 (KEM recommendations):
   - <https://csrc.nist.gov/pubs/sp/800/227/final>
9. Zcash ZIP 306 (turnstile policy context):
   - <https://zips.z.cash/zip-0306>
10. Monero decoy-selection regression discussion (`wallet2::gamma_pick`):
   - <https://github.com/monero-project/monero/issues/8872>
11. Lattice side-channel/rejection-leakage analysis (recent ePrint set):
   - <https://eprint.iacr.org/2025/582>
   - <https://eprint.iacr.org/2025/820>
   - <https://eprint.iacr.org/2024/2051>

## Findings And BTX Mapping
1. Malformed/stale P2P payload classes remain a top practical DoS category.
- External signal:
  - Bitcoin Core published two recent classes (`CVE-2025-46598`, `CVE-2025-54604`) in this area.
- BTX mapping:
  - Shielded P2P code already enforces capability gating (`NODE_SHIELDED`), oversized payload rejection,
    and per-peer shielded relay/request rate limiting.
  - Functional coverage exists in `test/functional/p2p_shielded_relay.py`.
- Action in this pass:
  - Re-ran the full P2P shielded relay suite as part of full functional run; passing.

2. Wallet migration cleanup safety remains high impact for production.
- External signal:
  - Bitcoin Core v30.2 notes a migration-path deletion bug and fix.
- BTX mapping:
  - `src/wallet/wallet.cpp` migration cleanup path now tracks only migration-created files/dirs
    and deletes only tracked artifacts (`wallet_files_to_remove`, `wallet_empty_dirs_to_remove`).
- Action in this pass:
  - Re-validated wallet migration-related functional and unit suites in full regression runs; passing.

3. KEM side-channel assumptions require continuous implementation vigilance.
- External signal:
  - PQClean security model and NIST SP 800-227 both reinforce implementation/hardware dependence.
- BTX mapping:
  - Existing ML-KEM hardening (`PQCLEAN_PREVENT_BRANCH_HACK` coverage in `verify.c` and `poly.c`)
    remains present in tree.
- Action in this pass:
  - Re-verified hardened symbols/patterns in `src/crypto/ml-kem-768`; no regression found.

4. Decoy-selection fragility can break spend construction and reduce practical privacy.
- External signal:
  - Monero `gamma_pick` regression discussion underscores sensitivity of ring-decoy edge behavior.
- BTX mapping:
  - Small-tree/low-diversity conditions can trigger ring-signature creation failures in stress flows.
- Action in this pass:
- Added deterministic ring-diversity pre-seeding helper:
  `test/functional/test_framework/shielded_utils.py`.
- Integrated helper in all affected shielded functional scenarios:
    - `wallet_shielded_send_flow.py`
    - `wallet_shielded_sendmany_stress.py`
    - `wallet_shielded_cross_wallet.py`
    - `wallet_shielded_encrypted_persistence.py`
    - `wallet_shielded_reorg_recovery.py`
    - `wallet_shielded_restart_persistence.py`
    - `wallet_shielded_anchor_window.py`
    - `wallet_shielded_mixed_stress.py`
  - `wallet_shielded_randomized_sim.py`
  - `p2p_shielded_relay.py`
- Added a new topology stress simulation to combine randomized shielded flow,
  node restarts, and partition/reorg convergence in one deterministic test:
  - `wallet_shielded_topology_sim.py`
  - Hardened helper for `-walletbroadcast=0` scenarios by explicit rebroadcast of local wallet txs.

## Test Evidence (This Pass)
- Unit/integration (`ctest`): `204/204` passed.
- Functional suite (`test_runner.py`): `45/45` passed.
- Build/staging note:
  - Reconfigured and rebuilt `build-btx` to stage newly added functional scripts
    into `build-btx/test/functional` before rerunning the matrix.
- Extended stress:
  - Direct run: `wallet_shielded_longhaul_sim.py --rounds=24 --sim-seed=20260306`
  - Result: successful completion.
  - Direct run: `wallet_shielded_topology_sim.py --rounds=32 --sim-seed=20260306`
  - Result: successful completion.

## Residual Risk
- Despite green regression and stress coverage in this pass, production readiness still depends on
  ongoing external cryptographic review and continued monitoring for new cross-project disclosures.
  In particular, lattice-proof implementations and shielded consensus paths should remain under
  dedicated audit cadence before irreversible mainnet launch decisions.
