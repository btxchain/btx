<!-- Copyright (c) 2026 The BTX developers -->
<!-- Distributed under the MIT software license, see the accompanying -->
<!-- file COPYING or http://www.opensource.org/licenses/mit-license.php. -->

# BTX Shielded Online Threat Review (2026-03-07)

## Scope
This pass refreshes external vulnerability intelligence, reconciles the latest
Claude analysis branch context, and records hardening/test actions completed
in this run.

## Branch Context Reconciliation
- Fetched `origin/claude/btx-privacy-analysis-8CN3q` and reviewed commit history.
- Verified `origin/claude/btx-privacy-analysis-8CN3q` is an ancestor of
  `codex/shielded-pool-overhaul`.
- Confirmed latest Claude-branch analysis docs are already present on current branch:
  - `doc/btx-design-assessment.md`
  - `doc/btx-shielded-pool-critical-issues.md`

## Primary Sources Reviewed (Online)
1. Bitcoin Core disclosure: CVE-2025-54604
   - <https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-54604/>
2. Bitcoin Core disclosure: CVE-2025-54605
   - <https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-54605/>
3. Bitcoin Core 29.1 release notes (rate-limited logging hardening)
   - <https://bitcoincore.org/en/releases/29.1/>
4. Bitcoin Core 30.2 release notes (wallet migration fixes)
   - <https://bitcoincore.org/en/releases/30.2/>
5. Bitcoin Core wallet migration incident post
   - <https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/>
6. NVD CVE records
   - <https://nvd.nist.gov/vuln/detail/CVE-2025-54604>
   - <https://nvd.nist.gov/vuln/detail/CVE-2025-54605>
7. NIST FIPS 203 (ML-KEM standard)
   - <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf>
8. NIST FIPS 204 (ML-DSA standard)
   - <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>
9. NIST SP 800-227 (KEM implementation recommendations)
   - <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf>
10. KyberSlash timing-attack reference and paper links
    - <https://kyberslash.cr.yp.to/>
    - <https://www.usenix.org/conference/usenixsecurity25/presentation/mccann>
11. Monero decoy-selection bug post-mortem
    - <https://github.com/monero-project/monero/issues/8872>
12. MatRiCT+ protocol paper
    - <https://eprint.iacr.org/2021/545>

## Findings And BTX Mapping

1. Current public Bitcoin Core disk-fill disclosures are already aligned with BTX mitigations.
- External signal:
  - CVE-2025-54604 and CVE-2025-54605 both describe disk-exhaustion vectors.
- BTX mapping:
  - The branch already uses per-callsite log rate limiting and relay throttling paths.
  - Existing P2P and shielded-relay functional coverage remains green.
- Inference:
  - No new code delta was required in this pass for these two disclosures.

2. PQ side-channel guidance remains implementation-critical.
- External signal:
  - FIPS 203 and SP 800-227 require strong handling of decapsulation failures and side-channel resistance.
  - FIPS 204 explicitly notes side-channel/fault considerations for ML-DSA implementations.
  - KyberSlash publications show practical key-recovery risk from timing leakage in non-constant-time paths.
- BTX mapping:
  - Existing ML-KEM integration remains bounded to hardened code paths and test coverage.
- Inference:
  - Continued constant-time review and platform testing remain mandatory before production launch.

3. Decoy-selection fragility remains a known privacy failure mode.
- External signal:
  - Monero issue #8872 documents a real-world off-by-one decoy-selection bug impacting privacy assumptions.
- BTX mapping:
  - BTX already includes ring-selection and shielded stress suites; these were rerun and passed in this pass.

4. New wallet hardening issue found and fixed in this pass.
- Issue:
  - `CShieldedWallet::ImportViewingKey` accepted mismatched `kem_sk`/`kem_pk` pairs and could overwrite
    spend-capable keyset entries via watch-only re-import.
- Fix:
  - Reject null `spending_pk_hash`.
  - Enforce `ValidateMLKEMKeyPair` during import.
  - Prevent spend-authority downgrade when the address already has a spending key.
- Tests:
  - Added functional regression checks in
    `test/functional/wallet_shielded_viewingkey_rescan.py`.

5. RPC import result correctness bug found and fixed in this pass.
- Issue:
  - `z_importviewingkey` previously returned `GetAddresses().back()` after import.
    Address ordering is map-order dependent, so with multiple imported keys this could
    return the wrong address for the key material being imported.
- Fix:
  - Resolve the imported address by matching both `spending_pk_hash` and full KEM public key
    in wallet state instead of relying on container order.
  - Return a wallet RPC error if imported key material cannot be resolved to a concrete address.
- Tests:
  - Extended `test/functional/wallet_shielded_viewingkey_rescan.py` with deterministic
    two-key import ordering checks that assert returned address identity on each import.

6. Shielded address ordering comparator consistency bug found and fixed in this pass.
- Issue:
  - `ShieldedAddress::operator<` ordered only by `pk_hash` and `kem_pk_hash`, while
    equality includes `version` and `algo_byte`.
  - This could collapse semantically distinct addresses into one map key if version/algo
    diversification is introduced or malformed data is encountered.
- Fix:
  - Updated strict ordering to include `version` and `algo_byte` before hash fields.
- Tests:
  - Added `shielded_address_ordering_distinguishes_all_identity_fields` in
    `src/test/shielded_wallet_address_tests.cpp`.

7. Production-readiness lint gate exposed executable-bit drift on stress simulators.
- Issue:
  - `scripts/verify_btx_production_readiness.sh` failed its lint phase because
    `wallet_shielded_longhaul_sim.py` and `wallet_shielded_topology_sim.py`
    had shebangs but non-executable (`100644`) mode in git index metadata.
- Fix:
  - Updated tracked mode to `100755` for both functional simulator scripts.
- Result:
  - Readiness rerun passed all enabled checks after mode correction.

## Test Evidence (This Pass)
- Unit/integration: `ctest --test-dir build-btx -j 8 --output-on-failure`
  - Result: `204/204` passed.
- Full functional suite: `test/functional/test_runner.py --configfile build-btx/test/config.ini -j 8`
  - Result: `45/45` passed.
- Production readiness checklist:
  - `scripts/verify_btx_production_readiness.sh --build-dir build-btx --artifact /tmp/btx-production-readiness-20260307-final.json`
  - Result: `pass` (all enabled checks green).
- Additional custom Python stress harness (multi-seed, high-round):
  - `wallet_shielded_randomized_sim.py --rounds=48 --sim-seed=2026030701`
  - `wallet_shielded_randomized_sim.py --rounds=48 --sim-seed=2026030702`
  - `wallet_shielded_topology_sim.py --rounds=18 --sim-seed=2026030703`
  - `wallet_shielded_longhaul_sim.py --rounds=14 --sim-seed=2026030704`
  - Result: all scenarios passed (`rc=0`).
- Included stress/e2e-heavy suites in the full run, including:
  - `wallet_shielded_sendmany_stress.py`
  - `wallet_shielded_mixed_stress.py`
  - `wallet_shielded_topology_sim.py`
  - `wallet_shielded_longhaul_sim.py`
  - `p2p_shielded_relay.py`
  - `wallet_shielded_viewingkey_rescan.py` (expanded with multi-key identity checks)
  - `shielded_wallet_address_tests` (expanded comparator identity test)

## Residual Risk
- Regression status is clean for this pass, but production readiness still depends on
  continued external cryptographic audit cadence for lattice-proof and side-channel surfaces.

## Round 12 Refresh (2026-03-07, Later Cycle)

### Additional Branch/Doc Reconciliation
- Re-fetched and re-verified:
  - `origin/codex/shielded-pool-overhaul = 95cdbeda16`
  - `origin/claude/btx-privacy-analysis-8CN3q = 98462409dc`
  - delta (`codex..claude`) remained empty.
- Found and imported Freivalds design document from another active Claude branch:
  - `doc/freivalds-algorithm-analysis.md`
  - source branch commit: `1d75a8d14f` on `origin/claude/review-branch-merge-BBa9g`

### Additional Runtime/Readiness Evidence
- Full ctest rerun after Freivalds integration:
  - `205/205` passed.
- Live runtime artifact:
  - `/tmp/btx-live-regtest-runtime-validation-20260307-v2.json` (`pass`)
- Dual-node artifact:
  - `/tmp/btx-m12-dual-node-p2p-20260307-v2.json` (`pass`)
- Host/container/bridge lifecycle artifact:
  - `/tmp/btx-m15-full-lifecycle-matrix-20260307-v2.json` (`pass`)
- Production readiness artifact (this cycle):
  - `/tmp/btx-production-readiness-20260307-v2.json` (`pass`, all enabled checks green)

### New Operational Finding
- Fast->normal ASERT transition simulation hit wall-clock guardrail before target height:
  - artifact: `/tmp/btx-m14-fast-normal-transition-20260307u.json`
  - termination: `max_wall_seconds_exceeded`
  - completed: `false`
  - observed cause: expected difficulty increase after transition drove per-block wall time spikes.
- Security interpretation:
  - not a consensus correctness failure
  - confirms stress harnesses must remain bounded and timeout-aware once crossing transition heights.

### Hardening Applied
- `scripts/live_regtest_load_stress.py` now handles round-confirm/final mining failures explicitly and always writes an artifact with deterministic status (`pass`, `pass_with_failures`, `partial`, `partial_with_failures`) instead of depending on hard exceptions in late-stage mining paths.

## Round 13 Refresh (2026-03-07, ASERT-only Runtime Cycle)

### Additional Branch Reconciliation
- Re-fetched and verified:
  - `origin/codex/shielded-pool-overhaul = c165111e6e` (before this cycle’s new local commit)
  - `origin/claude/btx-privacy-analysis-8CN3q = 98462409dc`
- Reconfirmed no missing commits from `claude/btx-privacy-analysis-8CN3q` into current codex branch.

### Additional Primary Sources Reviewed (Online)
1. Bitcoin Core security advisory index
   - <https://bitcoincore.org/en/security-advisories/>
2. Bitcoin Core disclosure pages (latest listed in advisory index at time of review)
   - <https://bitcoincore.org/en/2025/10/14/disclose-cve-2025-52916/>
   - <https://bitcoincore.org/en/2025/10/16/cve-2025-52917/>
3. OpenSSL vulnerabilities ledger
   - <https://openssl-library.org/news/vulnerabilities/>
   - includes fixes for CVE-2025-9230/CVE-2025-9231 (released in 3.5.3 and 3.4.4)
4. SQLite official CVE ledger
   - <https://www.sqlite.org/cves.html>
   - includes CVE-2025-6965 (fixed in 3.50.2)
5. Monero decoy-selection incident and mitigation trail
   - <https://github.com/monero-project/monero/issues/8872>
   - <https://www.getmonero.org/2025/09/24/monero-0.18.4.0-released.html>

### Additional Findings and BTX Mapping
1. ASERT-only MatMul routing reduced complexity in the active consensus path.
- Change applied this cycle:
  - commit `35be1c5a2d` removes DGW routing from active MatMul next-work selection and routes through MatMul ASERT logic exclusively.
- Effect:
  - eliminates one active retarget algorithm branch in MatMul mode, reducing convergence-surface complexity.

2. Runtime dependency check shows `btxd` links against macOS system SQLite.
- Evidence:
  - `otool -L build-btx/bin/btxd` shows `/usr/lib/libsqlite3.dylib`.
- Mapping:
  - wallet/sqlite code already enables defensive mode and disables trusted schema (`SQLITE_DBCONFIG_DEFENSIVE`, `SQLITE_DBCONFIG_TRUSTED_SCHEMA`), which narrows exploitability from malicious schema constructs.
- Residual:
  - keep SQLite runtime patch level under active operational monitoring because upstream CVEs continue to land.

3. OpenSSL advisories reviewed; no immediate BTX consensus-path impact identified in this cycle.
- Mapping:
  - BTX consensus and PoW validation are not OpenSSL-driven; however, operational tooling on build/runtime hosts still depends on system crypto stacks.
- Action:
  - retain host baseline checks in readiness runs.

4. Monero decoy-selection postmortem remains relevant to BTX ring-selection hardening strategy.
- Mapping:
  - BTX ring-selection/ring tests were rerun as part of this cycle’s full suite and remained green.
  - Decoy-selection correctness remains a standing privacy-critical area requiring continued adversarial tests.
