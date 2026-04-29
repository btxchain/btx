# BTX Shielded Security Review (2026-03-05)

> Historical note: this is a pre-launch security review snapshot from
> 2026-03-05. Current launch status for the Smile-only reset-chain surface is
> tracked in [btx-shielded-production-status-2026-03-20.md](btx-shielded-production-status-2026-03-20.md)
> and [btx-smile-v2-shielded-account-registry-redesign-2026-03-22.md](btx-smile-v2-shielded-account-registry-redesign-2026-03-22.md).

## Scope

This note captures an external security/CVE sweep and maps findings to the current `codex/shielded-pool-overhaul` implementation.

## External Inputs Reviewed

- Bitcoin Core disclosure: [CVE-2025-54604 / CVE-2025-54605](https://bitcoincore.org/en/2025/10/22/fuzzamul-disclosures/)
- Bitcoin Core disclosure: [CVE-2025-46598](https://bitcoincore.org/en/2025/09/18/cve-2025-46598/)
- Bitcoin Core security index: [Security Advisories](https://bitcoincore.org/en/security-advisories/)
- Bitcoin Core disclosure detail: [CVE-2025-54604](https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-54604/)
- Bitcoin Core disclosure detail: [CVE-2025-54605](https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-54605/)
- Bitcoin Core disclosure detail: [CVE-2025-46598](https://bitcoincore.org/en/2025/10/24/disclose-cve-2025-46598/)
- Bitcoin Core disclosure: [Wallet migration failure in 30.0/30.1 (Jan 5, 2026)](https://bitcoincore.org/en/2026/01/05/wallet-migration-bug/)
- Bitcoin Core release follow-up: [Bitcoin Core 30.2 released (Jan 10, 2026)](https://bitcoincore.org/en/2026/01/10/release-30.2/)
- Bitcoin Core release notes: [Bitcoin Core 30.2 release notes](https://bitcoincore.org/en/releases/30.2/)
- MatRiCT+ paper (design basis): [ePrint 2021/545](https://eprint.iacr.org/2021/545)
- Holistic RingCT proof-model critique (security notions for components can be insufficient): [ePrint 2023/321](https://eprint.iacr.org/2023/321)
- Decoy-selection vulnerability reference: [Monero issue #7807](https://github.com/monero-project/monero/issues/7807)
- Ring privacy post-mortem (decoy/ring-selection critique): [Monero post-mortem (2024-12-10)](https://www.getmonero.org/2024/12/10/fluffypony-post-mortem.html)
- ML-KEM side-channel research: [KyberSlash intro](https://kyberslash.cr.yp.to/)
- ML-KEM side-channel paper: [ePrint 2024/1049](https://eprint.iacr.org/2024/1049)
- ML-KEM standard reference: [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- KEM implementation guidance: [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final)
- PQClean side-channel constraints: [PQClean repository requirements](https://github.com/PQClean/PQClean)
- PQClean security advisories and resolved timing issues: [PQClean security overview](https://github.com/PQClean/PQClean/security)
- PQClean lifecycle signal: [PQClean deprecation notice (archival announced July 2026)](https://github.com/PQClean/PQClean)

## Findings and BTX Mapping

### 0) Upstream disclosure baseline as of 2026-03-05

- Applicability: High; BTX inherits broad Bitcoin Core networking/validation surfaces.
- Observation:
  - Bitcoin Core Security Advisories and 30.2 release notes indicate 2025 CVEs and a 2026 wallet
    migration defect/fix path, with no newer public CVE disclosures listed at review time.
- BTX action:
  - Continue periodic diff review against upstream advisories before release cut and after each
    upstream disclosure.

### 1) Log-filling / message-flooding pressure (CVE-2025-54605 class)

- Applicability: Relevant to any P2P parser path with attacker-controlled malformed traffic.
- Current BTX controls:
  - Source-location log rate limiting in `src/logging.h` (`DEFAULT_LOGRATELIMIT`, fixed-window limiter).
  - Shielded relay/data token buckets and per-peer throttling in `src/net_processing.cpp` (`ConsumeShieldedRelayBudget`, `ConsumeShieldedDataBudget`, request throttling).
  - Shielded payload size/canonical parsing guards for `shieldedtx` and `shieldeddata`.
- Status: mitigated at policy/logging layer for shielded paths; keep upstream sync with Core net-processing hardening.

### 2) Fuzzamul malformed anti-DoS payload pressure (CVE-2025-54604 class)

- Applicability: Relevant to BTX MatMul anti-DoS payload parsing.
- Current BTX controls:
  - Malformed/non-canonical payload rejection and bounded handling in validation/net paths (existing guards around MatMul payload checks).
- Status: partially mitigated in-tree; continue differential testing against upstream fixes.

### 3) Ring member selection criticism from deployed privacy systems

- Applicability: High; poor decoy selection weakens anonymity even with correct signatures.
- Current BTX controls:
  - Gamma-style decoy sampling and diversity constraints in `src/shielded/ringct/ring_selection.cpp`.
  - Exclusion-aware selection to avoid overlap and recent-tip concentration.
  - Test coverage in `src/test/ring_selection_tests.cpp` and `src/test/shielded_validation_checks_tests.cpp`.
- Status: materially improved versus deterministic dummy-members; keep tuning distribution using real-chain telemetry before production.

### 4) ML-KEM side-channel caution (KyberSlash class)

- Applicability: High for key confidentiality if implementation is not constant-time.
- Current BTX controls:
  - Correctness/serialization bounds and authenticated encryption checks are in place.
  - Secret material cleanup is in place for shared secrets and derived AEAD keys.
- Gap:
  - Constant-time guarantees for all decapsulation paths remain an external audit item.
- Required action before production:
  - Dedicated side-channel review of `src/crypto/ml-kem-768/` integration and compiler/target behavior.

### 5) MatRiCT+ maturity and audit depth

- Applicability: Critical; consensus-critical cryptography with limited deployment history.
- Current BTX controls:
  - Stronger structural validation, tx-context binding, and nullifier/proof cross-checking.
  - Expanded unit/functional tests and consensus integration checks.
- Gap:
  - Independent cryptographic audit is still mandatory before mainnet launch.
  - Recent holistic RingCT analyses (ePrint 2023/321) show that proving building blocks in isolation is insufficient and that full-system security notions are subtle; BTX must include whole-protocol proof assumptions and adversarial key-generation settings in external audit scope.

### 6) Wallet migration safety (2026 disclosure class)

- Applicability: High for data integrity; wallet migration bugs can cause destructive file operations.
- Current BTX controls:
  - Shielded wallet persistence and restart coverage in functional tests:
    - `test/functional/wallet_shielded_restart_persistence.py`
    - `test/functional/wallet_shielded_encrypted_persistence.py`
- Gap:
  - No dedicated migration-path fuzz/e2e suite yet for future wallet schema transitions.
- Required action before production:
  - Add migration rollback/idempotence tests before any wallet format migration is introduced.

### 7) PQClean dependency lifecycle risk

- Applicability: High for long-term patch velocity in consensus-adjacent crypto dependencies.
- Current BTX controls:
  - In-tree vendoring and local tests for ML-KEM integration.
- Gap:
  - Upstream PQClean archival/deprecation means future fixes may require alternate maintenance flow.
- Required action before production:
  - Define explicit ownership for ongoing ML-KEM code maintenance (upstream replacement, fork policy, and patch SLAs).

## New Hardening Added In This Cycle

- `CViewGrant::Create` now fails fast on oversized view-key input in `src/shielded/bundle.cpp`.
- Added edge tests in `src/test/shielded_transaction_tests.cpp`:
  - reject oversized ViewGrant plaintext input
  - accept/decrypt max-boundary ViewGrant plaintext input
- `src/net_processing.cpp` now treats non-shielded peers sending `getshieldeddata` or `shieldeddata`
  as protocol violations and disconnects/discourages them via `Misbehaving(...)`.
- `test/functional/p2p_shielded_relay.py` now enforces these disconnect paths end-to-end.
- `src/net_processing.cpp` now rejects oversized inbound `shieldedtx` payloads before transaction decode
  and penalizes oversized shielded payloads tunneled over legacy `tx` transport.
- `test/functional/p2p_shielded_relay.py` now verifies disconnect on oversized `shieldedtx` payloads.
- `src/net_processing.cpp` now rejects unsolicited inbound `shieldeddata` unconditionally (without
  relay-budget gating) so peers cannot mask protocol violations by exhausting token buckets first.
- `test/functional/p2p_shielded_relay.py` now verifies unsolicited `shieldeddata` disconnect still
  occurs after shielded-data relay budget exhaustion.
- `src/shielded/bundle.cpp` now rejects duplicate shielded output note commitments and oversized
  encrypted-note ciphertext blobs at bundle-structure validation time.
- `src/shielded/bundle.cpp` now also rejects undersized shielded output ciphertexts
  (`< AEADChaCha20Poly1305::EXPANSION`) at bundle-structure validation time, preventing
  consensus-accepted malformed outputs that cannot pass authenticated decryption.
- `src/shielded/note_encryption.cpp` now rejects undersized AEAD ciphertext before ML-KEM decapsulation
  to avoid unnecessary expensive decapsulation work on obviously malformed payloads.
- `src/shielded/validation.cpp` now prevalidates ring-member positions before MatRiCT proof parsing
  in `CShieldedProofCheck`, so malformed/out-of-range rings fail early without unnecessary proof decode work.
- `src/validation.cpp` now applies an equivalent ring-position precheck in mempool and block admission
  paths before spend-auth proof parsing, reducing CPU exposure to malformed shielded spends while preserving
  anchor-first rejection semantics in mempool policy.
- Added regression tests:
  - `src/test/shielded_tx_check_tests.cpp`: duplicate note commitment rejection.
  - `src/test/shielded_tx_check_tests.cpp`: undersized encrypted-note ciphertext rejection.
  - `src/test/note_encryption_tests.cpp`: undersized ciphertext decryption rejection.
  - `src/test/shielded_validation_checks_tests.cpp`: invalid ring position remains the reject reason
    even when proof bytes are malformed.

## Production Readiness Statement

The codebase is significantly hardened and test-backed for the currently implemented shielded surface, but it is **not yet production-ready** without:

1. External cryptographic audit for MatRiCT+ implementation details.
2. Side-channel audit of ML-KEM integration on release compiler/CPU targets.
3. Continued upstream security backport review for new Bitcoin Core disclosures.
4. Dependency maintenance plan for PQClean archival/deprecation risk.
