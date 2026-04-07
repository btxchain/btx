# BTX Shielded Pool Simulated Audit Report (2026-03-05)

## Scope
This report summarizes simulated internal audits run on the shielded stack prior to PR submission.
The objective is to improve confidence and expose residual risks before independent external review.

Audited components:
- `src/shielded/ringct/ring_signature.cpp`
- `src/shielded/ringct/range_proof.cpp`
- `src/shielded/ringct/balance_proof.cpp`
- `src/shielded/ringct/matrict.cpp`
- `src/wallet/shielded_wallet.cpp`
- Shielded RPC and functional workflows under `test/functional/`

## Simulated Audit Methodology
1. Code-structure review
- Checked challenge chain construction and transcript binding logic.
- Checked nullifier/key-image binding and ring-member material derivation paths.
- Checked auditor/view-key RPC behavior and spendability boundaries.

2. Negative/tamper testing
- Added tamper test for `public_key_offsets` to ensure verification fails on modification.
- Re-ran existing challenge/response tamper and forgery rejection tests.

3. End-to-end functional simulation
- Shielding, spending, merge, reorg, relay, encrypted persistence, and anchor-window scenarios.
- Viewing-key import/rescan and watch-only behavior validation.
- Explicit viewer transaction inspection and non-spendability assertion.

4. Regression run
- Full `ctest` execution on build artifacts.

## New Test Additions in This Iteration
1. Ring signature public-key-offset tamper resistance
- File: `src/test/ringct_ring_signature_tests.cpp`
- Test: `public_key_offset_tamper_detected`
- Expected behavior: any offset mutation invalidates signature verification.

2. Ring member hygiene and malformed ring rejection
- File: `src/test/ringct_ring_signature_tests.cpp`
- Tests:
  - `duplicate_ring_members_use_slot_domain_separation`
  - `null_ring_members_are_rejected`
  - `verify_rejects_null_member_ring`
- Expected behavior: signer and verifier reject malformed (null) ring members deterministically,
  while duplicate commitments are slot-domain-separated to prevent derived-key aliasing.

3. Auditor viewing-key capability/non-spendability checks
- File: `test/functional/wallet_shielded_viewingkey_rescan.py`
- Added checks:
  - `z_viewtransaction` on viewer wallet exposes owned output data.
  - watch-only viewer cannot construct spends (`z_sendmany` fails).

4. Hedged entropy and bounds-hardening checks
- Files:
  - `src/test/ringct_matrict_tests.cpp`
  - `src/test/ringct_ring_signature_tests.cpp`
- Tests:
  - `hedged_entropy_changes_signature_but_verifies`
  - `hedged_entropy_changes_matrict_proof_but_verifies`
  - `rejects_oversized_input_count`

5. Note encryption payload safety checks
- File: `src/test/note_encryption_tests.cpp`
- Test: `trydecrypt_rejects_oversized_runtime_ciphertext_payload`
- Expected behavior: runtime-constructed oversized ciphertext buffers are rejected before decryption work.

6. Input-secret hardening checks
- File: `src/test/ringct_ring_signature_tests.cpp`
- Tests:
  - `derive_input_secret_from_note_requires_32_byte_key_and_nonzero_secret`
  - `create_rejects_zero_input_secret`
- Expected behavior:
  - witness derivation rejects undersized spending-key material and zero-valued witness vectors;
  - signer rejects explicit zero-valued input witnesses before transcript generation.

7. ViewGrant decrypt-path bounds hardening checks
- Files:
  - `src/shielded/bundle.cpp`
  - `src/test/shielded_transaction_tests.cpp`
- Tests:
  - `view_grant_roundtrip_encrypt_decrypt`
  - `view_grant_decrypt_rejects_oversized_runtime_payload`
  - `view_grant_decrypt_rejects_underflow_payload`
- Expected behavior:
  - valid selective-disclosure payloads decrypt correctly for intended operator key material;
  - malformed in-memory oversized payloads are rejected before decrypt processing.

8. Effective-public-key collision rejection checks
- Files:
  - `src/shielded/ringct/ring_signature.cpp`
  - `src/test/ringct_ring_signature_tests.cpp`
- Test:
  - `duplicate_effective_public_keys_rejected`
- Expected behavior:
  - verifier rejects signatures where two ring slots are tampered to the same effective
    public key (`pk_j + offset_j`), preserving ring-member distinctness.

9. CTV full shielded-bundle commitment checks
- Files:
  - `src/script/interpreter.cpp`
  - `src/test/pq_consensus_tests.cpp`
- Coverage:
  - `ctv_hash_commits_to_shielded_bundle_fields` now validates CTV hash changes when mutating
    `ring_positions`, `view_grants`, and `proof` fields, in addition to note commitments/nullifiers.

10. `shieldeddata` deserialization cap checks
- Files:
  - `src/net_processing.cpp`
  - `test/functional/p2p_shielded_relay.py`
- Coverage:
  - `shieldeddata` parser now rejects payloads declaring more than
    `MAX_SHIELDEDDATA_BUNDLES_PER_MSG`;
  - functional test injects oversized `bundle_count` payload and asserts peer disconnect
    with deserialization-error logging.

11. Legacy `tx` service-gate bypass checks
- Files:
  - `src/net_processing.cpp`
  - `test/functional/p2p_shielded_relay.py`
- Coverage:
  - inbound shielded-bundle gating now applies regardless of transport command;
  - functional test asserts disconnect for non-shielded peers sending shielded
    payload via both `shieldedtx` and `tx`.

12. Shielded anchor reject-path log-flood hardening
- Files:
  - `src/validation.cpp`
- Coverage:
  - replaced unconditional `LogPrintf` on bad shielded anchors with debug-category
    logs to reduce default log-file amplification from attacker-triggered invalid data.

13. Shielded bundle serializer/deserializer bounds hardening
- Files:
  - `src/shielded/bundle.h`
  - `src/test/shielded_transaction_tests.cpp`
  - `src/test/shielded_tx_check_tests.cpp`
  - `src/test/shielded_validation_checks_tests.cpp`
- Coverage:
  - enforced early hard bounds in `CShieldedBundle` (de)serialization for
    inputs/outputs/view-grants/proof before expensive processing;
  - added deterministic over-limit serialize/unserialize tests;
  - updated pre-existing tx-check and spend-auth tests to assert the new
    earlier rejection point (serialization exception).

## Simulated Audit Results
Status: PASS (for all executed internal checks and test suites listed below).

Executed checks:
- Shielded functional suites:
  - `wallet_shielded_send_flow.py`
  - `wallet_shielded_restart_persistence.py`
  - `wallet_shielded_reorg_recovery.py`
  - `wallet_shielded_viewingkey_rescan.py`
  - `wallet_shielded_encrypted_persistence.py`
  - `wallet_shielded_anchor_window.py`
  - `wallet_shielded_rpc_surface.py`
  - `p2p_shielded_relay.py`
- Full C++ test matrix via `ctest --output-on-failure -j8`
- Stress/perf subset via `bench_btx`:
  - `MatRiCTCreateBench`, `MatRiCTVerifyBench`
  - `RingSignatureCreateBench`, `RingSignatureVerifyBench`
  - `MLKEMKeyGenBench`, `MLKEMEncapsBench`, `MLKEMDecapsBench`
  - `NoteEncryptBench`, `NoteDecryptBench`
  - `ComplexMemPool`, `MempoolEviction`

## Findings
1. Ring-signature transcript/offset tampering
- Result: detected and rejected by verification.
- Mitigation confidence: medium-high via deterministic tests and tamper checks.
- Additional hardening applied in this iteration:
  - challenge scalar decomposition now uses rejection-rehash to avoid modulo bias;
  - production witness secret derivation now binds to full note state plus spend key material
    (`DeriveInputSecretFromNote`) rather than `spending_key + ring_member` only;
  - MatRiCT proof creation now passes explicit per-input witness secrets to ring signing;
  - wallet scanning/tracking derives spend nullifiers through the same note-bound secret flow
    (`DeriveInputNullifierForNote`) for deterministic consistency;
  - ring signatures now use per-member offsets per input (`member_public_key_offsets`)
    instead of one offset shared across all ring members;
  - ring-member validation rejects null members at signing and verification;
  - duplicate commitment slots are domain-separated in derived public keys;
  - consensus ring reconstruction enforces per-input diversity against tree size;
  - secret bounds are tightened (`eta=2`) to reduce impossible-response rejection behavior;
  - derived witness vectors are wiped with `memory_cleanse`, including failed-attempt response buffers.
  - wallet decoy selection uses cross-input exclusion lists while preserving minimum diversity targets.
  - ring signing supports hedged runtime entropy (wallet path now injects strong random entropy into
    signer RNG seed derivation while preserving deterministic test mode).
  - wallet spend construction now explicitly cleanses in-memory spend/master seed buffers on function exit.
  - PQClean ML-KEM `cmov_int16` now includes branch-prevention guard to reduce compiler branch-risk
    in line with CVE-2024-37880 class guidance.
  - ring signature create/verify now reject oversized input-count vectors (`> MAX_RING_SIGNATURE_INPUTS`)
    as an additional DoS guardrail.
  - ML-KEM `poly_frommsg` now applies branch-prevention hardening on bit extraction path;
    note encryption now enforces runtime ciphertext upper bounds and explicit plaintext cleansing.
  - ring-signature transcript construction now rejects duplicate effective public keys per input,
    and signer path enforces the same invariant before finalizing offsets.

2. Viewer/auditor usability boundary
- Result: viewer can recover balances and inspect transaction outputs after rescan.
- Result: viewer remains non-spendable, as required for audit-only operation.

3. Merge behavior caveat
- `z_mergenotes` currently depends on notes being spendable under one spending keyset in the same transaction.
- Functional tests now construct compatible note sets accordingly.

4. Online source refresh for ongoing threat posture
- Reviewed additional primary sources in this pass:
  - NIST FIPS 203 final publication;
  - KyberSlash publication site + linked paper set;
  - NVD CVE-2024-36405 (KyberSlash-class timing issue);
  - Bitcoin Core upstream security advisories page and disclosure pages
    (`CVE-2025-54604`, `CVE-2025-54605`);
  - IACR ePrint `2017/995`, `2024/2051`.
- Result: no newly disclosed upstream issue requiring immediate BTX consensus or wallet hotfix
  beyond already tracked side-channel hardening and external lattice audit requirements.

5. Additional hardening from this iteration
- CTV shielded binding upgraded from partial-field commitment to full-bundle commitment hash.
- P2P shielded block-data parsing now includes explicit compact-size count cap before
  vector allocation, addressing a known deserialization-DoS class.
- P2P shielded service-gating now rejects shielded bundles from non-shielded peers
  even when transported via legacy `tx`, closing a policy bypass.
- Shielded-anchor reject logging downgraded from unconditional prints to debug logs,
  reducing disk-fill risk under invalid-input spam.
- Shielded bundle serialization now rejects over-limit structure sizes before
  transaction materialization/validation, reducing allocation and parser-pressure
  surface for malformed payloads.

## Residual Risks and Required External Audits
This simulated audit does **not** replace independent cryptographic review.
Required external work remains:
- Formal security review versus MatRiCT+/ePrint 2021/545 assumptions.
- Side-channel/timing review for proof generation and verification paths.
- Independent conformance vectors and implementation review from third-party lattice cryptographers.
- Assessment of bespoke design choices (response sampling and key-material derivation flow) against desired formal model.
- Review of slot-domain-separated duplicate handling against full MatRiCT+ formal assumptions.

## Conclusion
Internal simulated audit and test execution indicate implementation stability and regression safety for covered scenarios.
Production viability still depends on external cryptographic sign-off and independent validation artifacts.
