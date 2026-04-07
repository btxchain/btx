<!-- Copyright (c) 2026 The BTX developers -->
<!-- Distributed under the MIT software license, see the accompanying -->
<!-- file COPYING or http://www.opensource.org/licenses/mit-license.php. -->

# BTX Shielded Online Threat Review (2026-03-05)

## Scope
This review maps public cryptographic guidance and known ring-signature/decoy pitfalls
to concrete BTX shielded mitigations and deterministic tests.

## Primary Sources Reviewed
1. MatRiCT+ paper (linkable lattice ring proofs and challenge structure)
   - <https://eprint.iacr.org/2021/545>
2. FIPS 204 (ML-DSA verification strictness and malformed-input handling)
   - <https://doi.org/10.6028/NIST.FIPS.204>
3. CRYSTALS-Dilithium v3.1 (deterministic-vs-randomized signing discussion)
   - <https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf>
4. Monero critical key-image verification bug writeup
   - <https://www.getmonero.org/2017/05/17/mitigating-the-critical-0.9.10-11-bug.html>
5. Monero decoy-selection chain-reaction analysis
   - <https://www.getmonero.org/resources/research-lab/pubs/MRL-0001.pdf>
6. Monero decoy-selection regression discussion (wallet2 `gamma_pick` edge case)
   - <https://github.com/monero-project/monero/issues/8872>
7. Dilithium side-channel key recovery from implementation leakage
   - <https://eprint.iacr.org/2022/106>
8. KyberSlash timing leakage overview
   - <https://kyberslash.cr.yp.to/>
9. NIST PQC conference paper on single-trace Dilithium attacks
   - <https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/single-trace-side-channel-attacks.pdf>
10. Ring signatures over module lattices (attack/parameter discussion context)
   - <https://eprint.iacr.org/2025/820>
11. Fiat-Shamir with aborts side-channel discussion
   - <https://eprint.iacr.org/2019/715>
12. Decoy set reduction analysis in ring-signature ecosystems
   - <https://arxiv.org/abs/2408.06285>
13. Rejection-leakage attacks on Fiat-Shamir-with-aborts style signatures
   - <https://eprint.iacr.org/2025/582>
14. NIST FIPS 203 final (ML-KEM)
   - <https://csrc.nist.gov/pubs/fips/203/final>
15. NVD CVE entry for KyberSlash-class timing leakage
   - <https://nvd.nist.gov/vuln/detail/CVE-2024-36405>
16. Bitcoin Core upstream security advisories (cross-project CVE posture)
   - <https://bitcoincore.org/en/security-advisories/>
17. Bitcoin Core disclosure details for recent malformed-message DoS class
   - <https://bitcoincore.org/en/2025/08/20/disclose-mutated-blocksonly-rpc/>
18. Bitcoin Core disclosure details for stale-data relay bug class
   - <https://bitcoincore.org/en/2025/10/20/disclose-minv_stale_data/>
19. LinkableSMILE (recent ring-signature design/size/security tradeoff discussion)
   - <https://eprint.iacr.org/2024/553>
20. Monero decoy-selection skew discussion (`gamma_pick` truncation edge case)
   - <https://github.com/monero-project/monero/issues/7807>

## Risks Mapped To BTX
1. Response-distribution leakage around the real index
- Risk: narrow decoy responses can make real-index responses statistically distinguishable.
- Mitigation: signer now samples decoy/masking responses from a full bounded range
  and retains rejection checks on real responses.
- Code: `src/shielded/ringct/ring_signature.cpp`
- Deterministic check: `ringct_ring_signature_tests/response_distribution_limits_real_index_bias`

2. Cross-input linkability through shared signer key material
- Risk: if witness secrets are derived directly from ring composition, key-image and signer-key behavior
  can become brittle across wallet flows.
- Mitigations:
  - production signing secrets are now derived from wallet spend key material plus full note state
    (`DeriveInputSecretFromNote`), not from `spending_key + ring_member` alone;
  - `CreateMatRiCTProof` now passes explicit per-input secrets into ring signing;
  - wallet note tracking nullifiers are derived via the same note-bound secret flow
    (`DeriveInputNullifierForNote`) for consistency.
- Code:
  - `src/shielded/ringct/ring_signature.cpp`
  - `src/shielded/ringct/matrict.cpp`
  - `src/wallet/shielded_wallet.cpp`
- Deterministic checks:
  - `ringct_ring_signature_tests/derive_input_nullifier_changes_with_key_and_member`
  - `ringct_matrict_tests/create_verify_matrict_roundtrip`

2b. Cross-input decoy intersection risk ("chain reaction" style analyses)
- Risk: reusing decoy sets across multiple inputs can reduce effective anonymity under intersection analysis.
- Mitigations:
  - wallet ring selection now supports deterministic exclusion lists;
  - spend construction excludes previously selected ring positions across inputs when tree size permits;
  - selector now preserves required per-input diversity (`min(tree_size, ring_size)`) even under saturated exclusions.
- Code:
  - `src/shielded/ringct/ring_selection.cpp`
  - `src/wallet/shielded_wallet.cpp`
  - `src/shielded/validation.cpp`
- Deterministic checks:
  - `ring_selection_tests/select_ring_positions_with_exclusions_avoids_overlap_when_possible`
  - `ring_selection_tests/select_ring_positions_with_exclusions_is_deterministic`
  - `ring_selection_tests/select_ring_positions_with_exclusions_preserves_diversity_target`

3. Malleability/forgery surface from malformed ring material
- Risk: duplicate ring members and malformed challenge decomposition increase attack surface.
- Mitigations:
  - reject null ring members in each ring during create and verify;
  - apply slot-domain separation in derived ring public keys so duplicate commitments
    do not alias to identical derived key material;
  - enforce consensus-level minimum ring-position diversity from tree state
    (`bad-shielded-ring-member-insufficient-diversity`);
  - challenge scalar derivation now uses rejection-rehash without modulo fallback.
- Code: `src/shielded/ringct/ring_signature.cpp`
- Deterministic checks:
  - `ringct_ring_signature_tests/duplicate_ring_members_use_slot_domain_separation`
  - `ringct_ring_signature_tests/null_ring_members_are_rejected`
  - `ringct_ring_signature_tests/verify_rejects_null_member_ring`
  - `ringct_ring_signature_tests/challenge_chain_tamper_detected`

3b. Single-offset structural correlation
- Risk: one offset shared across all ring members can create unnecessary structure in effective-key equations.
- Mitigation: ring signatures now carry per-member offsets per input (`member_public_key_offsets`)
  and verification uses member-specific effective keys.
- Code: `src/shielded/ringct/ring_signature.h`, `src/shielded/ringct/ring_signature.cpp`
- Deterministic checks:
  - `ringct_ring_signature_tests/public_key_offset_tamper_detected`
  - `ringct_ring_signature_tests/public_key_offset_intersection_is_input_localized`

4. Secret persistence in process memory
- Risk: witness vectors retained after signing path returns.
- Mitigation: witness vectors are explicitly wiped via `memory_cleanse`,
  including failed-attempt response buffers and ephemeral `alpha` masks.
- Code: `src/shielded/ringct/ring_signature.cpp`

5. Rejection-path instability under bounded serialization constraints
- Risk: large secret/challenge products can cause impossible bounded responses and unstable signing retries.
- Mitigation: witness secret coefficient bound tightened to `eta=2` so
  `eta * BETA_CHALLENGE < RESPONSE_NORM_BOUND` holds with deterministic guard.
- Code: `src/shielded/ringct/ring_signature.cpp`

6. Side-channel pressure from data-dependent signing internals (timing/power literature)
- Risk: modern PQ implementations have repeatedly shown key leakage from subtle variable-time or
  data-dependent micro-operations.
- Mitigations applied in this pass:
  - removed centered-binomial rejection sampler from ring responses in favor of direct bounded sampling;
  - tightened secret bounds to keep response equations in bounded domain;
  - explicit witness cleansing after use;
  - introduced hedged signer entropy support so production signing can mix strong runtime entropy
    with deterministic transcript inputs (`CreateRingSignature(..., rng_entropy)`).
- References motivating this hardening:
  - <https://eprint.iacr.org/2022/106>
  - <https://kyberslash.cr.yp.to/>

7. ML-KEM compiler/constant-time caveat (CVE-2024-37880 class)
- Risk: compiler transformations can re-introduce branches around conditional moves in Kyber/ML-KEM code paths.
- Mitigation: added `PQCLEAN_PREVENT_BRANCH_HACK(b)` guard to `PQCLEAN_MLKEM768_CLEAN_cmov_int16`
  in `src/crypto/ml-kem-768/verify.c`, matching the existing hardening style already used in `cmov`.
- Reference:
  - <https://nvd.nist.gov/vuln/detail/CVE-2024-37880>

8. Proof-processing DoS surface from oversized ring input vectors
- Risk: expensive ring processing can be forced if oversized input vectors bypass upper bounds in helper APIs.
- Mitigation: explicit create/verify guards now reject `input_count > MAX_RING_SIGNATURE_INPUTS`
  in `CreateRingSignature` and `VerifyRingSignature` (defense in depth on top of higher-level limits).

9. ML-KEM branch-hardening and note payload safety
- Risk:
  - compiler branch insertion in `poly_frommsg` bit handling can weaken constant-time behavior;
  - unbounded runtime ciphertext vectors and plaintext lifetime can increase memory/DoS exposure.
- Mitigations:
  - added `PQCLEAN_PREVENT_BRANCH_HACK(b)` at `poly_frommsg` bit extraction in
    `src/crypto/ml-kem-768/poly.c` (in addition to `cmov_int16` hardening);
  - `TryDecrypt` now rejects runtime ciphertext payloads larger than
    `EncryptedNote::MAX_AEAD_CIPHERTEXT_SIZE`;
  - note plaintext buffers are explicitly cleansed after encryption/decryption paths.
- Deterministic check:
  - `note_encryption_tests/trydecrypt_rejects_oversized_runtime_ciphertext_payload`

10. Degenerate witness material and duplicate input secrets
- Risk:
  - zero-valued witness vectors and duplicated input-witness material can create malformed proofs
    and unnecessary cross-input linkage pressure.
- Mitigations:
  - `DeriveInputSecretFromNote` now rejects spending keys shorter than 32 bytes and rejects
    all-zero derived witness vectors;
  - `CreateRingSignature` now rejects zero-norm witness vectors at the API boundary;
  - `CreateRingSignature` now rejects duplicate witness vectors across inputs using
    commitment-hash fingerprints before challenge-chain construction.
- Code: `src/shielded/ringct/ring_signature.cpp`
- Deterministic checks:
  - `ringct_ring_signature_tests/derive_input_secret_from_note_requires_32_byte_key_and_nonzero_secret`
  - `ringct_ring_signature_tests/create_rejects_zero_input_secret`

11. ViewGrant runtime payload bounds outside serializer paths
- Risk:
  - malformed in-memory `CViewGrant` objects can bypass tx deserialization limits and trigger
    oversized allocation/work in decrypt paths.
- Mitigations:
  - `CViewGrant::Decrypt` now rejects payloads larger than
    `MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE` before ML-KEM decapsulation/AEAD handling.
- Code: `src/shielded/bundle.cpp`
- Deterministic checks:
  - `shielded_transaction_tests/view_grant_roundtrip_encrypt_decrypt`
  - `shielded_transaction_tests/view_grant_decrypt_rejects_oversized_runtime_payload`
  - `shielded_transaction_tests/view_grant_decrypt_rejects_underflow_payload`

12. Effective public-key collision hardening in ring verification
- Risk:
  - malformed `member_public_key_offsets` can force two ring slots to collapse to the same
    effective public key (`pk_j + offset_j`), reducing practical anonymity and creating
    avoidable structural ambiguity.
- Mitigations:
  - verifier transcript construction now rejects any input where effective public keys are
    not pairwise unique across ring members;
  - signer path now enforces the same uniqueness invariant before producing proofs.
- Code: `src/shielded/ringct/ring_signature.cpp`
- Deterministic checks:
  - `ringct_ring_signature_tests/duplicate_effective_public_keys_rejected`

13. Additional online refresh (2026-03-05)
- Primary-source checks reviewed in this pass:
  - Bitcoin Core security advisories + disclosures (`CVE-2025-54604`, `CVE-2025-54605`);
  - KyberSlash attack site and paper links;
  - IACR ePrint `2017/995` (rejection-sampling/timing pitfalls);
  - IACR ePrint `2024/2051` (power-analysis on lattice KEM implementations).
- Result:
  - no new external disclosure required immediate consensus-rule changes in this branch;
    mitigations stayed focused on implementation hardening (bounds checks, uniqueness
    invariants, deterministic negative tests).

14. CTV malleability risk on partial shielded commitment
- Risk:
  - template-constrained spends could remain malleable if CTV commits only to selected
    shielded fields and not the full bundle transcript.
- Mitigation:
  - `m_ctv_shielded_bundle_hash` now commits to full shielded bundle payload:
    `value_balance`, `shielded_inputs`, `shielded_outputs`, `view_grants`, and `proof`.
- Code:
  - `src/script/interpreter.cpp`
  - `src/test/pq_consensus_tests.cpp`
- Deterministic checks:
  - `ctv_hash_commits_to_shielded_bundle_fields` now verifies hash changes on mutation of
    `ring_positions`, `view_grants`, and `proof` in addition to commitments/nullifiers.

15. Network deserialization allocation guard for `shieldeddata`
- Risk:
  - unbounded compact-size vector declarations can trigger excessive allocation/work in
    message parsing (class similar to recent Bitcoin Core deserialization-DoS disclosures).
- Mitigation:
  - `ShieldedBlockData` now enforces `MAX_SHIELDEDDATA_BUNDLES_PER_MSG` during
    deserialization before vector allocation/growth;
  - sender path also refuses to relay payloads over this bundle-count bound.
- Code:
  - `src/net_processing.cpp`
  - `test/functional/p2p_shielded_relay.py`
- Deterministic checks:
  - `p2p_shielded_relay.py` now sends a crafted `shieldeddata` payload with
    `bundle_count = MAX_SHIELDEDDATA_BUNDLES_PER_MSG + 1` and asserts disconnect with
    deserialization-error logging.

16. Service-flag bypass via legacy `tx` transport
- Risk:
  - non-`NODE_SHIELDED` peers could send shielded transactions via legacy `tx`
    instead of `shieldedtx`, bypassing service-gating expectations.
- Mitigation:
  - inbound policy now rejects any transaction carrying a shielded bundle when
    peer lacks shielded relay capability, independent of command type.
- Code:
  - `src/net_processing.cpp`
  - `test/functional/p2p_shielded_relay.py`
- Deterministic checks:
  - functional relay test now verifies disconnect for non-shielded peers sending
    shielded payload via both `shieldedtx` and legacy `tx` commands.

17. Log-flood pressure on invalid shielded anchor paths
- Risk:
  - high-rate invalid shielded transactions/blocks with bad anchors could force
    unconditional `LogPrintf` writes and amplify disk pressure.
- Mitigation:
  - changed shielded anchor reject logging from unconditional prints to debug-category
    logs (`BCLog::MEMPOOL` / `BCLog::VALIDATION`), preserving diagnostics without
    default-log flood behavior.
- Code:
  - `src/validation.cpp`

18. Early deserialization allocation pressure in shielded bundle payloads
- Risk:
  - compact-size declared vectors can force large intermediate allocation/work before
    consensus validation if bounds are not enforced directly in bundle (de)serialization.
- Mitigation:
  - `CShieldedBundle` now enforces max counts/size during `Serialize` and `Unserialize`
    for `shielded_inputs`, `shielded_outputs`, `view_grants`, and `proof`.
- Code:
  - `src/shielded/bundle.h`
  - `src/test/shielded_transaction_tests.cpp`
  - `src/test/shielded_tx_check_tests.cpp`
  - `src/test/shielded_validation_checks_tests.cpp`
- Deterministic checks:
  - `shielded_bundle_serialize_rejects_oversized_inputs`
  - `shielded_bundle_serialize_rejects_oversized_outputs`
  - `shielded_bundle_serialize_rejects_oversized_view_grants`
  - `shielded_bundle_serialize_rejects_oversized_proof`
  - `shielded_bundle_unserialize_rejects_oversized_inputs`
  - `shielded_bundle_unserialize_rejects_oversized_outputs`
  - `shielded_bundle_unserialize_rejects_oversized_view_grants`
  - `shielded_bundle_unserialize_rejects_oversized_proof`

19. Wallet SQLite attack-surface hardening (2026-03-06 dependency refresh)
- Risk:
  - wallet DB engines are high-value targets; schema-level features and trigger-capable
    runtime behavior can increase blast radius if a corrupted or malicious DB file is opened.
- Mitigations:
  - wallet SQLite initialization now enables defensive mode (`SQLITE_DBCONFIG_DEFENSIVE`)
    when supported by the runtime;
  - trusted-schema execution is disabled via both db-config and pragma
    (`SQLITE_DBCONFIG_TRUSTED_SCHEMA`, `PRAGMA trusted_schema=OFF`);
  - failures in these hardening steps are fail-closed at DB-open time.
- Code:
  - `src/wallet/sqlite.cpp`
- Validation:
  - full unit/integration run (`ctest --output-on-failure -j8`);
  - full functional run (`test/functional/test_runner.py -j 8`);
  - production readiness checklist (`scripts/verify_btx_production_readiness.sh`).

## End-to-End Validation Run
Executed after applying all mitigations:
```bash
cmake --build build --target test_btx btxd -j8
build/bin/test_btx --run_test=ringct_ring_signature_tests,ringct_matrict_tests --log_level=message
build/bin/test_btx --run_test=shielded_transaction_tests,shielded_tx_check_tests,shielded_validation_checks_tests --log_level=message
build/bin/test_btx --run_test=note_encryption_tests,ringct_ring_signature_tests,ringct_matrict_tests,ring_selection_tests,shielded_validation_checks_tests --log_level=message
python3 test/functional/test_runner.py \
  wallet_shielded_send_flow.py \
  wallet_shielded_restart_persistence.py \
  wallet_shielded_reorg_recovery.py \
  wallet_shielded_viewingkey_rescan.py \
  wallet_shielded_encrypted_persistence.py \
  wallet_shielded_anchor_window.py \
  wallet_shielded_rpc_surface.py \
  p2p_shielded_relay.py \
  --combinedlogslen=0
cd build && ctest --output-on-failure -j8
```

## Residual Audit Gap
These mitigations reduce practical implementation risk but do not replace a formal third-party
lattice cryptography audit against MatRiCT+ assumptions and full side-channel review.
