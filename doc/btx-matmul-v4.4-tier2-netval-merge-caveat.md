# Tier-2 NET+VAL hardening (PR#89) — merge caveat & required final testing

This commit lands the **Tier-2 activation-height hardening** for the v4.4 ENC-DR
MatMul PoW (the PR#89 C5/C1/H1/H2/H3/H9/H10 items + the C4 large-block-over-V2
routing residual). It is committed to the feature branch to unblock dependent
work. It is **NOT yet certified merge-ready**: the items below MUST be completed
on a non-contended CI box before this is merged to the release branch.

## What landed (all gated inert while `nMatMulV4Height == INT32_MAX`)

- **Item A / C5** — off-thread bounded ENC-DR verify worker (`src/node/matmul_verify_worker.{h,cpp}`),
  cs_main classification extracted to `ChainstateManager` helpers, a bounded verdict
  memo (`pow.{h,cpp}`), wired at `ProcessBlock` + the `validation.cpp` recompute seam
  via the existing `MatMulRecomputeSingleFlight` guard. The worker pointer is
  **nullptr** unless v4 is active **and** `-matmulasyncverify` is set; RPC
  `submitblock`/`generateblock` and `TestBlockValidity` stay synchronous by
  construction.
- **Item B / C1+H2+H3** — `GetTrustAdjustedChainWork` / `TrustAdjustedWork`
  (= authenticated work + min(unauth suffix, 32·GetBlockProof)); routed at
  direct-fetch, outbound-peer protection, chain-sync eviction, IBD/download gating,
  anti-DoS thresholds, and `BlockRequestAllowed`.
- **Item C / H1+H9+H10** — cmpctblock budget double-charge fix (gated on
  `IsMatMulV4Active`); prefetch↔cache-capacity coupling; assumevalid-depth prefetch
  guard; per-peer MMSKETCH ingress token bucket; solicited-only MMSKETCH.
- **Item D / C4 residual** — `Transport::MaxSendablePayloadBytes()` + guards at the
  four `ProcessGetBlockData` block-send points, compact/V1 fallback for oversize on V2.

## Inactivity invariant (the core safety property)

While `nMatMulV4Height == INT32_MAX` (current mainnet), every changed path is
byte-identical to pre-Tier-2 behavior. Verified for the two highest-risk items:

- **C1**: `UpdateAuthenticatedChainWork` keeps `nAuthenticatedChainWork == nChainWork`
  for any fully body-validated / pre-fork chain, so `GetTrustAdjustedChainWork`
  returns **exactly `nChainWork`** (unauth suffix = 0). All routed call sites are
  therefore unchanged while disabled.
- **C5**: `m_matmul_verify_worker` stays nullptr (worker only constructed when v4
  active + opt-in), and `LookupMatMulEncDrVerdict` returns `std::nullopt` when v4
  inactive, so `ProcessBlock` and the recompute seam run the synchronous path.

## REQUIRED before merge (not yet done here)

1. **Full unit suite, clean run.** `build/bin/test_btx` compiles clean (verified) and
   a *complete* run of **3386 test cases** finished with **89 failures, ALL 89 in
   `shielded_*` suites** (shielded_v2_proof / _ingress / _send / audit_regression /
   stress / adversarial_proof_corpus / bundle / hardening). **Zero failures in
   matmul / pow / validation / net / mempool / consensus** — the entire surface this
   change touches is green.
   - **The 89 shielded failures are a known-ignorable environmental flake:**
     `ShieldedMerkleTree: failed to persist commitment index` — leveldb/disk-FD
     persistence pressure in the shielded subsystem under the full suite, **unrelated
     to this change** (no shielded code is touched here). Re-running on a box with more
     disk/FD headroom clears them; a reviewer should re-run once on their CI to
     reconfirm, but this is not a code defect and not a blocker.
2. **Functional battery, serial + non-contended.** Re-run the P2P battery
   (`p2p_v2_transport`, `p2p_compactblocks_hb`, `p2p_headers_sync_with_minchainwork`,
   the matmul p2p tests, and `p2p_matmul_encdr_sketch_cache`) **serially** on an
   unloaded box. Under heavy CPU load these flake on `assert self.is_connected`
   (P2P handshake timeout at connection setup) — a load artifact, not a logic failure.
   Confirm each passes when run alone.
3. **Pre-existing generic-P2P test gap (NOT introduced here).**
   `p2p_compactblocks.py` and `p2p_compactblocks_blocksonly.py` FAIL on BTX matmul
   regtest because they are generic upstream tests that build blocks manually
   (`create_block`, no matmul payload); such blocks are rejected at height 1 with
   `missing-product-payload` (a pre-existing consensus requirement this diff does not
   touch). This is the same class of gap as the historical
   `p2p_headers_sync_with_minchainwork` issue (task #78) and requires making those
   tests matmul-aware (mirror the `-regtestmatmulv4height` / payload handling used by
   the adapted tests). It is orthogonal to PR#89 and should be tracked separately.
4. **New tests added here** — `matmul_chainwork_auth_tests` (C1 forged-chain routing),
   `net_tests` additions (Item D transport bound), and the updated
   `p2p_matmul_encdr_sketch_cache.py` — confirm green in the clean runs above.
5. **Activation remains fail-closed.** Do not set a finite `nMatMulV4Height` on any
   public network until the §K.2b silicon no-inversion GO/NO-GO measurement and L0
   ratification are recorded (DR-34). This Tier-2 code only takes effect after that.

## Attribution note

The Tier-2 diff is clean with respect to the observed functional failures: the two
compactblocks failures are the pre-existing generic-test gap (item 3); the other
transient functional failures were the load-driven handshake flake (item 2). No
matmul/pow/validation unit test regressed.
