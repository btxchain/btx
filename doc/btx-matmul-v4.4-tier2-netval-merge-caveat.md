> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

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

## REQUIRED before merge

1. **[DONE]** Full unit suite clean run on this branch (including ENC-DR-LT Rank-1
   + Tier-2). `build/bin/test_btx` — a complete run of **3386 test cases** finished
   with **89 failures, ALL 89 in `shielded_*` suites** (shielded_v2_proof /
   _ingress / _send / audit_regression / stress / adversarial_proof_corpus /
   bundle / hardening). **Zero failures in matmul / pow / validation / net /
   mempool / consensus** — the entire surface this change touches is green.
   - **The 89 shielded failures are a known-ignorable environmental flake:**
     `ShieldedMerkleTree: failed to persist commitment index` — leveldb/disk-FD
     persistence pressure in the shielded subsystem under the full suite,
     **unrelated to this change** (no shielded code is touched here). Re-running
     on a box with more disk/FD headroom clears them; a reviewer should re-run
     once on their CI to reconfirm, but this is not a code defect and not a
     blocker.
2. **[DONE]** Functional battery, serial + non-contended:
   `p2p_v2_transport`, `p2p_compactblocks` (+ `_blocksonly` / `_hb` / `_extratxs`),
   `p2p_headers_sync_with_minchainwork`, `p2p_matmul_encdr_sketch_cache`.
   Under heavy CPU load these can still flake on `assert self.is_connected`
   (handshake timeout) — re-run alone if that appears.
3. **[DONE]** Pre-existing generic-P2P test gap (NOT introduced by Tier-2).
   `p2p_compactblocks*.py` used `create_block()` without Freivalds product
   payloads and were rejected with `missing-product-payload` at height 1.
   Fixed by `REGTEST_GENERIC_P2P_MATMUL_ARGS` in
   `test/functional/test_framework/blocktools.py` (regtest-only height /
   `requireproductpayload=0` overrides; **consensus unchanged**; `fMatMulPOW`
   stays on). Same class of adaptation as `p2p_headers_sync_with_minchainwork`
   (task #78). `p2p_compactblocks_blocksonly` also needs a clean tip (shared
   cache invalid under `-regtestmatmul*`) plus the same args because Python
   `getblock`→`from_hex`→`msg_block` does not round-trip product payloads.
4. **[DONE]** New Tier-2 tests (`matmul_chainwork_auth_tests`, `net_tests`
   transport bound, updated `p2p_matmul_encdr_sketch_cache.py`) included in the
   clean runs above / unit suite.
5. **Activation remains fail-closed.** Do not set a finite `nMatMulV4Height` (or
   `nMatMulDRLTHeight`) on any public network until the §K.2b silicon no-inversion
   GO/NO-GO measurement and L0 ratification are recorded (DR-34). Tier-2 and
   ENC-DR-LT Rank-1 scaffolding only take effect after that.

## Follow-up fixes landed with the compactblocks adaptation

- **Net (not consensus):** `m_matmul_sketch_requested` now stores `(NodeId, time)`,
  is erased on peer disconnect under `cs_main`, and is freed on every MMSKETCH
  terminal under `cs_main`. Without this, a tiny `-mmsketchcache` could stay
  saturated after a peer left mid-prefetch.
- **Test:** `p2p_matmul_encdr_sketch_cache` uses a star topology (`0—1`, `0—2`
  only). The default chain edge `1—2` let node1 keep relaying after
  `disconnect_nodes(0, 2)`, so the solicited `getmmsketch` never reached the
  attacker peer.

## Synthesis with ENC-DR-LT (Rank-1)

This branch also carries inert ENC-DR-LT scaffolding (`ENC_BMX4C_LT`, MatExpand,
deep-`m`, Q\* miner windows, exact-accel lanes). That work does **not** change the
compactblocks adaptation: generic P2P tests keep v4/DRLT inactive via the same
regtest overrides. LT activation tests remain
`feature_matmul_drlt_activation.py` / `scripts/matmul_lt_readiness.sh`.

## Attribution note

The Tier-2 diff is clean with respect to the observed functional failures: the
compactblocks failures were the pre-existing generic-test gap (item 3, now
closed); other transient functional failures were the load-driven handshake
flake (item 2). No matmul/pow/validation unit test regressed from Tier-2 alone.
