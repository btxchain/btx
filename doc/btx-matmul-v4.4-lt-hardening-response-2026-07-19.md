# BTX v4.4-LT hardening response (2026-07-19)

Response to the external deficiency report. Recommendations were verified against the tree before acting. Public activation remains **inert** (`INT32_MAX`). Subsidy stays **hardware-independent**.

## Economic framing (accepted; no code change to subsidy)

Progressively more capable AI-native hardware receives progressively greater **expected** mining opportunity through higher exact seal throughput. Per-block subsidy and total issuance remain hardware-independent. No GPU-model fields, tensor attestations, FP4/FP8 bonus multipliers, or hardware-specific targets.

## Verified and acted on

| Report item | Verdict | Action |
|---|---|---|
| §1 Hardware subsidy multipliers | Correct — do not implement | Documented |
| §17 `BTX_MATMUL_LT_BATCH` alters seal Q* | **Confirmed** | Split `consensus_Qstar` vs `execution_chunk` in `SolveMatMulV4LT` |
| §18 LT pool share target | **Confirmed** | Pass `effective_target` into LT solve |
| §11 Accel nonce-only API | **Confirmed** (fail-closed before) | Batch only when seeds match; else per-complete-header device calls |
| §10 Phase-B regenerates template | **Confirmed** | `ComputeSealDigestBMX4CLT` uses prepared `WindowSketchMinerLT` + `MineSlot` |
| §7 Per-MAC Fq reduction | **Confirmed worthwhile** | `ComputeCombineModQ` deferred `__int128` + one reduce (byte-identical) |
| §15 Sync EncDr on msg thread | **Confirmed** | Saturated queue: defer/drop; never `ProcessBlockSync` EncDr |
| §16 Best-header raw chainwork | **Confirmed** | Trust-adjusted selection + descendant auth-work propagation |
| IBD unbounded expensive budget | **Confirmed** | Global leaf-unit budget always charged; IBD/fast-phase uses finite elevated ceiling (≥256) |
| Q* charged as 1 verification | **Confirmed** | `MatMulEncDrWorkUnits` = Q* in seal mode; pending/budget consume leaf units |
| V2-only blocktxn ceiling | **Confirmed** | Prefer full `BLOCK` fallback when blocktxn exceeds V2 payload; NOTFOUND only if BLOCK also too large |
| §3 Unified public activation | **Confirmed useful** | Public nets require `v4==bmx4c==drlt` + `seal_as_pow` when DRLT live |
| §13 Metal ARC `id<MTLBuffer>&` | **Confirmed** | `__strong&` ownership fix |
| §19 `VerifyWindowSlotFreivalds` | **Confirmed** unsafe as general API | Marked test/diagnostic-only |
| §5 / §25 C-15 / overclaims | **Confirmed** | Docs corrected (below) |
| §4 Header-PoW wire redesign | **Confirmed** | Version-bit self-describing wire + `GetHash` commit; cmake flag no-op (see §4 below) |
| Full 256-bit slot IDs | **Confirmed worthwhile** | `DeriveWindowSlotId` + seed/leaf bind + duplicate-id reject; `nNonce64 = ReadLE64(slot_id)` |
| §9 Q* algorithm enforcement | **Confirmed** | Docs: Q* = aggregate commitment only; slot-id binding is consensus |

## Verified but deferred (not yet better as consensus changes)

| Report item | Why deferred |
|---|---|
| §5 Cryptographic extractor replacement | SplitMix is weak as a PRF story; swapping extractor is a consensus transcript change — needs golden vectors + external review before activation. |
| §6 / §8 Adaptive limbs / Strassen tournament | **Acted (miner-local)** | Public exact baselines: deferred `ComputeCombineModQ`, `ComputeCombineAdaptiveLimbBMX4C` / base-256 + two-limb routes, Karatsuba-9; CPU tournament harness + `doc/btx-matmul-v4.4-combine-algorithm-tournament.md`. Integer transcript unchanged (byte-identical tests). ASERT still calibrates to fastest known exact after silicon measure. |
| §12–14 Native IMMA/MFMA/MXFP4/Metal MPP | Real gaps; keep fail-closed stubs; do not mislabel scalar kernels. Full tensor residency is Phase 3. |

## §4 Header-PoW wire redesign (**acted** 2026-07-19)

**Problem:** `BTX_ENABLE_HEADER_NONCE_ON_WIRE` made Header-PoW wire format build-dependent. Peers compiled differently would disagree on header bytes; `GetHash()` excluded `nNonce`, so grind/malleation could poison caches without changing block identity.

**Design (hard-fork appropriate; public heights remain `INT32_MAX`):**

1. **Self-describing format bit** — `CBlockHeader::BTX_HEADER_POW_COMMIT_VERSION_BIT` (`nVersion` bit 26). `SERIALIZE_METHODS` appends `nNonce` (+4 → 186 bytes) iff the bit is set. No height context needed at (de)serialize; mixed 182/186 headers in one `headers` message work.
2. **Canonical identity** — `GetHash()` folds `nNonce` when the bit is set. Post-activation, changing `nNonce` changes block identity.
3. **Activation** — rides unified v4 (`IsMatMulV4Active` / `nMatMulV4Height`). At/above: bit **required**. Below: bit **forbidden**. `ComputeBlockVersion` and `CreateNewBlock` set the bit automatically.
4. **HeaderPoW gate** — commitment form: `GetHash() <= eased_nBits_target`. Legacy (bit clear): `H(GetHash() || nNonce)`. `nNonce` stays out of `ComputeMatMulHeaderHash` either way.
5. **Compile flag** — `BTX_ENABLE_HEADER_NONCE_ON_WIRE` is a **deprecated no-op** for wire/consensus (may remain as a build tag). Both ON and OFF builds speak the same protocol.

**Not done here:** setting mainnet/testnet `nMatMulV4Height` finite, or enabling `nMatMulHeaderPoWDiscountBits` on public nets.

## Documentation posture

Prefer: exact reference available · scalar device fallback · native tensor unimplemented/qualified · C-15 external review open · direct-product assumption open · fastest-known-as-of-date · activation inert.

Remove/qualify: “C-15 closed”, “no cheaper mathematical path”, “12.5% shortcut cap”, “software-complete” for native tensor lanes, “device-resident” without “scalar GEMM today”.
