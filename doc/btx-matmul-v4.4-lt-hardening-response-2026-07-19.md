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
| §5 Cryptographic extractor replacement | **Acted (candidate)** — SplitMix replaced by domain-separated ChaCha20 PRF Extract under ENC_BMX4C_LT; SplitMix retained for differential tests; golden vectors frozen. External C-15 review still required before activation (not closed). |
| §6 / §8 Adaptive limbs / Strassen tournament | **Acted (miner-local)** | Public exact baselines: deferred `ComputeCombineModQ`, `ComputeCombineAdaptiveLimbBMX4C` / base-256 + two-limb routes, Karatsuba-9; CPU tournament harness + `doc/btx-matmul-v4.4-combine-algorithm-tournament.md`. Integer transcript unchanged (byte-identical tests). ASERT still calibrates to fastest known exact after silicon measure. |
| §12–14 Native IMMA/MFMA/MXFP4/Metal MPP | INT8 IMMA/MFMA residency is now broader (including radix `Y·H` and Karatsuba combine), but native MXFP4 remains a real gap. Logical MX components and planner labels are not hardware execution; keep native stubs fail-closed. |

## §4 Header-PoW wire redesign (**WITHDRAWN** 2026-07-19 — activation hard NO-GO)

**Problem (original):** `BTX_ENABLE_HEADER_NONCE_ON_WIRE` made Header-PoW wire format build-dependent.

**Attempted fix (withdrawn):** self-describing `nVersion` bit 26 appending `nNonce` (+4 → 186) and folding it into `GetHash()`.

**Confirmed defect:** bit 26 was previously legal for miners to set. Pre-activation, old nodes always read 182-byte headers while new nodes demanded 186 whenever the bit was set — an immediate consensus/wire split. A historical chain scan cannot fix that; the design itself is unsafe.

**Current posture (this tree):**

1. **Fixed 182-byte wire** — `SERIALIZE_METHODS` never appends `nNonce`; bit 26 does not change framing.
2. **Fixed 182-byte `GetHash()`** — `nNonce` is never folded into identity.
3. **Spam gate (when enabled in tests)** — `H(GetHash() || nNonce)` with `nNonce` local/decoupled. **Not safe to enable on public nets** until a height-contextual wire carries `nNonce`.
4. **`SerializeWithNonce` / `UnserializeWithNonce`** — **TEST-ONLY** helpers; not consensus wire.
5. **`ComputeBlockVersion` / miner** — do **not** OR bit 26.
6. **Activation** — HeaderPoW commitment-format activation remains a **hard NO-GO** regardless of arithmetic / LT fixes. Public heights stay `INT32_MAX`.

**Required before any retry:** height-contextual (de)serialization (or another design that keeps all pre-activation peers byte-identical), not a free version bit.

## Documentation posture

Prefer: exact reference available · logical MX-compatible layout · actual
execution dtype named separately (CPU integer, dense INT8 IMMA/MFMA, or a
future self-qualified native MXFP4 kernel) · C-15 external review open ·
direct-product assumption open · fastest-known-as-of-date · activation inert.

Remove/qualify: “C-15 closed”, “no cheaper mathematical path”, “12.5% shortcut cap”, “software-complete” for native tensor lanes, “device-resident” without “scalar GEMM today”.
