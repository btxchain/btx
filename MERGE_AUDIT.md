# v4.6 Fold — Merge & Loss/Revert Audit

**Branch:** `wip/v46-fold`
**Base (PR head lineage):** `origin/claude/matmul-v4-design-spec-af23sj` @ `4e945a2` (ci: disable GitHub Actions workflows) — its ancestors include `9c1fa6d` (V3 coupled activation) and `42ded4c` (warning fixes).
**Merged in (v4.6 stack):** `origin/wip/gkr-margin` @ `67a5e86` (margin: Q=128 / Fp2, composed ~71.9).
**True merge-base:** `42ded4c` (the warning-fixes commit is shared ancestry — the v4.6 stack was built on top of it).

> Lineage note: the task brief stated the PR head was `9c1fa6d` with `876e391` as the divergence
> point and `4e945a2` as an earlier commit. In the actual repo the PR-head tip is `4e945a2`
> (CI-disable) with `9c1fa6d` as its parent, and the real merge-base is `42ded4c`, not `876e391`.
> The branch was created from the PR-head tip (`4e945a2`) so BOTH `9c1fa6d`'s V3 activation AND
> the CI-disable are preserved; branching from `9c1fa6d` would have dropped the CI-disable.

---

## Conflict resolution (6 files)

All conflicts stemmed from `9c1fa6d` (V3 coupled activation); both lineages had independently
rewritten the coupled/accel-policy files. The GKR/FRI/AIR files did **not** conflict because the
PR-side warning fixes (`42ded4c`) are shared ancestry that the v4.6 hardening was built on top of.

| File | Conflict | Resolution |
|------|----------|------------|
| `src/pow.cpp` | 3 hunks + 1 duplicate decl | Both sides thread coupled options into `RecomputeCoupledPuzzleReference`/`TryMineRCCoupledBatch`. Standardized on the already-declared `options_coup`; removed the v46 duplicate `opts_coup` declaration (would have been an unused-variable warning). Kept v46's "Profile-selected domains (F7)" comment. |
| `src/matmul/matmul_v4_rc_coupled.cpp` | `ResolveRCCoupParams`, `ResolveRCCoupOptions` | Took the **v46 profile-based resolver** (`nMatMulRCCoupledProfile` switch: 2→V2, 3→V3, else fail-closed). It is a strict superset of 9c1fa6d's hard-wired `toy?…:V3` — profile 3 yields byte-identical V3 params/options. Forced: the auto-merged v46 `coupled_tests`/`pow_tests` depend on this selector and the `profile==2` default. Result = v46 parent verbatim. |
| `src/matmul/matmul_v4_rc_coupled.h` | 2 doc comments | Took v46's profile-matrix docs (match the resolver kept), appended the "public activation heights are not raised" note from the PR side. |
| `src/matmul/matmul_v4_rc_accel_policy.h` | struct doc comment | V3-default descriptor (9c1fa6d) + v46's projection/selector note. Struct body auto-merged to `v3_profile_enabled` + V3 defaults (base==v46 for the struct, only 9c1fa6d changed it). |
| `src/matmul/matmul_v4_rc_accel_policy.cpp` | `MakeLegacyV1…` tail + v46-unique `MakeProductionV3RCCoupConsensusConfig` + `RCCoupParamsFromConsensusConfig` comment | Kept the v2→v3 field rename (9c1fa6d) **and** grafted in v46's `MakeProductionV3RCCoupConsensusConfig`, adapted to `v3_` naming (`v3_profile_enabled=true`, `material_exchange_rounds=4`). Kept v46's explicit `transcript_version=ENC_RC_V1` in the legacy config (== struct default, harmless). |
| `src/test/matmul_v4_rc_accel_policy_tests.cpp` | `rc_coup_consensus_config_defaults_ai_production` | Took the 9c1fa6d **V3** assertion set (config_version=V3, `v3_profile_enabled`, `material_exchange_rounds`, `RCCoupOptionsFromConsensusConfig`). The `RCCoupConsensusConfig` descriptor is non-consensus (used only by accel-policy + tests, never by `pow.cpp`), so the V2↔V3 default choice is safe for block validation. |

### Fix applied during the fold (not a mechanical resolution)

`src/test/matmul_v4_rc_coupled_tests.cpp` — **auto-merged but semantically broken.** 9c1fa6d's added
test `rc_coup_public_activation_resolves_v3_production_profile` builds a default `Consensus::Params`
(profile field absent in 9c1fa6d's world) and asserts a non-toy activated node resolves to **V3
production**, including `resolved.bank_pages != medium.bank_pages`. Under the v46 resolver a default
`Params` has `nMatMulRCCoupledProfile == 2` → `MakeMediumRCCoupParams` (V2), so the test would FAIL.
This directly contradicts v46's `rc_coup_inactive_and_constants` (asserts default profile == 2) and the
mainnet `assert(nMatMulRCCoupledProfile == 2)`.
**Fix:** added `p.nMatMulRCCoupledProfile = 3;` to that test so it explicitly selects the V3 family.
This preserves BOTH v46's deliberate default (V2 = CI-safe stand-in, mainnet-asserted) AND 9c1fa6d's
full V3-production coverage (51 GiB / 96 GiB / 12 TiMAC / 4 GiB exchange, `exchange_rounds=4`).

---

## Loss / Revert Audit

### ☑ FRI v5 — PRESENT/OK
- Even/odd `f(x),f(-x)` half-domain fold: `src/matmul/matmul_v4_rc_fri.cpp:292-293`
  (`even=(f(x)+f(-x))/2`, `odd=(f(x)-f(-x))/(2x)`, `next=even+β·odd`).
- Blowup-sized **terminal constant-codeword** check (NOT vacuous fold-to-singleton): terminal
  layer size must equal `blowup` — `fri.cpp:509,525` (`terminal layer size != blowup`), `:663`
  (`final layer not blowup`); constant-leaf check `fri.cpp:531` (`terminal layer not constant`),
  `:683` (`MerkleRootConstantLayer(final_value, blowup)`); constant codeword bound `fri.cpp:750`.
- `kRCFriNumQueries = 128` — `src/matmul/matmul_v4_rc_fri.h:53`.
- `kRCFriBatchNumQueries = 128` — `src/matmul/matmul_v4_rc_fri.h:264`.

### ☑ Arbiter hard-disable — PRESENT & EFFECTIVE
- `inline constexpr bool kRCGkrFormalSoundnessReady = false;` — `src/matmul/matmul_v4_rc_gkr.h:64`.
- No env path re-enables: `EnvRCGkrArbiterEnabled()` (`gkr.cpp:2500-2508`) returns `false`
  unconditionally while `!kRCGkrFormalSoundnessReady` — `BTX_RC_GKR_ARBITER` is ignored (compile-time
  gate). Arbiter cutover probe `gkr.cpp:2505`: `if (!kRCGkrFormalSoundnessReady) return false;`.

### ☑ G1–G5 — PRESENT/OK
- Files present: `matmul_v4_rc_gkr_eval.{h,cpp}`, `matmul_v4_rc_gkr_air.{h,cpp}`,
  `matmul_v4_rc_gkr_wiring.{h,cpp}`, and the Fp3 module `matmul_v4_rc_gkr_field_ext3.h`
  (the "field_ext3" file — its actual name carries the `matmul_v4_rc_gkr_` prefix).
- `CheckWinnerProofRelationsV7` is called from `VerifyWinnerProofV7` — `gkr.cpp:2472`
  (function body `gkr.cpp:2311`+); impl at `gkr.cpp:1986` (`CheckWinnerProofRelationsV7Impl`).
- Five forgery→relation mappings intact: `enum class RCGkrRelation { G1..G5 }` (`gkr.h:617`),
  used across the relations checker as `fail(RCGkrRelation::G1)` (Construction I operand/PRF
  grounding), `G2` (layer claim), `G3` (Construction III LogUp membership), `G4` (Construction IV
  chained wiring), `G5` (residual). Failure strings carry the `v7:g<N>:<detail>` prefix.

### ☑ Composed separation ~71.9 (Fp2, honest — NOT phantom 76.8) — PRESENT/OK
- `RCGkrComposedSeparationBits()` — `gkr.cpp:2299` — returns
  `RCGkrComposedSeparationBits(kRCGkrFriProximityBitsV5)`, FS-subtotal-dominated at ≈ 71.9 bits.
  The 76.8 figure is documented in-code as the **FRI proximity floor** that needs the DEFERRED Fp3
  challenge cutover — it is NOT returned as the current composed value.
- Integration test `gkr_integration_composed_separation_bound` —
  `src/test/matmul_v4_rc_gkr_integration_tests.cpp:177`: asserts `composed_bits > 64` (:211),
  `> 71.0` (:212, actual ≈ 71.94), `< 72.0` (:213), and `!inadequate_margin` (:216, margin ≈ 7.9).

### ☑ V3 coupled resolver — PRESENT/OK (one test fixed, see above)
- `ResolveRCCoupOptions` present — `coupled.cpp:729` (profile switch).
- Activated non-toy → V3 (via profile 3): `ResolveRCCoupParams` → `MakeProductionV3RCCoupParams`
  (`rows_per_lobe = 128`, `coupled.cpp:661`); `ResolveRCCoupOptions` → `MakeV3RCCoupOptions`
  (`material_exchange = true`, `exchange_rows = 128`, `exchange_rounds = 4`, `coupled.cpp:670-672`).
- Reachability regression fixed in `coupled_tests.cpp` (profile=3 made explicit).

### ☑ int64 reference BYTE-IDENTICAL — PRESENT/OK
- `RecomputeCoupledPuzzleReference` (`src/matmul/matmul_v4_rc_coupled.cpp:1035/1050`) and
  `RecomputeResidentCurriculumReference` (`src/matmul/matmul_v4_rc.cpp`): the merged tree is
  **byte-identical to the v4.6 parent** — `git diff 67a5e86 -- matmul_v4_rc_coupled.cpp` and
  `-- matmul_v4_rc.cpp` both show **0 lines**. The fold introduced ZERO changes to the reference.
- Divergence vs the PR parent (`4e945a2`) is solely the v4.6 lineage's own evolution (A4/F10 wgrad
  int64-recombine in `Phase2MicroTraining`), which is int64-exact and is NOT the reference function.

### ☑ Heights INT32_MAX / golden gate / warning fixes — PRESENT/OK
- Heights: `nMatMulV4Height{INT32_MAX}` (`params.h:402`), `nMatMulRCHeight{INT32_MAX}` (:495),
  `nMatMulRCCoupledHeight{INT32_MAX}` (:512). Mainnet asserts
  `nMatMulRCCoupledHeight == INT32_MAX` and `nMatMulRCCoupledProfile == 2`
  (`src/kernel/chainparams.cpp:326,328`) — consistent with the resolver kept.
- Golden gate V1/V2/V3: `coupled.{h,cpp}` == v46 parent; `BTX_RC_COUP_*_V1/_V2/_V3` domain tags and
  the V1/V2/V3 param makers are unchanged. Neither lineage altered a golden constant.
- Warning fixes (`42ded4c`) intact: `-Wswitch` — the five coupled-only kinds (`OmittedPages`,
  `DuplicatedPages`, `WrongM`, `WrongExchangeTranscript`, `CrossVersionReplay`) are handled in the
  episode malicious switch `gkr.cpp:1940-1944` (plus the v46 coupled constructors); `-Wunused-result`
  — `if (!DenseInt64GemmLocal(...)) { … return false; }` at `mx_ozaki.cpp:111`, and
  `DenseInt64GemmLocal` is `[[nodiscard]]` (`mx_ozaki.cpp:46`). No warning reintroduced.

---

## Guardrails — all honored
- int64 reference untouched by the fold (0-line diff vs v4.6 parent). ✔
- Heights INT32_MAX; mainnet coupled activation asserted inert. ✔
- Arbiter hard-disabled (`kRCGkrFormalSoundnessReady=false`, no env re-enable). ✔
- No adversarial/golden test weakened; the one test change (profile=3) makes a broken auto-merged
  assertion pass without loosening any check. ✔

**Status: MERGE COMPLETE — no items lost or reverted. One auto-merge semantic break fixed.**
**This branch goes to the rack for compile/validation BEFORE it touches the PR head.**
