# BTX MatMul v4.2 / BMX4-C — C-15 Independent Audit: Determinism / Consensus-Split & Verifier-DoS Lens

*Status: INDEPENDENT reviewer findings, one lens of a C-15 review panel. Scope: DETERMINISM /
consensus-split safety, verifier-DoS surface, spec↔implementation conformance. Reviewer did NOT
run git and edited no file except this one. Written 2026-07-16 (numair@daia.ai).*

Read set: `doc/btx-matmul-v4.2-consolidated-design.md`, `doc/btx-matmul-v4-exact-int-on-float.md`,
`doc/btx-matmul-v4-accumulator-eligibility.md`, `doc/btx-matmul-v4.2-consolidated-design.md` §4/§5.
Code set: `src/matmul/matmul_v4.cpp`, `src/matmul/int8_field.{h,cpp}`, `src/matmul/pow_v4.cpp`,
`src/matmul/accel_v4.cpp`, `src/pow.cpp` (v4 gates §3089–3142, packing §178–198), `src/validation.cpp`
(§9978–10177), `src/kernel/chainparams.cpp` (§568–574, §1214–1233).

---

## 0. Orientation — what is actually under review

The BMX4-C **design** (`btx-matmul-v4.2-consolidated-design.md`) is explicitly STAGED and
parameter-frozen: 𝓜₁₁ alphabet, E8M0 power-of-two scales, base-2⁶ limbs, `V42` domain tags, the
nibble-11/16 sampler, and scale-free 𝓜₁₁ U/V. **None of this is implemented.** The code in the repo
is entirely **v4.1 ENC-S8**: balanced-s8 operands in [−125, 125] (`kBalancedBound`), base-2⁷ limbs
(`kCombineLimbBase = 128`), `V4`/`V3` domain tags, byte-rejection sampling at threshold 251. This is
consistent with the doc's own posture (§10: golden vectors deliberately not generated until M-t24 and
the C-15 review land).

Therefore this review does two things: (1) audits the **shared verifier/combine machinery** that
BMX4-C will reuse byte-for-byte (the design's central claim is that this machinery is format-blind and
unchanged), and (2) checks whether the v4.2-specific determinism claims (E8M0 exact shift, base-2⁶
bound edge, nibble sampler) are sound *as designed*, flagging that they are **unverified-in-code**
pending implementation. The single most load-bearing structural fact, confirmed below, is that the
**entire committed-and-verified path is pure integer / F_q arithmetic with zero floating point** — so
the whole t=24/t≈14 accumulator question is a *throughput-eligibility* matter, never a chain-split
one.

---

## 1. Findings by severity

### F-1 (INFO / CLOSED-with-margin) — No-rounding completeness on the consensus path is structural, not argued

`grep` for `float|double|__fp16|_Float` across `int8_field.cpp`, `matmul_v4.cpp`, `pow_v4.cpp` returns
**nothing**. The consensus verifier `VerifySketch → SketchFreivalds` (matmul_v4.cpp:501) runs entirely
over F_q = 2⁶¹−1 (`FqAdd/FqMul/FqReduce`, all `uint64_t`/`unsigned __int128`) and over int8 operands;
it never forms C, never touches the limb combine, never touches FP. Determinism is pinned by
`static_assert(std::endian::native == std::endian::little)` (int8_field.cpp:17) plus integer-only
arithmetic (associative/commutative → order-independent, int8_field.cpp:112–123).

Consequence for the review mandate: the no-rounding theorem
(`btx-matmul-v4-exact-int-on-float.md` §2) is **only needed on the miner side**
(`matmul_v4_exact_float.*`, not on any consensus surface). Every FP-eligibility question — the C-1′
gate, t=24 vs t≈14, E8M0 exactness on real silicon — governs whether a *device* may run a native FP
path at full rate, and the dispatcher (`accel_v4.cpp:343–384`) plus the consensus verifier both
re-derive the honest operands and check the committed integers on the integer reference. A
mis-rounding device produces a wrong digest → discarded → CPU fallback. **It can lose throughput; it
cannot split the chain.** This is closed with large margin *for consensus*. The residual (M-t24) is a
throughput/eligibility measurement, not a safety gate — stated correctly in the design (§4.1, §10).

### F-2 (INFO / CLOSED) — C-1′ "fallback bit-identity" is structurally guaranteed, not a risk

The mandate asks whether the t=24 native path and the t≈14 INT8 fallback are "truly bit-identical."
The question is structurally inverted: there is no independent "native result" and "fallback result"
that must be reconciled. The **CPU integer reference is the sole source of truth**
(`btx-matmul-v4-accumulator-eligibility.md` §4-(1); design §4.3 "the CPU integer reference remains the
sole source of truth"). The dispatcher accepts a device result **iff** `VerifySketch` reproduces it
against the regenerated operands and the device digest equals `H(σ‖payload)`
(accel_v4.cpp:367). Any native/fallback path that does not land on the CPU-reference integers is
rejected. Bit-identity between two *conforming* exact paths is then a theorem (integer-matrix
associativity + unique canonical F_q residue, matmul_v4.cpp:426–439 / :354–360), not a device-behavior
assumption. Both the per-nonce and batched dispatchers implement the "verify every result, discard the
whole window on any mismatch" contract (accel_v4.cpp:428–470). **Closed.**

### F-3 (LOW → INFO / CLOSED for current code; SPEC-DEBT for v4.2) — the base-2⁷ combine bound is CORRECT and tight; the off-by-one flagged elsewhere is not in this function

`CheckCombineLimbBound` (matmul_v4.cpp:271–287) is the exact place the mandate's "base-2⁶ bound edge /
off-by-one" concern points at. **Result of the audit: the code is correct.** The four balanced
base-128 digits in [−64, 63] tile the contiguous, bijective range **[−135,274,560, +133,160,895]**
(128⁴ = 268,435,456 distinct values ↔ exactly that inclusive range), so the binding constraint for
symmetric P/Q entries |x| ≤ 15,625·n is the *positive* extreme. The function pins
`kLimbMaxPositive = 133'160'895` and returns `15,625·n ≤ 133,160,895` ⇒ **n ≤ 8522** — matching the
value that `btx-matmul-v4-exact-int-on-float.md` §3 flagged as the corrected bound, and pinned by
`matmul_v4_field_tests.cpp:235–238` / `matmul_v4_batch_tests.cpp:117–120` (8522 PASS, 8523 FAIL). The
"±2²⁷ symmetric" phrasing that the exact-float doc calls out is a *comment discrepancy in the redesign
prose*, not a defect in this function — the function's own comment and constant are the corrected
asymmetric value. At the production window (n = 4096, max entry 64M; n ≤ 8192, max entry 128M) the
decomposition is total with ≈1.04× margin over the tightest legit dimension. **No off-by-one defect in
the shipped code.**

The v4.2 successor is design-only and *not coded*: §5.2 re-pins to 4 balanced base-2⁶ digits with the
remainder-top rule, `288·n ≤ 2²³ − 1` ⇒ n ≤ 29,127, and internally corrects the redesign doc's
`8,255,527` to `8,255,455`. This is an open spec debt (design §11-item 9); when implemented it needs
its own exhaustive decomposition-totality test and regenerated golden vectors. Classification:
CLOSED for current code, conformance-gap for v4.2.

### F-4 (LOW) — latent limb-bound coupling: `DecomposeLimbPlanes` silently drops the remainder; totality rests on a coincidental `MAX_DIM < 8522` margin

`DecomposeLimbPlanes` (matmul_v4.cpp:321–337) extracts exactly 4 digits and **discards any residual
`x` with no hot-loop assert** ("Not asserted in the hot loop; pinned by the unit tests"). Totality is
guaranteed only when `CheckCombineLimbBound(n)` holds. Every *live* caller guards correctly — the CUDA
(cu:696), Metal (accel.mm:1371,1554), HIP (hip:574) backends and `matmul_v4_batch.cpp:24` all gate on
`CheckCombineLimbBound` and refuse/return on failure — and the **consensus verifier never decomposes
limbs at all** (SketchFreivalds is matvec-only). So a violation can at worst make a *miner* miscompute
Ĉ and self-reject via verify+fallback: throughput loss, not a split.

The latent hazard is a config footgun: `MATMUL_V4_ABS_MAX_DIM = 8192` (pow.cpp:168) is below the
limb-bound ceiling 8522 only by coincidence, and there is no static coupling asserting it. A future
parameter raise (`nMatMulV4MaxDimension`/`nMatMulV4Dimension` above 8522, or an `ABS_MAX_DIM` bump)
with the base-2⁷ limbs unchanged would silently truncate high P/Q entries in the GPU combine. Because
consensus n is pinned to exactly `nMatMulV4Dimension = 4096` (F-8) and the max is 8192, this is not a
live defect. Recommend: add a hot-loop `assert(x == 0)` (or an explicit total/partial return) in
`DecomposeLimbPlanes`, and a `static_assert` coupling `MATMUL_V4_ABS_MAX_DIM` to the limb ceiling, so
the v4.2 base-2⁶ rebase cannot regress this silently.

### F-5 (LOW / DoS-hardening) — `IsMatMulV4PayloadSizeValid` uses a loose 256 MiB cap, not the exact expected size

`IsMatMulV4PayloadSizeValid` (pow.cpp:3089–3096) pins `matmul_dim == nMatMulV4Dimension` (good) but
bounds the payload only by `matrix_c_data.size() ≤ MATMUL_V4_MAX_PAYLOAD_WORDS = 8192² = 67,108,864`
uint32 words = **256 MiB**. The legitimate payload at the pinned n = 4096 is m = 1024, m² = 1,048,576
F_q words = **8 MiB** (2,097,152 uint32 words) — a 32× headroom. A block whose `matrix_c_data` is
oversized-but-under-cap passes this gate; `CheckMatMulProofOfWork_V4ProductCommitted` then calls
`UnpackMatMulV4SketchWordsToBytes` (pow.cpp:187–198, ~256 MiB allocation + byte expansion) **before**
`VerifySketch → ParseSketch` performs the exact-size reject.

Assessment: this is a *hardening* item, not a practical DoS. (a) `ParseSketch` (matmul_v4.cpp:450–467)
checks `payload.size() != expected_words·8` **first**, in O(1), so the expensive O(n²) Freivalds never
runs on a malformed payload — the wasted work is bounded to one unpack. (b) Amplification is ≈1:1 (the
attacker must transmit the oversized bytes), and block-level serialization limits gate the message
well before 256 MiB. Recommend tightening the cap to the exact expected word count for the active
dimension (`2·(n/b)²`), converting a 32× slack into an O(1) exact reject and eliminating the pre-parse
unpack. Note the legacy v2/Freivalds paths (pow.cpp:2860–2949) already compute an exact
`expected_words = n·n` and additionally guard the `n·n` multiply against overflow — the v4 gate is
looser than its own predecessors.

### F-6 (INFO / CLOSED) — sampler determinism: no platform-dependent branch on the committed path

`ExpandBalancedS8Stream` (int8_field.cpp:66–110): SHA-256 counter-mode XOF, per-byte rejection at
`byte ≥ 251`, accepted bytes consumed in stream order, seed byte-order pinned by `SeedBytesLE`, block
counter via `WriteLE64`. `ExpandFqStream` (int8_field.cpp:189–223): four LE64 words per block, each
masked to 61 bits, rejected only when equal to `kFieldPrime` (probability 2⁻⁶¹). Both are pure
integer, endianness-pinned, and have **no data-dependent floating-point or platform branch** — the
accepted-element order is a deterministic function of the seed. `SampleBalancedS8` rejection is a plain
integer comparison. The `block` counter (uint64) cannot exhaust at any header dimension (n² ≤ 8192² ⇒
≈2.1M blocks). **Closed for current code.**

For v4.2 this is the highest-risk *unimplemented* determinism surface: the design's nibble-11/16
bijection (design §2.3 — "a pinned bijection maps 11 of the 16 nibble codes onto 𝓜₁₁ and rejects the
other 5"), the 2-bit scale plane, and the structural E2M1-hole rule (no code maps to ±5/±0.5/±1.5/−0)
are new and must (a) be a single pinned table with no endianness ambiguity in nibble extraction
order, (b) be covered by the "alphabet-hole" adversarial vectors (design §4.3-item 4), and (c) get
regenerated golden vectors. Flagged as UNVERIFIED-IN-CODE, not a defect.

### F-7 (INFO / CLOSED) — E8M0 exactness is sound as designed but unimplemented

The design's dequant `Â = μ·2^e` with e ∈ {0..3}, E8M0 codes restricted to 127..130 (design §2.1), is
an exact integer left-shift on the verifier — `Â = μ << e`, |Â| ≤ 6·2³ = 48, well inside int8 and F_q.
As designed this is exact by construction (power-of-two, no significand change), and the
scale-exactness adversarial vectors (design §4.3-item 3: "E8M0 application as a pure exponent add … no
significand bit changes") are the right test. **But no scale plane exists in the code today** — the
current operands are unscaled s8. The load-bearing verifier requirement is that dequant be performed
with an integer shift (not an FP multiply by 2^e), which the design commits to (§3) but which must be
enforced when coded. Sound-as-designed, unverified-in-code.

### F-8 (INFO / CLOSED) — consensus dimension is pinned; the n=65535 memory-blowup is not reachable

`ExpandOperand` allocates n² int8 (matmul_v4.cpp:140–149); at the header-field max n = 65535 that is
4.3 GB per matrix, an obvious verify-DoS *if n were attacker-controlled*. It is not: on the consensus
path `matmul_dim` is forced to **exactly** `nMatMulV4Dimension` in three independent places —
`ContextualCheckBlockHeader` (validation.cpp:9994), `IsMatMulV4PayloadSizeValid` (pow.cpp:3092), and
`CheckMatMulProofOfWork_V4ProductCommitted` (pow.cpp:3110) — with the header-level range check
(validation.cpp:9988–9993) as defense-in-depth. Mainnet `nMatMulV4Dimension = 4096`, min 4096, max
8192 (chainparams.cpp:568–573); the launch-option override is itself range-checked
(chainparams.cpp:1227–1233). So the verifier only ever expands 4096² = 16 MiB operands. **Closed.**

### F-9 (INFO / CONFORMANCE) — miner↔verifier agreement holds; spec↔impl gap is the expected "v4.2 not built yet"

Miner `ComputeDigest` (pow_v4.cpp:20) commits `Ĉ = (U·A)(B·V) mod q` via `ComputeSketchOptimal →
ComputeCombineModQ` (direct mod-q). Verifier `VerifySketch` (pow_v4.cpp:57) parses+range-checks the
payload, exact-recomputes `H(σ‖payload)` against `header.matmul_digest`, then runs R=3 Freivalds
rounds binding the payload via Fiat–Shamir `H(σ‖H(payload))` (matmul_v4.cpp:485–497). Soundness
(≤2/q per round, ≤2⁻¹⁸⁰ total) rests on `FqFromInt32` injectivity for |C| < 2³⁰ < q
(int8_field.h:155–160) — verified correct. The GPU limb-tensor combine is byte-identical to
`ComputeCombineModQ` by the shifted-fold identity and is test-pinned
(matmul_v4.cpp:354–360, ComputeCombineLimbTensorStacked). All consistent.

The spec↔impl "gap" is that the code implements v4.1 ENC-S8 and the reviewed doc specifies v4.2
ENC-BMX4C — but this is *by design* (the doc is a frozen-parameter shelf design, not an activation).
There is nothing to diverge yet. The consequence for this review: every v4.2-specific determinism
claim (F-3 v4.2 branch, F-6, F-7) is sound-on-paper and UNVERIFIED-IN-CODE, and the shared machinery
the doc leans on (F-1, F-2, F-8, this finding) is present and correct.

---

## 2. Correctness spot-checks performed (no defect found)

- **`FqReduce`** (int8_field.cpp:129–143): for x < q² < 2¹²², `hi = x>>61 ≤ q`, `lo ≤ q`, `s = lo+hi ≤
  2q < 2⁶²`; the fold `(s&q)+(s>>61) ≤ q+1`; one conditional subtract lands in [0, q). q and q+1 both
  reduce correctly (→ 0, → 1). Correct.
- **`FqFromSigned(INT64_MIN)`** (int8_field.cpp:175–182): `magnitude = (uint64)(-(x+1))+1` = 2⁶³, no
  signed-overflow UB. Correct.
- **Weight shift** `1u64 << (7·(i+j))`, max exponent 42 < 61 (matmul_v4.cpp:374) — no UB; 2⁴² mod q =
  2⁴². Correct (v4.2's 6·(i+j) max 36 also fine).
- **int32 accumulators** in `ComputeExactProduct`/`ComputeProjected*`/`ComputeCombineModQ`/limb GEMM:
  peak |·| = 15,625·n ≤ 128M (n≤8192) and n·64² ≤ 268M (n≤65535) < 2³¹ — no signed-overflow UB at any
  header n; these are miner-side only (not on the consensus verify path).
- **`ParseSketch`** exact-size gate precedes canonicality loop precedes any hashing; `expected_words =
  m·m` (size_t, no 64-bit overflow at pinned m=1024). Correct.

---

## 3. Verdict

**No consensus-split defect and no practical verifier-DoS were found in the shared code.** The
determinism story for consensus is genuinely strong *because the entire committed-and-verified path is
integer / F_q with zero floating point* — the FP eligibility machinery is quarantined behind
verify+fallback and the pinned-dimension consensus verifier, so it can only cost throughput.

**Highest-value results (real, concrete, in shipped code):**
1. **F-5 (LOW/DoS-hardening):** the v4 payload cap is 32× looser than the exact expected size (256 MiB
   vs 8 MiB) and permits a pre-parse ≤256 MiB unpack; tighten to the exact `2·(n/b)²` words. Backstopped
   by `ParseSketch`'s O(1) exact reject, so not exploitable, but it is looser than the v2/Freivalds
   predecessors in the same file.
2. **F-4 (LOW/latent):** `DecomposeLimbPlanes` silently drops the remainder with no hot-loop assert;
   totality depends on the un-asserted coincidence `MATMUL_V4_ABS_MAX_DIM (8192) < 8522`. Add an
   assert + static coupling before the v4.2 base-2⁶ rebase can regress it.
3. **F-3 (POSITIVE):** the `CheckCombineLimbBound` code is **correct and tight** — the off-by-one the
   exact-float doc flags is a prose/comment issue elsewhere, not in this function.

**What needs the on-silicon M-t24 measurement to settle:** nothing about *consensus safety*. M-t24
(proven t=24 exact block-scaled FP4/MX accumulation on ≥2 vendors' parts) settles only (a) whether a
device runs the native FP4 path at 1× or falls to its INT8 1-GEMM path, (b) which ASIC-residual band
applies, (c) whether the FP8-fold tier exists — all throughput/eligibility, all fail-closed to CPU.
Because the verifier is integer, a wrong M-t24 outcome degrades a device's rate; it never risks a
split. The design states this correctly.

**Miner↔verifier / spec↔impl conformance:** miner (`ComputeDigest`) and verifier (`VerifySketch`)
agree on the same committed Ĉ; digest exact-recompute + Fiat–Shamir-bound Freivalds is sound; the GPU
limb combine is byte-identical to the direct mod-q combine and test-pinned. Spec↔impl: the code is
v4.1 ENC-S8 throughout; BMX4-C (𝓜₁₁, E8M0 scales, base-2⁶ limbs, `V42` tags, nibble sampler, 𝓜₁₁
U/V) is **not implemented**, consistent with the doc's STAGED status — so the v4.2 determinism claims
(E8M0 exact shift, nibble-sampler determinism, base-2⁶ bound) are **sound-as-designed but
unverified-in-code**, and MUST be revalidated with regenerated golden vectors + the §4.3 adversarial
set (t-discrimination, boundary-pin, scale-exactness, alphabet-hole) at implementation time. A
replayed s8-era vector set would certify nothing (design §4.3; accumulator-eligibility doc §4).

**Confidence:**
- Consensus path is integer-only / no FP: **High** (grep-confirmed + read).
- No consensus-split defect in shared code: **High** for the reviewed functions; **Medium** overall,
  since the GPU backend kernels (cu/mm/hip) were read only at their `CheckCombineLimbBound` gates, not
  end-to-end (they are backstopped by verify+fallback regardless).
- F-5/F-4 severity (hardening, not exploitable): **High**.
- v4.2-as-designed soundness: **Medium** (paper-correct; unimplemented; the nibble sampler + E8M0 shift
  are the surfaces to re-audit in code).
- M-t24 is throughput-only, not a safety gate: **High**.
