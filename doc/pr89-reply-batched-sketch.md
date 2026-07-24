# PR #89 reply — batched-sketch profile (v4.1) — draft response to @vanities

> Draft reply for the PR #89 review thread. Context: @vanities measured the
> v4 sketch workload on real silicon (RTX 5090 + H100) and showed it is
> consumer-favoring at b=8. This is the follow-up that landed in response.

---

@vanities — thank you for this. Your measurement (5090 ≈ 161 nonce/s vs H100 ≈ 64 nonce/s, H100/5090 = 0.40× at n=8192, b=8) falsified the design's central claim, and your per-stage methodology told us *why*, which is worth more than the headline number. This is the second time a model-based estimate for this workload has been wrong on real hardware (the per-element XOF was the first), so we've stopped arguing from MAC counts and rooflines anywhere in the spec: §K.2b now treats every ordering claim as measurement-gated, and your numbers are the pinned anchor.

## What we changed (v4.1 "batched-sketch" profile)

Your root-cause diagnosis was that the per-nonce work is structurally wrong for datacenter parts: the GEMMs are skinny (too little tensor volume per launch to reach an H100's dense-GEMM operating point), and the SHA-XOF operand generation + int-ALU mod-q combine sit exactly on the units where a high-clock consumer card is strongest. The v4.1 profile restructures the enforced shape rather than just turning parameter knobs:

1. **Template-scoped A, U, V; nonce-fresh B and σ** (spec §A.2 v4.1). `seed_A`, `seed_U`, `seed_V` now bind a *template hash* — every header field except the nonce and the nonce-derived seed fields — so a miner expands A/U/V and computes `P = U·A` **once per template**. `seed_B` and σ still bind the full header including `nNonce64`.
2. **Cross-nonce batching into one large dense GEMM.** Per window of Q nonces the miner computes the nonce-fresh right factors `Qᵢ = Bᵢ·V` (stackable as `[B₁; …; B_Q]·V`) and evaluates all Q combines as the single GEMM `P·[B₁·V | … | B_Q·V]` — m × Q·m × n. At n=4096, b=4, Q=32 that's a 1024 × 32768 × 4096 s8 shape per limb pair: large, dense, batched — the shape your measurement said was missing, in place of Q skinny per-nonce launches.
3. **b = 8 → 4**, doubling m: the marginal per-nonce tensor volume rises to ≈1.25n³ MACs while the per-nonce non-tensor floor stays one B-expansion + one digest (the A-side XOF cost — half the per-nonce SHA — amortizes away).
4. **The mod-q combine moves onto tensor units** (the C-13 limb path you flagged as the post-XOF bottleneck): 4 balanced base-2⁷ limbs, 16 s8×s8→s32 limb-pair GEMMs + one O(m²) mod-q fold, byte-identical to the direct combine (valid for all n ≤ 8589).

Consensus surface: the verifier is **unchanged** — O(n²) sketch-Freivalds on the one winning nonce, challenges still Fiat–Shamir from `H(σ‖H(Ĉ))`. Batching is miner-only; the batched digest is byte-identical to the single-nonce reference for every (header, nonce) (pinned by `matmul_v4_batch_tests`, and the solve loop re-derives the winner through the reference path before sealing). Payload is 8 MiB at n=4096 (inside existing message limits); golden vectors re-pinned.

## What we are NOT claiming

We are not claiming this wins on datacenter hardware. The shape argument says it *targets your measured root cause*; whether it actually inverts the ordering is exactly the kind of claim that has now been wrong twice when argued from models. The spec's §K.2b GO/NO-GO requires, on physical H100/B200 (and ideally your 5090 for the anchor): tensor stages a strict majority of *marginal* per-nonce wall-time at Q ≥ 32; ≥ ~60% of peak INT8 utilization on the batched GEMMs; and an actually-measured nonce/s ordering. Until then the datacenter claim stays labeled a hypothesis. If you're able to re-run your harness on this profile, we'd take that over any estimate we can produce — `src/bench/matmul_v4_stage_bench.cpp` pins the stage boundaries (S0 template / S1b expand-B / S2 B·V / S3a-c stacked limb combine / S3′ ALU combine / S4 digest) so your numbers and ours are directly comparable, bit-exactness gated.

## The part we specifically want you to attack: the I1′ relaxation

The template-scoping is a **deliberate weakening of v4.0's anti-amortization invariants** (I1 "both operands nonce-fresh" and I7 "nonce-fresh projectors"), and we would rather have it broken in review than on mainnet. The replacement invariant I1′ (spec §C) says: B nonce-fresh; A/U/V template-scoped; per-nonce *marginal* work (expand B + B·V + combine + digest) is Freivalds-bound and is what difficulty prices. The security argument as written:

- soundness untouched (verifier and Fiat–Shamir challenges unchanged, per-round error ≤ 2/q);
- no pre-mining (A/U/V bind prevblock/merkle/time via the template hash — nothing computable before the template exists; memorylessness survives at template granularity, which is admittedly weaker than per-nonce);
- symmetric (every miner of a template derives the same A/U/V and amortizes identically, pooled miners included);
- difficulty must be recalibrated to the marginal unit, since U·A amortizes (this feeds the ASERT rescale item).

What we can't prove: that the marginal unit has no further shortcut. The floor argument is "any correct `Ĉᵢ` must read all of the fresh pseudorandom `Bᵢ`, and `M·Bᵢ·V` with fixed rank-m `M = U·A`, `V` has no known sub-n²m evaluation" — *no known* is not a theorem, and template-scoped U/V reopen exactly the projector-cache channel I7 existed to close. Specific directions we'd value adversarial eyes on: cross-nonce shared structure in the XOF-derived Bᵢ; batch-algebra shortcuts over the fixed (M, V) pair; and whether the template-refresh boundary (merkle/time churn) creates any difficulty-gaming angle between templates. This review is flagged as a mainnet-activation blocker (ACTIVATION B4′) — it does not ship without it.

Changes are in `src/matmul/matmul_v4_batch.{h,cpp}`, `matmul_v4.{h,cpp}`, `pow_v4.{h,cpp}`, `pow.cpp` (solve-loop wiring), spec §A.2/§C/§E/§K.2b, and the stage bench. All six v4 unit suites plus the regtest fork-activation functional test are green on the CPU reference.

Thanks again — the measurement moved this design more than anything else in the review.
