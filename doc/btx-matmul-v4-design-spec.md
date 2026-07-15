# BTX MatMul Proof-of-Work: Engineering Design Specification (v4)

**Status:** Draft for implementation review
**Supersedes:** MatMul v3 (`doc/btx-matmul-pow-spec.md`) at the v4 activation height
**Activation:** Hard-fork consensus swap at `BTX_MATMUL_V4_HEIGHT` (height-gated, no dual-algorithm transition)
**Scope:** Consensus proof-of-work only. Post-quantum signatures (ML-DSA / SLH-DSA), the shielded pool, and its formal-verification artifacts are **out of scope and unmodified** (§0.4, §J).

---

## 0. Executive Summary

### 0.1 Problem statement

MatMul v3 was designed to align mining with *commodity* AI hardware and to make ASICs economically pointless rather than impossible. In production that objective has been over-achieved in the wrong direction: **consumer and end-of-life datacenter cards are the most cost-effective miners, at or near parity with current datacenter accelerators (H100/H200).** Three structural properties of v3 cause this, all confirmed in the shipped code:

1. **The proof-of-work is a SHA-256 lottery, not a matrix computation.** A pre-hash "epsilon gate" (`nMatMulPreHashEpsilonBits`, upgraded to **18 bits** at height 50,000 — `src/consensus/params.h:156-161`, `src/kernel/chainparams.cpp:237-238`; `CheckMatMulPreHashGate`, `src/pow.cpp:2688-2697`) admits only **1 in 2¹⁸ ≈ 262,144** nonces to the matrix step. The marginal cost of scanning a nonce is a 4-block SHA-256 hash of the header; the matrix multiply runs on a vanishing fraction of attempts. Miner throughput is therefore bounded by **SHA-256 hashrate over the nonce space**, which is exactly the resource on which retired ASIC-class mining cards (e.g. NVIDIA CMP series) and high-clock consumer GPUs excel. This is the "the share of SHA-256 is enormous… the proportion of GPU capacity dedicated to matrix operations decreases as difficulty rises" observation.

2. **The exact field GF(2³¹−1) forbids tensor cores.** Every backend (CUDA `src/cuda/matmul_accel.cu`, Metal `src/metal/matmul_accel_kernels.metal`, Apple AMX `src/matmul/matmul_pow.cpp:101-176`) performs exact 32-bit modular arithmetic on **integer ALUs**. No backend touches INT8/FP8/BF16/FP16 tensor cores (verified: no `wmma`/`mma_sync`/`cublas`/`__half`/`bfloat`/`fp8`/`int8`/`dp4a` in the CUDA path). The H100/H200/B200 derive their entire advantage from low-precision tensor throughput and HBM bandwidth; under v3 both sit **idle**.

3. **n = 512 is cache-resident and the work is low arithmetic-intensity.** Each matrix is ~1 MiB (`4·n²`), so the problem never leaves L2 and datacenter HBM capacity/bandwidth is irrelevant. Historically the rank-8 low-rank noise also let the O(n³) product be amortised to an O(n²·r) update; that specific reuse was closed at height 125,000 by folding the nonce into the matrix seed (`src/pow.cpp:53-100`), but the epsilon gate (1) makes the point moot — the dense multiply seldom runs at all.

### 0.2 Objective (explicit pivot)

**v4 makes the dense matrix multiplication the sole, unavoidable, per-nonce unit of work, executed on low-precision tensor cores, and scales the problem so that throughput is bounded by tensor-FLOPS and on-device memory capacity.** The intended consequence is that **datacenter-class accelerators (H100, H200, B200/GB200) achieve the best cost-per-block**, while 16–32 GB consumer cards, Apple silicon, and prior-generation mining cards (CMP-class) become uncompetitive — and mining difficulty rises with aggregate *compute*, not with hash rate.

This is a **deliberate reversal** of v3's stated "commodity-hardware fairness / ASIC economic-misalignment" goal. Every existing BTX artifact (README, `doc/btx-matmul-pow-spec.md`, the public site) optimises for broad participation on "any machine from the last decade," including "Apple Silicon or CPU." v4 supersedes that positioning for the mining subsystem. The spec states this openly so downstream documentation is reconciled rather than silently contradicted (§N).

Two hard constraints shape the design and are drawn directly from the requirements discussion:

- **Compute must scale up, and must not become memory-bandwidth-bound.** "The worst would be to have the compute go down because it's memory-hard not compute-hard." v4 is engineered to sit **above the roofline ridge point** (compute-bound), using memory *capacity* as an exclusion gate but never memory *bandwidth* as the bottleneck (§L). Pure memory-hardness — the classic low-VRAM-exclusion lever — is explicitly rejected because it flattens the FLOPS advantage and rewards cheap high-bandwidth cards (precisely the CMP-170HX profile).
- **Verification must remain cheap, specifically via Freivalds' algorithm.** "If we can't efficiently do Freivalds it is a problem." v4 keeps an O(n²) deterministic Freivalds product check as the primary verification path (§D), so full nodes never re-run the O(n³) work. A ZK layer (Plonky2) is analysed and shown to be **not required** for the deterministic INT8 design; it is retained only as an optional module for hypothetical non-deterministic (FP8/BF16) variants (§F).

### 0.3 Design in one paragraph

Each nonce derives fresh, full-rank matrices **A, B** from `H(prevhash ‖ height ‖ merkle ‖ nBits ‖ nNonce64 ‖ dim ‖ parentMTP)`, computes the **full dense product C = A·B** over a small-prime / CRT integer field that maps onto **INT8 tensor cores with exact INT32 accumulation** (bit-identical across vendors — the property FP8/BF16 cannot provide), commits to C with a product-committed digest, and accepts the block iff the digest ≤ target. There is **no pre-hash gate** (SHA is reduced to seed derivation and final sealing, per "limit SHA to just the seed and sealing roles") and **no low-rank noise** (removing both the amortisation shortcut and v3's reliance on an unproven direct-product conjecture). Verifiers run a deterministic **Freivalds** check in O(n²). The default dimension rises from **n = 512 to n = 4096**, with a memory-capacity gate that scales n (and/or a required resident working set) so the problem exceeds consumer VRAM while fitting datacenter HBM. Difficulty (ASERT) and the 21M monetary schedule are unchanged; ML-DSA / SLH-DSA signatures are untouched.

### 0.4 What is explicitly NOT changed

| Subsystem | Status | Reason |
|---|---|---|
| ML-DSA (FIPS 204) / SLH-DSA (FIPS 205) signatures | **Unchanged** | Transaction/script layer (`src/libbitcoinpqc`, `src/script/pqm.*`, `interpreter.cpp`), orthogonal to PoW. "Retain the ML-DSA and SLH-DSA schemes already in place." |
| Shielded pool + `formal-verification/` proofs | **Unchanged** | Proves value-soundness of the privacy pool, not the PoW. Swapping PoW disturbs no proof artifact. |
| Monetary policy (21M cap, 525k halving, 20 BTX subsidy) | **Unchanged** | Independent of the work function. |
| ASERT difficulty machinery | **Reused** | Target now bounds the product-committed digest; only genesis/bootstrap calibration is revisited (§I). |
| Past blocks (height < activation) | **Validated under legacy v3 rules** | Height-gated fork; no rewrite of history. Satisfies "doesn't break the chain and past blocks." |

---

## 0.5 Traceability: every raised concern → where it is addressed

The following matrix maps each point raised in the requirements discussion to the mechanism and section that resolves it. (Sources in brackets refer to the discussion screenshots.)

| # | Concern as raised | v4 resolution | Section |
|---|---|---|---|
| 1 | Consumer 5090 is the most efficient miner, at parity with H100/H200 | Invert via INT8 tensor-core dense matmul at large n (b=8 keeps it compute-bound, §K.2a); datacenter wins per card (H100 ≈ 2.4×, B200 ≈ 5.4× a 5090) and per joule. No capacity gate (closed, §L.4) — the lever is compute + energy | §K, §L, §M |
| 2 | "Increase the compute level while washing out the retail guys" | Matmul is the sole per-nonce cost; difficulty tracks tensor-FLOPS; n scaled to exceed consumer VRAM | §A, §K, §M |
| 3 | SHA-256 share is enormous; matrix share shrinks as difficulty rises | **Remove the pre-hash epsilon gate**; SHA limited to seed + sealing; one dense matmul per nonce | §A, §C, §I |
| 4 | "Hashing takes up way more of the mining effort than GPU compute" | Same as #3 — matmul runs on every nonce; SHA cost becomes negligible per attempt | §A, §C |
| 5 | Scale matrix size n = 512 → 4096+, deterministic INT8 | n = 4096 default (scalable); INT8/CRT field on tensor cores; exact INT32 accumulation | §A, §B, §M |
| 6 | ZK layer "mandatory"; limit SHA to seed/sealing; matmul dominant; Plonky2; large-n re-verification infeasible | SHA limited to seed/sealing; matmul dominant; **Freivalds O(n²) makes re-verification feasible so ZK is optional, not mandatory**; Plonky2 analysed as optional module | §A, §D, §F |
| 7 | Retain ML-DSA / SLH-DSA for quantum resistance | Untouched — orthogonal subsystem | §0.4, §J |
| 8 | "If we can't efficiently do Freivalds it is a problem" | Deterministic Freivalds over an independent 61-bit prime on the exact-integer product (§D.3 — never over the composite CRT modulus, §D.2); R = 3 rounds for ≤ 2⁻¹⁸⁰; ≈ 0.1 s verify at n = 4096 | §D |
| 9 | Target datacenters (H100/H200); let them win more blocks | INT8 tensor-FLOPS + HBM-capacity design gives datacenter the best cost-per-block | §K, §M |
| 10 | Must scale compute; worst case is compute going down via memory-hardness | Compute-bound above the roofline ridge (AI_opt = 2n/b, b=8, §K.2a); never bandwidth-bound; no capacity gate (§L.4). More tensor FLOPS always → more reward | §L |
| 11 | May need to abandon SHA-256 (consumer excels at it) | SHA-256 demoted to seed derivation + block sealing; it is no longer the mining bottleneck | §A, §C |
| 12 | Don't break the chain / past blocks | Height-gated hard fork; legacy blocks validated under v3 rules | §0.4, §G, §J |
| 13 | CMP cards / old hardware / cheap electricity dumping price (2 CMP ≈ 1 5080) | CMP-class cards lack low-precision tensor GEMM (CMP-170HX FP32 = 0.39 TFLOPS) and are excluded by the INT8-tensor + VRAM-gate design | §K, §N |
| 14 | Advisor: make it memory-bound to limit low-VRAM GPUs | **Not adopted** — no verification-preserving capacity gate exists (§L.4), and bandwidth-hardness would resurrect junk (rejected). Admission is by INT8-tensor-path eligibility (§S.1); design stays compute-bound | §L, §M, §S |
| 15 | Change consensus immediately; give requirements | This document; clean hard-fork swap with a complete implementation checklist | §G–§J |
| 16 | Consumer/Apple users must still pool massively and earn rewards, not be shut out | v4 *orders* by INT8 throughput, never hard-excludes; share-based pooling over cheap Freivalds-verified shares pays proportional-to-compute (PPLNS/PPS); Apple M5 re-enters with a genuine INT8 path | §O.1, §O.2, §P.3 |
| 17 | How M1+ Apple / RTX 3090/5090 / datacenter fare in v3 vs v4 | Full cross-generation comparison: CMP & M1–M4 fall to verify-only, M5+ and all Ampere+ NVIDIA re-rank by INT8 TOPS (H100 = 2.4× a 5090); datacenter wins per device & per watt | §P |
| 18 | Measure network compute in nonces / % of Bitcoin (btxprice.com) & reflect the true compute growth | Nonce metric *inverts* at the fork (drops ~10⁵–10⁶×); recalibrate `w` to the §I.4 fork constant or switch to an INT8-TOPS/H100-eq/AI-$ metric; effective compute rises ~30× same-hardware, ~10²–10³× combined | §Q |
| 19 | End-to-end post-quantum (hard requirement) | **Met** — PQ-only chain from genesis (`fEnforceP2MROnlyOutputs` + `SCRIPT_VERIFY_REJECT_LEGACY_SIGS`); v4 PoW, Freivalds, hashes (128-bit post-Grover), ML-DSA/SLH-DSA all PQ-safe | §R |
| 20 | Close FPGA/ASIC loopholes — need AI-native GPU compute to win; stop rogue mine-and-dump pools (btxpool.org) | Only bit-exact INT8 tensor silicon wins (FPGAs 13–31× behind, SHA/bandwidth ASICs gain nothing); junk-hardware pools de-rated 10–360×/excluded; AI-rental opportunity cost creates a `N_eq·r/800` $/BTX floor that makes below-floor dumping irrational | §S |

---

## 0.6 Document structure

- **§A–§C** — Core algorithm, INT8/CRT arithmetic, anti-amortisation invariants *(the work function)*
- **§D–§F** — Freivalds verification, data availability & node tiers, optional ZK *(the check)*
- **§G–§J** — Consensus params, header/serialization, validation/mining/difficulty wiring, file-by-file hard-fork checklist *(the integration)*
- **§K–§N** — Hardware economics, compute-vs-memory reconciliation, parameter calibration, migration & risk register *(the economics)*
- **§O** — Evolving consumer matmul hardware (Apple M5) & inclusive pooling *(who can still participate)*
- **§P** — Cross-generation hardware: M1→M5, RTX 3090/4090/5090, datacenter, v3 vs v4, solo & pooled *(who wins)*
- **§Q** — Network compute accounting, the btxprice valuation model across the fork & the per-GPU mine-vs-AI-rental switchover (§Q.21) *(measuring — and pricing — the compute)*
- **§R** — Post-quantum security — end-to-end audit *(the quantum requirement)*
- **§S** — ASIC/FPGA resistance, AI-native-compute necessity & rogue-pool (mine-and-dump) economics *(closing the loopholes)*
- **Appendices** — Glossary (A), references (B), open calibration items (C), optional CRT compute-multiplier variant — full spec (D)

---

## 0.7 Normative verification model (GOVERNING — READ BEFORE §A–§N)

Sections A–N were drafted in parallel. **This section is normative and governs wherever a drafted section diverges in detail.** Section §D is the authoritative long-form verification specification and is internally consistent with this note; where §A, §G, §H, or §K–§N state a conflicting payload size, digest form, field, or round count, the values here (and in §D–§E) win. Three decisions are fixed:

### (1) Verification never recomputes the product (the load-bearing property)

Every full node validates a block in **O(n²)** and never performs the O(n³) matmul. It regenerates `A, B` from the header seeds (O(n²) PRF), runs `R` deterministic Freivalds rounds — each a pair of O(n²) matrix–vector products `A·(B·r)` reproducing the true `C·r` without ever forming `C` — and recomputes the small product commitment. This asymmetry (miner does n³, every node does n²) is why a matmul PoW is viable on a blockchain, and it is the direct answer to the owner's requirement that verification be cheap. Measured budget (§D.4): **≈ 0.1 s single-threaded at n = 4096**, ~0.1 % of the 90 s block interval.

### (2) Soundness field — an independent large prime, NOT the composite CRT modulus

The compute field is small (INT8 residues mod primes `p_i < 2⁸`, CRT modulus `P ≈ 2³²`). **Freivalds must NOT be run over the composite modulus `P`:** `ℤ_P` is a ring, and an adversary can localize a forged error to a single CRT plane, collapsing per-round soundness to `1/p_min ≈ 2⁻⁷·⁹` (proof in §D.2). Any earlier text (including drafts of this note and §G/§K–§N) claiming `1/P` soundness over `ℤ_P` is **superseded and must not ship.**

The correct construction (§D.3), native to the exact-INT32 accumulation of the INT8 path: the committed product entries are **exact integers** (`|C_ij| ≤ n·125² = 15,625·n < 2³⁰` for every header-expressible `n ≤ 65,535`; §B.4/§G.4-#3), so run Freivalds over an **independent large prime `q = 2⁶¹ − 1`** (Mersenne; one 64-bit multiply-and-fold per MAC) — or over `GF((2³¹−1)²)` to reuse the existing `matmul::field` code. Because any two distinct canonical integer entries differ by `|Δ| < 2³² < q`, a wrong entry can never alias to a correct residue: **per-round error ≤ 1/q ≈ 2⁻⁶¹.**

**Normative round count: `R = 3`** → error ≤ 2⁻¹⁸³ for the full-C form (per-round ≤ 1/q) and ≤ 2⁻¹⁸⁰ for the default sketch form (per-round ≤ 2/q, §E.2) — both well past 2⁻¹²⁸. `R = 2` gives only 2⁻¹²² / 2⁻¹²⁰ (short of 2⁻¹²⁸) and is reserved for regtest. This supersedes an earlier `R = 8` draft value computed under the incorrect small-field assumption; §G.2 (`nMatMulV4FreivaldsRounds` = 3, regtest 2) and §G.4 invariant #5 (the `1/q` bound) now reflect it.

### (3) Payload & product commitment — recommended: compressed sketch

The consensus digest commits to the **final product `C = A·B`** (never to an intermediate transcript of partial sums — that would force O(n³) re-execution and violate (1); the per-step quadratic transcript sketched in §A.3 is design commentary only, not consensus). Two payload profiles are supported; **the sketch is the recommended default** because cheap verification and small bandwidth are the paramount blockchain constraints:

| Profile | Payload at n=4096 | Verify time | Work-binding | Serialization impact |
|---|---|---|---|---|
| **Sketch (default)** — ship `Ĉ = U·C·V ∈ 𝔽_q^{m×m}`, `m=n/b`, balanced-s8 σ-derived `U,V`; digest `H(σ‖Ĉ)`; sketch-Freivalds `xᵀĈy ≟ (Uᵀx)ᵀA(B(Vy))` (§E) | **~2 MiB** (b=8, m=512) | **~0.1 s** | dense INT8 `n×n×2m` GEMM ≈ `n³·(2/b) = n³/4` per nonce (§E.3) | **fits existing 16 MB/24 MB limits — no §H.3 protocol-limit changes needed** |
| Full-C (strict-binding alternative) | 64 MiB | ~0.3 s | strict `Θ(n³)` (Freivalds pins all n² entries) | requires the §H.3 message/`MAX_SIZE` plumbing |

Both profiles verify in O(n²) via the `q = 2⁶¹−1` Freivalds of (2) and use the product-committed digest form of v3's `ComputeProductCommittedDigest` (`src/matmul/transcript.cpp:485`). Where §A/§H describe a mandatory 64 MiB full-`C` payload, treat that as the *alternative* profile; the **default is the sketch**, which also removes the need to raise `MAX_PROTOCOL_MESSAGE_LENGTH`/`MAX_SIZE`.

**Honest work-binding disclosure (§E.3):** under the sketch, the optimal miner computes `Ĉ = (U·A)(B·V)` directly at ≈ `n³·(2/b)` MACs (a factor `b/2` = 8× below full `n³` at b=16) — it need not form all of `C`. This does **not** weaken security (no invalid block passes; §E.3) and does **not** reintroduce SHA or any non-tensor shortcut: the work remains a **dense INT8 tensor-core GEMM** of the same hardware profile, so the datacenter advantage (§K) and the "compute, not hashing, is the work" fix are fully intact. It only means the per-nonce *work unit* is `n³·(2/b)`, not `n³`; **difficulty calibration (§I.4) and the §M work-unit/economics MUST use the `n³·(2/b)` figure.** Strict `n³` binding is available by choosing the full-C profile or the optional ZK module (§F.4d); it is not required to meet any stated objective.

**Resolved (was Appendix C-9) — the compute is a single exact-integer INT8 matmul, k = 1.** The normative baseline multiplies **one** pair of dense pseudorandom **s8 operand matrices** `A, B` (entries seed-derived in `[-125, 125]`) into the **exact integer product** `C = A·B` — which is precisely what an `s8×s8→s32` tensor-core GEMM produces natively, with `|C_ij| ≤ 15,625·n < 2³⁰` for every header `n ≤ 65,535` (§B.4), so `C` is an exact INT32 matrix with no modular reduction. Freivalds then runs over the independent prime `q = 2⁶¹−1` on that exact integer product (2). This is the only construction that keeps verification at the cheap R = 3 / 2⁻¹⁸³ point: the k-prime CRT scheme of §B.3 leaves the product defined only mod `M`, for which no single exact integer exists to check over `q`, and per-plane checking would need ~17 small-field rounds per lane (blowing the §D.5 budget). **The CRT/multi-prime construction (§B.3, §B.5) is therefore demoted to a non-normative, optional _compute-multiplier variant_:** each extra prime is one more independent s8 GEMM whose own exact-integer lane product is committed and Freivalds-verified over `q` separately, multiplying both per-nonce work and verification cost by `k`. It is off by default (k = 1). This supersedes every `k = 4` / `nMatMulV4PrimeCount = 4` reference in §B.3, §G.2, §M.2, §M.4, and the "CRT-reconstruct to Z_M" step in §D.3.

### (4) Price-independence of consensus — no market price is an input to any protocol parameter (GOVERNING; anti-manipulation)

**Every consensus parameter is fixed by hardware and verification budgets, never by the observed BTX price.** `n`, `k`, `b`, `R`, the difficulty target and its ASERT response, the difficulty floor, the emission/reward schedule, and the share/pool work-unit are set from the verification budget (1)–(3) and the §K/§P hardware ordering — *never* from a price. Difficulty tracks **delivered compute** (ASERT reads chainwork and solve-times, §I.4 — a physical quantity, not a price), and the marginal-cost floor of §S.4.3 / §Q.6 is a **structural consequence** of requiring real INT8 tensor work, *not* a tuned target.

This is a **security property, not a stylistic choice.** The market price of BTX can be adversarially suppressed — mine-and-dump, wash trading, manufactured "fake supply" sell pressure (§S.4) — and any design that reads price back into a parameter (e.g. "at the current price only cheap consumer/junk silicon rationally mines, so lower difficulty / the work unit / the floor to match") hands the manipulator a **second lever**: whoever suppresses the *print* would thereby also lower the network's *cost floor*, keeping dumping profitable and entrenching the suppression. That circular loop is precisely the attacker's win condition, and v4 must not close it.

Therefore **v4 treats price as an OUTPUT the market discovers, never an INPUT to the protocol.** All economic quantities in §Q/§S — the `$/BTX` production floor `P_prod`, the per-GPU switchover price `P*_g`, `N_eq`, the "who mines vs. rents" split — are **descriptive read-outs at whatever price happens to obtain**, not design targets. In particular, the low-price, **consumer-dominated, low-`P_prod`-floor regime of §Q.21 is the currently-suppressed *attack state*, NOT the equilibrium and NOT a calibration target**; the protocol must behave identically across the full price range, including under adversarial suppression, and its intended hardware ordering (§K/§P) and floor *mechanism* (§S.4.3) must hold without reference to where the print sits today. Retail inclusion is delivered by proportional, Freivalds-verified **share-based pooling (§O.2)** — itself price-independent — and **never** by lowering the consensus bar to match a suppressed-price regime. Any figure, graph, or parameter recommendation elsewhere in this document that appears to tune the design to the current price is subordinate to this note and must be read as descriptive-at-a-price, not prescriptive.

### Normative launch parameters (supersede any divergent example in §A–§N)

| Symbol | Value | Notes |
|---|---|---|
| `n` (dimension) | **4096** all production nets; **≤ 8192** only after the §H.3 serialization work (full-C profile) or trivially under the sketch | §D.5: n = 4096 baseline meets the <100 ms target; n = 8192 ≈ 1 s conservative (ceiling); **n ≥ 16384 is EXCLUDED** — fails the single-thread verify budget regardless of miner capability. |
| `k` (compute lanes) | **1** (baseline) | Single exact-integer s8 matmul; s8 operands in `[-125,125]` give exact INT32 accumulation for n ≤ 137,438 (§B.4). k > 1 (the §B.3 CRT variant) is an optional compute-multiplier at ×k verify cost, off by default. |
| `q` (verification prime) | **2⁶¹ − 1** (or `GF((2³¹−1)²)`) | Independent of the compute field; gives 1/q per-round soundness (§D.3). |
| `b` (commit/sketch tile) | **8** (m = n/b = 512 at n=4096); keep b = 8 at larger n | **Revised 16 → 8** (§K.2a/§L.2 roofline fix): the *optimal* sketch miner's arithmetic intensity is `AI_opt = 2n/b` ops/byte, so b=16 gave AI≈512 — **below** the peak INT8 roofline ridges of H100 (591), B200 (563), 4090 (655), bandwidth-clipping datacenter throughput and leaking ~9–22% of the compute lever back to bandwidth-rich consumer cards. b=8 gives AI≈1,024 ≥ 1.56× above every ridge. Sets sketch dimension m and payload 8m² bytes (§E.1). |
| `U, V` (sketch projectors) | **balanced s8** (normative) | So `U·A`, `B·V` run as native IMMA/MFMA/TensorOps GEMMs on the tensor path; `|U·A| ≤ n·127·125 < 2³¹` exact in s32; the small m×m stage (`≈ n·m²` MACs, < 3 % of work) runs in exact 64-bit integer / mod-`q` ALU arithmetic (§B.6). Resolves the "𝔽_q-dense U,V" dtype ambiguity in (3). |
| `R` (Freivalds rounds) | **3** (2 on regtest) | Error ≤ 2⁻¹⁸³ over q. |
| Payload (default) | **~2 MiB** sketch at n=4096, b=8 (`8m²`, m=512) | Within existing 16/24 MB limits; no protocol-message-size fork needed. (Was 512 KiB at b=16.) |
| Per-nonce work unit (difficulty/§I.4/§M.4) | **`n³·(2/b) = n³/4 ≈ 3.44×10¹⁰` ops** (`2n²m + nm²`, m=512) | Optimal-miner basis (§E.3). Work-binding shortcut tightened to **b/2 = 4×** below full n³ (was 8×). The floor and hardware ordering are **invariant** to this figure (work-unit-neutrality theorem, §L.2.1 / §S.4.3) — it sets difficulty calibration, not economics. |
| Verify budget | **< 100 ms target, < 1 s hard ceiling**, single-thread | Binds n from above (§D.5). Verify cost is **unchanged** at b=8 (Freivalds matvecs dominate; the 2 MiB payload SHA ≈ 5–10 ms). No capacity/working-set gate exists (§L.4) — the footprint lever is closed, not deferred. |

### On the memory-capacity gate (§L/§M)

Per (1) and §D.5, `n` is capped by the verification budget, so a *single-matmul* VRAM gate (which needs n ≈ 49k–74k, far past the verify ceiling) is out. **Closed, not deferred: no verification-preserving capacity / memory-bandwidth / working-set gate exists** in the nonce-parallel, single-winner, O(n²)-verify model (proof in §L.4). Three attacks jointly cap every construction below the ~4.55× rental-price gap it would need to overcome: *verifier-linearity collapse* (any operand structure the O(n²) verifier can evaluate composes into an O(n²m) miner shortcut; any nonlinearity that blocks the miner also forces the verifier to O(n³)), *selection filtering* (a nonce-dependent footprint is defeated by grinding the O(1) selection PRF to resident nonces — ~10 ns of SHA vs a 31.6 µs GEMM), and *batch-streaming with winner-recompute* (losing candidates are discarded and the single winner is recomputed post hoc, so per-candidate in-flight state collapses to 32 bytes and off-card traffic → 0). The datacenter advantage therefore rests **permanently** on the **INT8 tensor-core compute lever and the energy lever**, both fully compatible with cheap sketch verification (§K/§P: H100 ≈ 2.4×, B200 ≈ 5.4× an RTX 5090 per card on §P.1-corrected dense INT8; joules/nonce ranks B200 < H100 < consumer; CMP-class and M4 excluded by lack of low-precision tensor GEMM) — and datacenter "wins per card and per joule at every price," while consumer "wins per rental-dollar at every price," an in-model-irreducible fact (§L.4, §S.4.6) that no gate can invert. Appendix C reclassifies the capacity gate from *future hardening* to *resolved-negative*.

---

## A. Core v4 PoW Algorithm

### A.1 Overview and symbols

MatMul v4 replaces the v3 per-nonce workload — a low-rank-perturbed product behind a SHA-256 pre-hash gate — with exactly **one fresh, full-rank, dense `n × n` modular matrix multiplication per nonce attempt**. The digest commits to the full product `C = A·B`, and a header is valid iff the digest meets the difficulty target. There is no pre-filter, no reusable term, and no structured (low-rank) component anywhere in the per-nonce computation.

> **Normative note (see §0.7):** the consensus digest commits to the *final product* `C` (product-committed digest, verified in O(n²) via Freivalds), **not** to the per-step transcript sketched in A.3. The transcript discussion is retained as design rationale only; it is not recomputed by validators.

Symbols used throughout sections A–C:

| Symbol | Meaning |
|---|---|
| `n` | matrix dimension (square operands `A, B ∈ Z^{n×n}`) |
| `b` | commitment tile (block) size; `b | n` |
| `N` | `n / b`, blocks per dimension |
| `k` | number of CRT residue channels (section B) |
| `p`, `p_m` | small prime modulus / the m-th residue prime, `p_m < 2^8` |
| `M` | `∏ p_m`, effective CRT modulus |
| `E_max` | maximum magnitude of a canonical operand element |
| `T` | 256-bit difficulty target derived from `nBits` |

### A.2 Seed and operand derivation

v4 extends the v3 nonce-bound seed rule (`DeterministicMatMulSeedV3`, `src/pow.cpp:85-100`), introduced at height 125,000 (`nMatMulNonceSeedHeight`, `src/consensus/params.h:162-167`) to close cross-nonce `A, B` reuse — the "~12.8x amortization" noted at `src/pow.cpp:58-62`. v4 keeps every binding of that rule and adds a distinct domain tag:

```
seed_A = SHA256( "BTX_MATMUL_SEED_V4" || hashPrevBlock || height || nVersion
                 || hashMerkleRoot || nTime || nBits || nNonce64
                 || matmul_dim || parent_mtp || 0x41 )      # 0x41 = 'A'
seed_B = SHA256( "BTX_MATMUL_SEED_V4" || ... same fields ... || 0x42 )   # 'B'
sigma  = SHA256d(header)                                     # as v3 DeriveSigma
```

Because `nNonce64` is inside the seed preimage, **every nonce attempt defines a completely independent operand pair** `(A, B)`. Operand entries are expanded from `seed_A`/`seed_B` by a deterministic XOF with per-byte rejection sampling into the canonical range of the arithmetic (section B.2/B.3); expansion costs `O(k·n²)` bytes and is subdominant to the per-nonce GEMM cost (`Θ(k·n²·m)` under the default sketch payload, `Θ(k·n³)` under full-C; §E.3).

### A.3 Product and digest (design rationale; consensus form per §0.7)

The consensus digest is the **product-committed** hash of the exact-INT32 product `C = A·B`: tile `C` into `b×b` blocks, algebraically compress each tile to one field element under a σ-derived vector (as v3's `ComputeProductCommittedDigest`, `src/matmul/transcript.cpp:485-509`), and SHA256d the compressed image with a `"BTX_MATMUL_V4"`/σ prefix. Recomputing this digest from a shipped `C` is O(n²) (hashing n² words); it does **not** require re-running the matmul.

*(Design note — why no intermediate transcript: v3 absorbed a linearly-compressed word per partial sum, and that linearity is exactly what enabled its low-rank replay shortcut, `CompressAfBlock`/`CompressEbBlock`/`CompressEfBlock`, `src/matmul/transcript.cpp:379-381`. v4 removes the shortcut at the source — fresh full-rank operands with no additive split, §A.5/§C — so no schedule-pinning transcript is needed, and none is used, keeping verification at O(n²). See §0.7.)*

Validators confirm `C = A·B` with O(n²) Freivalds probes over the independent prime `q = 2⁶¹−1` (§D.3) — never over the composite modulus `M` (§D.2); the full protocol is §D.

### A.4 Solve and Verify

```
Solve(header, params, max_tries):
    T ← DeriveTarget(header.nBits, params.powLimit)
    while max_tries > 0:
        seed_A, seed_B ← SeedsV4(header, height)          # A.2; includes nNonce64
        A_m ← SampleMatrix(XOF(seed_A||m), n, p_m) for m in 1..k   # fresh, dense, full-rank whp
        B_m ← SampleMatrix(XOF(seed_B||m), n, p_m) for m in 1..k
        C   ← INT8_MATMUL(A, B)                            # reference path: Θ(k·n³) exact s8×s8→s32, no gate
                                                           # (optimal sketch miner evaluates Ĉ=(U·A)(B·V) directly, §E.3)
        d   ← ProductCommittedDigest(sigma, C, n, b)       # O(n²)
        max_tries -= 1
        if d ≤ T: header.matmul_digest ← d; return true
        header.nNonce64 += 1
    return false

Verify(header, params, height):                            # O(n²) — never recomputes A·B
    T ← DeriveTarget(header.nBits, params.powLimit)
    if UintToArith256(header.matmul_digest) > T: return false   # cf. src/matmul/matmul_pow.cpp:282-291
    C ← block.matrix_c_data                                # full-C profile shown; default ships sketch Ĉ (§0.7-(3), §E)
    if ProductCommittedDigest(sigma, C, n, b) != header.matmul_digest: return false
    seed_A, seed_B ← SeedsV4(header, height); regenerate A, B streaming
    return Freivalds(A, B, C, sigma, R)                    # §D, O(R·n²) over 𝔽_q, q = 2⁶¹−1
```

Structural difference from v3 `Solve` (`src/matmul/matmul_pow.cpp:293-336`): operand derivation moves **inside** the nonce loop (v3 hoists `FromSeed` above it, lines 306-307, because pre-fix operands were nonce-invariant), and the `noise::Generate`/`E_L·E_R` construction (v3 lines 314-319; `src/matmul/noise.cpp:144-157`) is deleted entirely.

**Acceptance rule.** A header is valid iff `matmul_digest ≤ T`, the digest recomputes from the shipped `C`, and Freivalds confirms `C = A·B`. There is no pre-hash gate condition.

### A.5 Removals from v3, and why

**Removal 1 — the pre-hash epsilon gate is eliminated (`ε = 0`).** v3 requires `sigma ≤ T << ε` before a nonce may enter the matmul (`CheckMatMulPreHashGate`, `src/pow.cpp:2688-2697`), with `ε = 18` bits since height 50,000 (`src/consensus/params.h:156-161`; `src/kernel/chainparams.cpp:237-238`). Consequently only 1 in 2¹⁸ ≈ 262,144 nonces touches the matmul — **the v3 workload is a SHA-256 lottery with occasional matmul decoration**, and selection pressure rewards hash throughput, not matrix throughput. v4 removes the gate; every nonce pays the full GEMM.

**Removal 2 — low-rank noise is eliminated (`r` removed).** v3 computes `A' = A + E, B' = B + F` with rank-`r=8` `E = E_L·E_R, F = F_L·F_R` (`src/matmul/noise.cpp:144-157`; mainnet `r=8`, `src/kernel/chainparams.cpp:167`). Since `A'B' = AB + AF + EB + EF` with `AB` cacheable, a miner replays the digest in `O(n²·r)` (the in-tree `PrecomputeCleanBlockProducts`/`ReplayCanonicalHashWithReusableCleanProducts`, `src/matmul/transcript.cpp:313-399`, ~64× discount). v4's operands are the fresh pseudorandom matrices themselves — no clean/noise split, no rank parameter, no cacheable additive term.

### A.6 Per-nonce cost is a hard dense-GEMM bound — Θ(n³) full-C, Θ(n³·2/b) sketch

Per nonce the enforced work is a dense INT8 tensor-core GEMM with no sub-dense shortcut. Under the full-C profile it is `k·n³` MACs plus `O(k·n²)` sampling/commit — `k·n³·(1+o(1))`. Under the **default sketch payload** the optimal miner computes `Ĉ = (U·A)(B·V)` directly, so the enforced unit is `k·(2n²m + nm²) = k·n³·(2/b)·(1+o(1))` MACs (§E.3, §0.7-(3)) — a constant-factor (b/2 = 8) rescale of the same dense-GEMM hardware profile, priced into difficulty (§I.4). In either profile there is no path around the dense-GEMM term:

- **No cross-nonce reuse.** `A, B` are functions of `nNonce64` (A.2); nothing from nonce `x` recurs at `x+1`.
- **No low-rank shortcut.** Operands are dense i.i.d. samples (full rank whp per channel); there is no constructed `C = C_cached + Δ_lowrank` because nothing is shared across nonces.
- **Strassen / sub-cubic.** Not forbidden, made non-remunerative: to pass Freivalds the miner must produce the *correct* committed image of `A·B`, and integer Strassen at n=4096 (2–3 feasible levels) saves ≤ ~1.2–1.3× while its block linear-combinations exceed the s8 input range (needing ≥ s16 operands no s8×s8→s32 MMA accepts) and its extra `Θ(n²)` add passes run on integer ALUs, not tensor cores. Any residual constant-factor edge is absorbed by difficulty calibration (§N-risk-ii), exactly like any miner optimization — not a break, because the unit of work is "the correct product," and `N³` tile products of `b³` MACs is the cheapest way to produce it on tensor cores.

---

## B. Arithmetic: an INT8 tensor-core field

### B.1 Requirements

v3 pins every backend to 32-bit integer ALUs: `Element = uint32` over GF(2^31−1) (`src/matmul/field.h:15-16`), and neither CUDA (`src/cuda/matmul_accel.cu`) nor Metal (`src/metal/matmul_accel_kernels.metal`) contains any tensor-core/`mma`/`wmma`/cuBLAS/INT8/DP4A path. The v4 number system must: (1) map the inner loop onto s8×s8→s32 (or u8×u8→s32) MMA units; (2) be **exact** — integer MMA has no rounding, so results are bit-identical across vendors/schedules *provided the s32 accumulator never overflows*; (3) reduce to a canonical form so every implementation serializes identical bytes; (4) provide a large effective modulus for the digest alphabet and Freivalds. FP8/BF16/FP16-accumulate are excluded: floating accumulation rounds per partial sum, making results order- and vendor-dependent.

### B.2 Candidate (i): single small prime `p < 2^8`

**Unsigned, `p = 251`.** Canonical `x ∈ [0,251)`, stored u8; sample one XOF byte, reject ≥ 251 (2.0%). GEMM u8×u8→s32; one Barrett/`%` reduction per output element. No dual representation.

**Signed Mersenne, `p = 127 = 2^7−1`.** Canonical `x ∈ [0,126]`; reduce s32 `S` by shift-add fold `S = (S & 127) + (S >> 7)` (≤4 folds) then a conditional subtract. **Dual-zero:** `127 ≡ 0`; samplers never emit 127, reducer maps 127→0, canonical range strictly `[0,127)`. A balanced variant `[−63,63]` (s8) quadruples headroom (see B.4).

*Assessment:* simple, `k=1`, maximal headroom — but ~7–8-bit alphabet gives per-round Freivalds soundness only 1/127…1/251, forcing many rounds.

### B.3 Candidate (ii): CRT residue decomposition over `k` small primes — **optional compute-multiplier (non-baseline)**

> **Normative status (§0.7):** the v4 baseline is **k = 1** — a single exact-integer s8 matmul (Candidate (i)-style operands: dense pseudorandom s8 in `[-125,125]`, exact INT32 product `C = A·B`), verified by Freivalds over the independent prime `q = 2⁶¹−1`. The CRT/multi-prime construction below is an **optional, off-by-default** way to multiply the per-nonce work by `k` (k independent s8 GEMMs, each committing its own exact-INT32 lane product and Freivalds-verified over `q` separately, at ×k verification cost). It is retained for completeness; all `k = 4` figures in §B are illustrative of that variant. For the baseline, read the following with k = 1 (single lane), and divide per-nonce MAC counts and operand-storage figures by k.

```
p_1=251, p_2=241, p_3=239, p_4=233   →   M = 3,368,562,317 ≈ 2^31.65
```

Operands live in `Z_M`; by CRT `Z_M ≅ Z_251×Z_241×Z_239×Z_233`, sample each residue uniformly (byte rejection; 2.0/5.9/6.6/9.0%) and the element is exactly uniform over `Z_M` with no wide-integer arithmetic in the hot path. **Normative representation:** each residue is stored as its **balanced representative** in `[−(p_i−1)/2, (p_i−1)/2]` (s8) — `[−125,125]` for p₁ = 251 (§G.2) — so every channel is an s8×s8→s32 GEMM. **Layout:** `k` planar s8 matrices per operand (each `n²` bytes) — residue-planar, so each channel is a standard s8 GEMM; the per-nonce matmul is `k` independent s32-accumulated INT8 GEMMs (the v3 "split16" 4×-GEMM idea, now on tensor cores), perfectly parallel across SMs/devices.

| Criterion | (i) single p=251 | (ii) CRT k=4 |
|---|---|---|
| Effective modulus | 251 ≈ 2^8 | M ≈ 2^31.65 ≥ v3's 2^31−1 |
| Freivalds soundness/round | 2^−8 | ≤ 1/233 per round; R rounds compound (§D) |
| Transcript/commit word entropy | ~8 bits | ~31.6 bits/element |
| Tensor-core mapping | 1 GEMM | k independent GEMMs |
| MACs/nonce | n³ | k·n³ (raises compute floor; absorbed by difficulty) |

Candidate (i) is an acceptable minimal profile; the normative v4 arithmetic is (ii).

### B.4 Exact INT32 overflow bound

Each s32 accumulator sums `n` products of canonical elements; with `E_max` the max magnitude, `n·E_max² ≤ 2^31−1` ⟹ `n_max = ⌊(2^31−1)/E_max²⌋`:

| Encoding | E_max | E_max² | n_max |
|---|---|---|---|
| **s8, p=251 balanced [−125,125] (normative, §G.2)** | 125 | 15,625 | **137,438** |
| u8, p=251 unsigned [0,250] | 250 | 62,500 | 34,359 |
| u8, raw [0,256) | 255 | 65,025 | 33,025 |
| p=127, [0,126] | 126 | 15,876 | 135,266 |
| p=127 balanced [−63,63] s8 | 63 | 3,969 | 541,064 |

Under the normative balanced encoding any `n ≤ 137,438` — in particular every header-expressible `n ≤ 65,535` (§G.4-#3) — runs the whole reduction dimension in one un-reduced s32 accumulation (one reduction per output element). For `n > n_max`, split the K-dimension into panels of depth `≤ n_max`, reduce each to the canonical balanced range `[−(p_m−1)/2, (p_m−1)/2]`, and sum panel residues before a final reduce; since `x ↦ x mod p_m` is a homomorphism, reduce-then-sum = sum-then-reduce, so **the panel partition is not consensus-visible**. The only consensus-fixed granularity is the commit tile `b`.

### B.5 Recombination: CRT reconstruction (Garner, u64)

Needed only where a `Z_M` value is materialized (e.g. CRT-reconstructing committed residue planes to canonical integers, §D.3-(1)); never inside the GEMMs — and never as the Freivalds field: the check runs over the independent prime `q = 2⁶¹−1` (§D.2/§D.3).

```
d_1 = x_1
d_2 = (x_2 − d_1)·217                        mod 241
d_3 = ((x_3 − d_1)·20  − d_2)·120            mod 239
d_4 = (((x_4 − d_1)·13 − d_2)·204 − d_3)·39  mod 233
x   = d_1 + 251·( d_2 + 241·( d_3 + 239·d_4 ) )    # x ∈ [0,M), fits u64
```

Inverse constants (each verified): 251⁻¹ mod 241 = 217; 251⁻¹ mod 239 = 20; 241⁻¹ mod 239 = 120; 251⁻¹ mod 233 = 13; 241⁻¹ mod 233 = 204; 239⁻¹ mod 233 = 39. Max reconstruction = M−1 = 3,368,562,316. For balanced (signed) quantities, lift `x ∈ [0,M)` to `x − M` iff `x > (M−1)/2`; the lift is unique whenever `2·|value| < M` (§D.3-(1)).

### B.6 Determinism argument

(1) s8×s8→s32 / u8×u8→s32 MMA is exact (two's-complement multiply-add, no rounding); given B.4 no accumulator wraps, so the s32 result equals the mathematical dot product. (2) Integer addition is associative/commutative ⇒ result independent of accumulation order, warp/CTA mapping, split-K, or fragment shape — NVIDIA IMMA, AMD MFMA, Apple integer simdgroup/DP4A, AVX-512 VNNI all produce the identical value (contrast FP8/BF16, which round per partial sum and are not bit-reproducible, [arXiv:2511.00025](https://arxiv.org/pdf/2511.00025)). (3) Canonical reduction is a pure function (127→0 for the Mersenne profile). (4) Compression, Garner, SHA256d are deterministic byte functions. Hence `Verify` on any conforming backend reproduces the miner's digest bit-for-bit.

### B.7 Worked instantiation at `n = 4096`

| Quantity | Value |
|---|---|
| Dimension, tile | n=4096, **b=8, m=512** (baseline k=1; N is per-lane) |
| Channels | **k=1 baseline** (single exact-integer s8 matmul, §0.7); optional CRT compute-multiplier k>1 {251,241,239,233} off by default (Appendix D) |
| Operand storage | k=1: 2 s8 matrices × n² B = **32 MiB**/nonce (CRT k=4 variant: 8 residue matrices = 128 MiB) |
| MAC count | full product k·n³ = 2^36 ≈ 6.9×10¹⁰ INT8 MACs (~1.37×10¹¹ ops)/nonce at k=1; optimal sketch miner ≈ 2n²m ≈ 1.8×10¹⁰ MACs (§E.3, b=8) — sub-ms at INT8 tensor-core peak either way |
| Accumulator peak | 4096·125² = 6.4×10⁷ < 2^31−1 (balanced residues, §B.4); headroom ×33.6; no mid-K reduction |
| Payload | sketch Ĉ: 8·m² = **2 MiB** (default, b=8, §E.1); full-C alternative: n² int32 = 64 MiB |
| Commit overhead | ≪ 1% of GEMM MACs |

---

## C. Anti-amortization and hardness invariants

v4's posture: **every accepted digest certifies one full dense matmul, and no cheaper computation produces an acceptable digest.**

- **I1 — Nonce-fresh operands (with per-block memorylessness).** `seed_A/seed_B` commit to `(hashPrevBlock, height, nVersion, hashMerkleRoot, nTime, nBits, nNonce64, matmul_dim, parent_mtp, which)` (A.2). No operand/product/partial shared across nonces; extends the v3 nonce-fold fix. **Corollary (rent-and-dump bound):** because the seed binds `hashPrevBlock` (and parent MTP), *nothing* is computable before the parent block exists — a rent-burst attacker gets zero head start, cannot pre-mine during cheap-rental idle windows, and cannot stockpile work across blocks. This per-block memorylessness is the strongest non-batchability property available to a progress-free PoW, and combined with ASERT (§I.4, 3,600 s half-life) it is the complete in-model bound on spot-rental mine-and-dump (§S.4.4).
- **I2 — Full-rank dense operands.** i.i.d. uniform per channel; no rank parameter, no `noise::Generate`, no structured component.
- **I3 — No reusable additive split.** v4's product has no term independent of `nNonce64`; the clean-products cache has nothing to hold.
- **I4 — (non-normative, see §0.7).** Schedule-pinning via an intermediate transcript is *not used* in v4; work-forcing comes from I1–I3 + Freivalds on the final product, keeping verification O(n²). Retained here only to document why v3's linear-compression replay has no v4 analogue: there is no cacheable additive term to compress.
- **I5 — No pre-hash lottery.** `ε=0`; every nonce runs the dense GEMM; the cheapest nonce costs Θ(k·n²·m) (sketch profile; Θ(k·n³) full-C, §E.3), not one SHA-256d.
- **I6 — Bit-exact arithmetic.** Acceptance requires exact digest reproduction (B.6); approximate/low-precision "estimate then patch" cannot substitute.
- **I7 — Nonce-fresh sketch challenge.** The sketch projectors `U, V` and the Freivalds vectors `x, y, r` MUST derive from `σ = SHA256d(header)` *including* `nNonce64`, and the round challenges MUST bind the payload hash (Fiat–Shamir, §D.1). This forecloses every cross-nonce projection cache — a template-constant `U` would make `U·A`-style objects reusable across nonces — and hardens the §3 sketch work-binding. Currently implicit; made normative.
- **I8 — Work-unit uniformity.** Every nonce's resource footprint (FLOPs, bytes touched, working set) MUST be identical and nonce-independent. This is the structural anti-selection-filter invariant: the moment a resource requirement varies with the nonce, a cheap PRF grind converts the variation into a discount (the §L.4 selection-filter attack), recreating a filterable lottery in resource-space exactly as a pre-hash gate does in hash-space (I5). It is the reason no capacity/bandwidth gate can be smuggled in per-nonce (§L.4).

Shortcut-to-invariant map:

| v3 shortcut | v3 cost effect | v4 invariant that closes it |
|---|---|---|
| Pre-hash epsilon gate | matmul on 2⁻¹⁸ of nonces; PoW → SHA lottery (`src/pow.cpp:2688-2697`) | **I5** |
| Low-rank noise amortization | O(n²r) via cached AB + factorized corrections, ~64× (`src/matmul/noise.cpp:144-157`; `transcript.cpp:313-399`) | **I2 + I3** |
| Cross-nonce A,B reuse (pre-125,000) | per-tip operands amortized, ~12.8× (`src/pow.cpp:58-62`) | **I1** |
| Linear transcript-compression replay | `(uᵀA)(Bv)` factorization, O(b²)/step (`transcript.cpp:362-392`) | **I2+I3** (no cacheable term) + digest on final C only |
| Strassen / sub-cubic | ~(7/8)^levels multiply savings in principle | non-remunerative: Freivalds demands the correct dense C; s8-range + constant-factor barriers (A.6) |
| Reduced-precision approximation | fast approximate product | **I6** — digest equality demands bit-exact C |
| Sketch evaluation shortcut `(U·A)(B·V)` (v4-specific) | factor b/2 = 4 below full n³ at b=8 (§E.3) | acknowledged, not closed: same dense INT8 tensor-GEMM profile, priced into difficulty (§0.7-(3), §I.4); strict n³ binding needs full-C or ZK (§F.4d) |
| Nonce-dependent resource footprint (would-be capacity/bandwidth gate) | selection-filter grind → per-nonce discount → filterable lottery (§L.4) | **I8** — work-unit uniformity; also why no capacity gate exists (§L.4) |
| Cross-nonce sketch-projector cache | reuse `U·A`-type objects if `U` is template-constant | **I7** — nonce-fresh `U,V` and Freivalds challenges |

Together I1–I3 and I5–I8 make the marginal cost of a nonce equal the average cost — a dense INT8 tensor-core GEMM of `k·n³·(2/b)` MACs under the default sketch payload (`k·n³` under full-C; §E.3) — with all identified v3 amortization channels (and the resource-footprint and projector-cache channels a would-be capacity gate would open) structurally absent rather than parameter-disabled, and with verification held at O(n²).

---

## D. Freivalds verification over the v4 field

### D.1 The check

v4 keeps the v3 verification contract — a deterministic, non-interactive Freivalds check (`src/matmul/freivalds.h:24-41`, `src/matmul/freivalds.cpp`) — and changes only the field arithmetic and round schedule. Per round `t = 1..R`:

1. Derive challenge vector **r**ₜ deterministically from the header: `r_t = DeriveRandomVector(H(σ ‖ H(payload)), t, n)` — the v4 extension of `DeriveRandomVector` (`src/matmul/freivalds.h:25`). The hash **must** bind the claimed product object (Fiat–Shamir), exactly as v3 binds the challenge seed to `(A, B, C, σ)` (`doc/freivalds-algorithm-analysis.md`), so a miner cannot choose the payload after seeing the challenge.
2. Compute **y** = B·**r**ₜ, then **z** = A·**y**. Because A and B are regenerated from the header seeds, **z is the true C·r**ₜ **obtained without ever forming C** — two O(n²) matvecs.
3. Compare **z** against the claimed object: `C·r_t == z` when full C is shipped, or the projected form `xᵀ·Ĉ·y == (Uᵀx)ᵀ·A·(B·(V·y))` for the sketch payload of §E (same asymptotics; see E.2).
4. Accept iff all R rounds match and the product-committed digest recomputed from the payload equals `matmul_digest` (the v4 analogue of `ComputeProductCommittedDigest`, `src/matmul/transcript.cpp:485-509`, wired as in `src/pow.cpp:2831-2965` and `src/validation.cpp:10145-10196`).

> **Why this is cheap (the load-bearing property).** The verifier performs *no* O(n³) work anywhere: seed-expansion of A and B is O(n²), each round is two or three O(n²) matvecs, and the digest recompute is O((n/b)²). The n³ product exists only on the miner's side. This is the entire asymmetry the design rests on, and it is why the answer to "can we efficiently do Freivalds?" is an unqualified **yes** — quantified in D.4.

### D.2 Soundness in a small field — the problem

v3 runs 2 rounds over GF(2³¹−1) for error < 2⁻⁶² (`src/matmul/freivalds.h:33-36`, `src/consensus/params.h:180-183`, modulus at `:144`). v4's compute field is small: a prime p < 2⁸, or k such primes combined by CRT with P = ∏pᵢ ≈ 2³². Freivalds' per-round error is 1/|F|, so a small field is punishing:

| Field for the check | Per-round error | Rounds for ≤ 2⁻¹⁰⁰ | Rounds for ≤ 2⁻¹²⁸ |
|---|---|---|---|
| 𝔽ₚ, p = 251 | 1/251 = 2⁻⁷·⁹⁷ | **13** | **17** (16 rounds give only 2⁻¹²⁷·⁵) |
| 𝔽ₚ, p = 127 | 1/127 = 2⁻⁶·⁹⁹ | **15** | **19** |
| ℤ_P, P = 251·241·239·233 ≈ 2³¹·⁶⁵ | **1/233 = 2⁻⁷·⁸⁶ (not 1/P!)** | 13 | 17 |
| 𝔽_q, q = 2⁶¹−1 (recommended) | 2⁻⁶¹ | **2** | **3** |
| GF((2³¹−1)²) extension (reuses v3 field code) | ≈ 2⁻⁶² | **2** | **3** |

> **Correction — the composite-modulus trap.** Running the check "over the CRT-reconstructed modulus P" does **not** give error 1/P. ℤ_P is a ring, not a field: an adversary can localize the error to a single CRT plane (make ΔC ≡ 0 mod every prime except one). The residual Δ·r then vanishes automatically modulo the clean primes, and the per-round catch probability collapses to 1/p_min ≈ 2⁻⁷·⁹ — no better than a single small prime. Any v4 text claiming 1/P soundness over ℤ_P must not ship.

### D.3 Soundness restored — lift to exact integers, verify modulo one big prime

The fix is native to the v4 compute path. INT8 inputs with exact INT32 accumulation mean the *true* product entries are exact integers: with balanced entries in [−125, 125] (§B.4, p₁ = 251), |C_ij| ≤ n·125² = 15,625·n < 2³⁰ for every header-expressible n ≤ 65 535. Therefore:

1. **Commit the exact integer product** `C = A·B` — the native `s8×s8→s32` GEMM output, an exact INT32 matrix (k = 1 baseline, §0.7). Payload words are range-checked for canonicality, as v3 does at `src/pow.cpp:2867`. *(Optional k > 1 CRT variant: each lane commits its own exact-INT32 lane product `C⁽ᵐ⁾ = A⁽ᵐ⁾·B⁽ᵐ⁾` and is Freivalds-verified over `q` separately — there is no reconstruction to `Z_M`, and payload/verify cost scale ×k.)*
2. **Run Freivalds over an independent large prime q = 2⁶¹−1** (Mersenne; one 64-bit multiply + fold per MAC), or over the quadratic extension GF((2³¹−1)²) if reusing the existing `matmul::field` code is preferred. Since any two distinct canonical committed values differ by |Δ| < 2³² < q, a wrong integer entry can never reduce to a matching residue: per-round error ≤ 1/q.

**Consensus parameters:** `R = 3` rounds (error ≤ 2⁻¹⁸³, exceeding the 2⁻¹²⁸ requirement; `R = 2` already gives 2⁻¹²²). This replaces v3's `nMatMulFreivaldsRounds = 2` and keeps the round count in the same regime instead of the 17–19 rounds a naïve small-field check would need.

### D.4 Cost and time — the numbers behind "yes, Freivalds is efficient"

Calibration: v3's measured bench `MatMulFreivaldsN512R2` = **569 430.56 ns per round** at n = 512 (`src/bench/matmul_freivalds_bench.cpp:46-49`; value recorded in `doc/freivalds-algorithm-analysis.md`). That is τ = 569 430 ns / 512² = **2.17 ns per element per round** (a round ≈ 3n² MACs ⇒ 0.72 ns/MAC, single-threaded, memory-bound). Scaling by n² and R, with a conservative 2× multiplier for 61-bit lanes:

| n | Ops/round (≈3n² MACs) | Per round | R = 3 (2⁻¹⁸³) | Conservative ×2 | + A,B regen (O(n²) PRF) | **Total worst-case** | % of 90 s block¹ |
|---|---|---|---|---|---|---|---|
| 4 096 | 5.0×10⁷ | 36.4 ms | 109 ms | 219 ms | 15–35 ms | **≈ 0.13–0.25 s** | 0.14–0.28 % |
| 8 192 | 2.0×10⁸ | 146 ms | 437 ms | 874 ms | 55–135 ms | **≈ 0.49–1.0 s** | 0.55–1.1 % |
| 16 384 | 8.1×10⁸ | 583 ms | 1.75 s | 3.5 s | 0.2–0.5 s | ≈ 2.0–4.0 s | 2.2–4.4 % |
| 32 768 | 3.2×10⁹ | 2.33 s | 7.0 s | 14 s | 0.9–2.2 s | ≈ 7.9–16 s | 8.8–18 % |

¹ Block interval `nPowTargetSpacingNormal = 90` s (`src/kernel/chainparams.cpp:199`).

With the sketch payload of §E (2 matvecs + one m-wide probe instead of 3 matvecs, ≈ 0.7×), the n = 4096 baseline lands at **≈ 95 ms base / ≤ 0.2 s conservative** end-to-end. The R challenge vectors can additionally be batched into a single streaming pass over A and B (matvecs are bandwidth-bound), pulling the realistic figure further under the 100 ms target.

### D.5 Hard verification budget — and n is bounded above by it

This section is normative, not advisory:

- **Budget:** worst-case full-node verification per block MUST be well under 1 s single-threaded, target < 100 ms; the C-commitment payload MUST stay ≤ a few MiB (§E). Any (n, field, R) violating either bound is out of bounds for consensus.
- **Consequence for n:** the table admits **n = 4096 (baseline, ≈7–10× ceiling margin, meets 100 ms at the base extrapolation)** and **n = 8192 (permitted maximum, ≈1.0 s conservative)**. **n ≥ 16 384 fails the single-threaded ceiling and is excluded**, independent of what mining hardware could produce.
- **n is capped by the verifier, not sized by the miner.** If the memory-gate (§M) wants a larger hardware footprint, it must come from required-resident working set, batching depth, or multi-instance requirements — **not** from raising n. Verification cost is a first-class limiter on the parameter and must stay consistent with §M.

Per-verification cost also fits inside the existing DoS envelope (global `nMatMulGlobalVerifyBudgetPerMin = 512` at `src/consensus/params.h:174`, per-peer 32/min `:147`, pending cap 16 `:146`) once rescaled for v4 (§E.4).

**Bottom line for the project requirement:** Freivalds at v4 scale is efficient — 3 rounds, 2⁻¹⁸³ soundness, ≈ 0.1 s at the n = 4096 baseline, ~0.1 % of the block interval, no O(n³) anywhere in the verifier.

---

## E. Data availability & payload

### E.1 What ships: the product sketch, not C

v3 ships the full product matrix in `matrix_c_data` (`src/primitives/block.h:96-101`) — 4n² bytes ≈ 1 MiB at n = 512 — while the digest is computed from per-block compressed words (`ComputeProductCommittedDigest`, `src/matmul/transcript.cpp:485-509`; active on mainnet at height ≥ 61 000, `src/kernel/chainparams.cpp:187-188`). Full-C shipping does not survive the v4 scale-up:

| Payload option | Bytes | n = 4096 | n = 8192 | n = 16 384 | n = 32 768 |
|---|---|---|---|---|---|
| Full C (v3 style) | 4n² | 64 MiB | 256 MiB | 1 GiB | 4 GiB |
| Sketch Ĉ, b = 8 (m = n/8) | 8m² | 2 MiB | 8 MiB | 32 MiB | 128 MiB |
| **Sketch Ĉ, b = 16** | 8m² | **512 KiB** | **2 MiB** | 8 MiB | 32 MiB |
| Sketch Ĉ, b = 32 | 8m² | 128 KiB | 512 KiB | **2 MiB** | 8 MiB |

**v4 ships only the compressed per-block commitment**: the sketch **Ĉ = U·C·V ∈ 𝔽_q^{m×m}**, m = n/b, where U (m×n) and V (n×m) are dense σ-derived pseudorandom matrices (the v4 generalization of `DeriveCompressionVector`/`CompressBlock`, `src/matmul/transcript.cpp:185-230`), words canonical mod q = 2⁶¹−1 (8 bytes). The header digest is `matmul_digest = H(σ ‖ Ĉ)`, recomputed by every verifier in O(m²). Recommended and normative network-wide: **b = 8 for n ≤ 8192 (2 MiB / 8 MiB)** (`nMatMulV4TranscriptBlockSize = 8`, §G.2) — always within the few-MiB budget, versus the out-of-bounds 64 MiB–4 GiB of full C. The choice balances **three** b-sensitive quantities: the payload 8·(n/b)² shrinks with b, the §E.3 work-shortcut factor b/2 (and commitment coarseness) grows with b, and — the binding constraint from below (§K.2a) — the optimal-miner arithmetic intensity `AI_opt = 2n/b` *falls* with b, and must stay above every device's INT8 roofline ridge to keep the datacenter ordering. b = 16 (the earlier choice) gave `AI_opt = 512`, *below* the H100/B200/4090 ridges (591/563/655) — clipping datacenter throughput and leaking ~9–22 % of the compute lever; **b = 8 gives `AI_opt = 1,024 ≥ 1.56×` above every ridge** at a 2 MiB payload and a tighter 4× shortcut. b = 4 (2,048 AI, 8.4 MiB) buys no further ordering benefit once above every ridge. **b = 8 is the chosen balance** (roofline-driven, §K.2a).

A deliberate change from v3: v3's compression is *block-diagonal* (an independent b²-weight functional per b×b tile), which is **not** checkable by plain Freivalds — probing it against A·B costs Θ(b·n²) per round. Making U and V dense rank-m sketches is what turns the commitment into a plain-Freivalds-checkable object at O(n²).

### E.2 How the verifier runs Freivalds without ever holding C

Data flow per block, everything O(n²) or below:

1. **Regenerate A, B from the header seeds** — O(n²) PRF expansion (v3's `SharedFromSeed` path, cf. `src/pow.cpp:2854-2855`); ~15–35 ms at n = 4096. The verifier *never* needs the O(n³) product: A·(B·r) reproduces any projection of C directly.
2. **Digest check** — recompute H(σ ‖ Ĉ) over the ≤ 2 MiB payload (< 1 ms) and compare to `matmul_digest` ≤ target.
3. **Sketch-Freivalds rounds** — for t = 1..R = 3, derive (xₜ, yₜ) ∈ 𝔽_q^m from H(σ ‖ H(Ĉ)) and check

   **xₜᵀ · Ĉ · yₜ == (Uᵀxₜ)ᵀ · A · (B · (V·yₜ))**

   Right side: two dense O(n²) matvecs plus O(nm) projections; left side O(m²). If Ĉ ≠ U·C·V in even one word, each round catches it with probability ≥ 1 − 2/q (the test is bilinear in (x, y), total degree 2 — Schwartz–Zippel over 𝔽_q): error ≤ (2/q)³ = 2⁻¹⁸⁰ at R = 3, the sketch-form analogue of §D.3's full-C 2⁻¹⁸³.

Total at n = 4096: **≈ 95 ms** (base extrapolation from the v3 bench, §D.4), ≤ 0.2 s conservative — inside the target and far inside the 1 s ceiling.

### E.3 Work-enforcement note (coordinate with §M and §0.7)

Any linear commitment of C admits an algebraic evaluation shortcut: Ĉ = (U·A)·(B·V) can be computed in ≈ 2n²m + nm² MACs (U·A and B·V at n²m each, their m×n by n×m product at nm²) instead of the honest n³ + n²m + nm², a factor ≈ n/(2m) = b/2 (**4× at b = 8**; 3.8× counting the lower-order terms). Stated plainly:

- The **de-facto per-nonce work unit** under this payload is a dense INT8 n×n×2m GEMM (2n²m ≈ 1.72×10¹⁰ MACs at n = 4096, **b = 8, m = 512** — i.e. `n³/4 ≈ 3.44×10¹⁰` ops) — same tensor-core, same bandwidth profile as the full product, 1/4 the volume, and with arithmetic intensity `2n/b = 1,024` above every device roofline (§K.2a). Difficulty calibration in §M/§I.4 MUST assume this optimal algorithm, not the naïve n³ figure.
- v3 does not have this gap only because it ships full C and Freivalds pins all n² entries. Restoring *strict* n³ binding requires full-C payload (out of DA bounds above) or a proof of full evaluation — the optional ZK module of §F.4(d).
- Verification soundness is unaffected: no invalid block passes; the gap concerns only how much work a *valid* block proves. The work remains a dense INT8 tensor-core GEMM, so the datacenter lever (§K) and the "compute not hashing" fix are intact.

### E.4 Node tiers and DoS budgets

| Tier | Per-block cost | Storage |
|---|---|---|
| Mining | ≈ 2n²m INT8-MACs per lane per nonce (GPU tensor cores; §E.3) + digest hash | working set per §M |
| Consensus-validating | full §E.2 check: ≈ 0.1–0.2 s CPU (n = 4096) | payload to prune depth 10 000 (`src/consensus/params.h:151`): 10⁴ × 2 MiB ≈ **20 GiB rolling** (b=8) |
| Economic (high-value operator) | full check over recent window only (`nMatMulValidationWindow = 1000`, `:145`), assumevalid beneath | ≈ 500 MiB rolling |
| SPV | header-only: `matmul_digest ≤ target`, O(1) | headers only; no payload download |

DoS budgets rescaled from v3's envelope (512 global/min × ~5 ms ≈ 2.6 s CPU/min, `:172-174`), holding the same ≈3 s CPU/min ceiling (honest steady-state demand is only ~0.7 blocks/min at 90 s spacing):

| n | Verify cost | Global/min (v3: 512) | Per-peer/min (v3: 32) | Max pending (v3: 16) | Pending memory |
|---|---|---|---|---|---|
| 4 096 | ≈ 0.15 s | **20** | **4** | 16 | ~8 MiB (sketch) |
| 8 192 | ≈ 0.6 s | **5** | **2** | 8 | ~16 MiB |

Failed verifications keep v3's ban/penalty semantics (`nMatMulPhase2FailBanThreshold`, `:148`). IBD uses headers-first plus windowed/assumevalid payload checking; at 0.15 s/block full re-verification of deep history remains available but is not the default path.

---

## F. Optional ZK (Plonky2) layer — when and why

### F.1 Verdict first: not required for the recommended design

The advisor's concern — "large n makes re-verification expensive for nodes" — is resolved by §D/§E without a proof system: re-verification is O(n²), ≈ 0.1 s at baseline, 2⁻¹⁸³ sound, with zero prover-side overhead. A ZK layer must beat that to justify itself, and for the deterministic INT8 path it cannot:

| | Freivalds (§D) | Plonky2 proof of the same matmul |
|---|---|---|
| Miner overhead per block | none (payload is a by-product) | minutes-to-hours of proving (F.2) |
| Verify time | ≈ 0.1 s (n = 4096) | ~ms once proof exists |
| Extra payload | 2 MiB sketch | ≈ 43 KB proof |
| Soundness | statistical, ≤ 2⁻¹⁸⁰ | computational (hash-based, FRI) |
| Trusted setup | none | none |

**Conclusion: ZK is NOT part of the v4 baseline.** Freivalds is sufficient wherever the computation is bit-reproducible from the header — which the exact-INT32 INT8 path is by construction.

### F.2 Feasibility check: one n = 4096 matmul inside a ~90 s block

- **Naïve arithmetization:** n³ ≈ 6.9×10¹⁰ multiplication gates, before hashing the commitment in-circuit. At an optimistic 10⁶ gates/s this is ~19 hours — infeasible by ~3 orders of magnitude.
- **Sumcheck-reduced arithmetization:** Thaler's optimal matmul interactive proof achieves prover time T(n) + O(n²) and O(n²) verifier ([Thaler](https://people.cs.georgetown.edu/jthaler/OptimalMatMult.pdf)), but wrapping it in a SNARK still requires hashing C-scale data in-circuit (~10⁷–10⁸ Poseidon constraints at n = 4096) — tens of minutes.
- **State-of-the-art specialized systems:** DualMatrix proves one dense 2¹⁵×2¹⁵ product in **150.84 s** (verify 0.56 s); the same paper reports Libra at 50 s for a mere 256×256 ([Dualmatrix, Cybersecurity 2025](https://link.springer.com/article/10.1186/s42400-025-00462-6)).

**Feasibility verdict: proving even one n = 4096 matmul per block is not viable within a 90 s interval on today's provers.** GPU/GKR proving is improving fast, which is why this is a future module, not discarded.

### F.3 Plonky2 specifics (for the module, when triggered)

- **Field:** Goldilocks, p = 2⁶⁴ − 2³² + 1 — 64-bit native, ~40× speedup over 256-bit fields ([Polygon, Plonky2 deep dive](https://polygon.technology/blog/plonky2-a-deep-dive)). Exact INT32 product entries (< 2³⁰) embed with no range decomposition.
- **No trusted setup:** FRI polynomial commitments, hash assumptions only.
- **Recursion:** recursive proof ~170–300 ms on a laptop ([Polygon](https://polygon.technology/blog/plonky2-a-deep-dive); [Plonky2 paper PDF](https://docs.rs/crate/plonky2/latest/source/plonky2.pdf)).
- **Proof size:** compresses to ≈ **43 KB** at rate 1/256 (≈ 11.6 s compression); larger/faster when latency matters.

### F.4 When ZK WOULD be required

- **(a) Non-deterministic tensor paths.** A future FP8/BF16 variant is not bit-reproducible, so every recompute-based check (Freivalds included) breaks; a proof of correct evaluation against a committed rounding profile becomes **mandatory**. This is the advisor's scenario — it just doesn't apply to the deterministic INT8 baseline.
- **(b) Succinct verification demand.** SPV/bridges/chain-proof sync needing O(1) PoW validity: Plonky2 recursion folds per-block proofs into one chain proof.
- **(c) Parameter escape hatch.** If n or DA ever outgrow the §D.5/§E budgets (n ≥ 16 384), a proof replaces both the O(n²) check and the payload.
- **(d) Strict work binding.** A proof of full C evaluation closes the b/2 enforcement gap of §E.3 without shipping full C.

**Positioning:** an optional, soft-fork-gated commitment slot in the header (proof hash), default-off. Baseline consensus remains Freivalds-only.

#### F.5 Sources

- [Polygon — Plonky2: A Deep Dive](https://polygon.technology/blog/plonky2-a-deep-dive)
- [Plonky2 draft paper (PDF)](https://docs.rs/crate/plonky2/latest/source/plonky2.pdf)
- [Thaler — An Optimal Interactive Proof for Matrix Multiplication](https://people.cs.georgetown.edu/jthaler/OptimalMatMult.pdf)
- [Dualmatrix — conquering zkSNARK for large matrix multiplication (Cybersecurity, 2025)](https://link.springer.com/article/10.1186/s42400-025-00462-6)

---

## G. Consensus parameters for v4

### G.1 Activation

v4 follows the established BTX activation convention (`int32_t` height field defaulting to `std::numeric_limits<int32_t>::max()` plus an `IsXxxActive` helper, cf. `nMatMulNonceSeedHeight` at `src/consensus/params.h:167` and the named constants at `src/kernel/chainparams.cpp:42-54`). It is a **height-gated hard fork**, not BIP9: at heights `< nMatMulV4Height` the v3 rules apply unchanged; at heights `>= nMatMulV4Height` the v4 rules apply exclusively. There is no dual-algorithm grace period.

```cpp
// src/consensus/params.h (add after nMatMulProductDigestHeight, :196)
int32_t nMatMulV4Height{std::numeric_limits<int32_t>::max()};
bool IsMatMulV4Active(int32_t height) const { return height >= nMatMulV4Height; }
```

```cpp
// src/kernel/chainparams.cpp (add to the constant block at :42-54)
static constexpr int32_t BTX_MATMUL_V4_HEIGHT{172'800}; // mainnet placeholder
```

The mainnet value `172'800` is a **release-scheduling placeholder** (~17.5 days past the ≈155,870 tip at 90 s spacing); the final value must be set at tag time to guarantee at least two release cycles of deployment runway, and must never be at or below any already-mined height.

### G.2 New `Consensus::Params` fields

Symbols: `n` = dimension, `k` = prime count, `p_i` = primes, `P = ∏ p_i`, `b` = commit tile, `R` = Freivalds rounds.

| Field | Type | Default | main | testnet | testnet4 | signet | regtest | Meaning |
|---|---|---|---|---|---|---|---|---|
| `nMatMulV4Height` | int32 | INT32_MAX | 172,800† | TBD† | TBD† | TBD† | 100 | Activation height. |
| `nMatMulV4Dimension` | uint32 | 4096 | 4096 | 4096 | 4096 | 1024 | 256 | Required `matmul_dim` (`n`). |
| `nMatMulV4MinDimension` | uint32 | 4096 | 4096 | 4096 | 4096 | 1024 | 64 | Lower bound. |
| `nMatMulV4MaxDimension` | uint32 | 8192 | 8192 | 8192 | 8192 | 2048 | 1024 | Upper bound (relay/payload practicality; H.3). |
| `nMatMulV4PrimeCount` | uint32 | 1 | 1 | 1 | 1 | 1 | 1 | `k`; compute lanes. **1 = normative single exact-integer s8 matmul** (§0.7). k > 1 selects the optional §B.3 CRT compute-multiplier (extra independent s8 GEMMs, ×k verify cost); off by default. |
| `nMatMulV4TranscriptBlockSize` | uint32 | 8 | 8 | 8 | 8 | 8 | 8 | `b`; product-commit/sketch tile, m = n/b (§0.7, §E.1/§K.2a). **8** (was 16): keeps `AI_opt = 2n/b = 1,024` above every INT8 roofline ridge. |
| `nMatMulV4FreivaldsRounds` | uint32 | 3 | 3 | 3 | 3 | 3 | 2 | `R`; Freivalds rounds over q = 2⁶¹−1 (§0.7-(2), §D.3). |
| `nMatMulV4DigestScheme` | uint32 | 1 | 1 | 1 | 1 | 1 | 1 | Digest scheme (1 = SHA256d over the σ_v4-derived dense sketch Ĉ = U·C·V of exact-INT32 C, §E.1). |
| `nMatMulV4AsertRescaleNum` | uint32 | 1 | calibrated‡ | ‡ | ‡ | 1 | 1 | One-time ASERT rescale num at fork (I.4). |
| `nMatMulV4AsertRescaleDen` | uint32 | 1 | calibrated‡ | ‡ | ‡ | 1 | 1 | Rescale den. |
| `nMatMulV4GlobalVerifyBudgetPerMin` | uint32 | 16 | 16 | 16 | 16 | 32 | 1024 | Global expensive-verify budget above fork (I.5). |
| `nMatMulV4PeerVerifyBudgetPerMin` | uint32 | 4 | 4 | 4 | 4 | 8 | 1024 | Per-peer budget. |
| `nMatMulV4MaxPendingVerifications` | uint32 | 4 | 4 | 4 | 4 | 8 | 16 | Pending cap (4 × 2 MiB = 8 MiB bound at n=4096 sketch, b=8; 256 MiB under full-C). |

† Testnet/testnet4/signet heights TBD at tag time (≥ two release cycles past each tip). Regtest = 100 so tests exercise both fork sides. ‡ See I.4; 1/1 = "no rescale" (only for near-genesis activation).

The **prime set is a compile-time constant** (it defines the field):

```cpp
// src/matmul/field.h
inline constexpr uint32_t V4_PRIME_COUNT{4};
inline constexpr uint32_t V4_PRIMES[V4_PRIME_COUNT]{251, 241, 239, 233};   // P ≈ 2^31.65
```

Entries of `A`, `B` are seed-derived balanced residues in `[-125,125]` (signed INT8). A `static_assert` pins `nMatMulV4PrimeCount == V4_PRIME_COUNT`.

### G.3 v3 parameters retired or ignored at/above `nMatMulV4Height`

| v3 field | Status above fork |
|---|---|
| `nMatMulDimension`, `nMatMulTranscriptBlockSize` | Superseded by V4 fields; consulted only for `< nMatMulV4Height`. |
| `nMatMulNoiseRank` | **Retired** (no low-rank noise; `matmul::noise` never invoked for v4). |
| `nMatMulMinDimension`/`nMatMulMaxDimension` (2048) | Superseded — note v3 max (2048) is *below* v4 default (4096); bounds must be height-selected. |
| `nMatMulFieldModulus` | **Retired** — replaced by `V4_PRIMES`. |
| `nMatMulPreHashEpsilonBits` + upgrade fields | **Retired** — no pre-hash gate; `CheckMatMulPreHashGate` bypassed at v4 heights. |
| `nMatMulNonceSeedHeight`, `nMatMulParentMtpSeedHeight` | Subsumed — V4 seed rule (H.4) is unconditionally nonce- and parent-MTP-bound. |
| `nMatMulFreivaldsBindingHeight`, `nMatMulProductDigestHeight`, `fMatMulRequireProductPayload` | Subsumed — v4 blocks are always product-committed; C payload always required. |
| verify-budget/pending fields | Value-superseded by V4 budgets at v4 heights (mechanism unchanged). |
| `fMatMulFreivaldsEnabled`, `nMatMulFreivaldsRounds` | `fMatMulFreivaldsEnabled` stays true; rounds superseded by `nMatMulV4FreivaldsRounds`. |
| ASERT family, `nMatMulValidationWindow`, fail/ban thresholds | **Kept unchanged** (I.4, I.5). |

### G.4 Invariants (static_assert / chainparams-construction / `matmul_params_tests.cpp`)

1. `n % b == 0` for every accepted dim in `[Min,Max]` (4096 % 16 = 0).
2. `MinDimension ≤ Dimension ≤ MaxDimension ≤ 65535` (header `matmul_dim` is uint16, `src/primitives/block.h:38`).
3. **Exact accumulation:** balanced residues `|a|,|b| ≤ 125` ⇒ `|C_ij| ≤ n·125² = 15,625·n`; require `15,625·n < 2^31` ⇒ `n ≤ 137,438`; every header-expressible `n ≤ 65,535` is exactly representable in INT32 with no mid-matmul reduction.
4. Primes distinct, each `≤ 251 < 2^8`; `k ≥ 2`.
5. **Soundness:** Freivalds runs over the independent prime `q = 2⁶¹−1` on the exact-integer product (§D.3); per-round false-accept ≤ 1/q (≤ 2/q for the sketch form, §E.2). Require `(2/q)^R ≤ 2⁻¹²⁸` ⇒ `R ≥ 3` (R = 3 → ≤ 2⁻¹⁸⁰ sketch, ≤ 2⁻¹⁸³ full-C). The composite-modulus / per-lane small-prime bound (`1/p_min = 1/233 ≈ 2⁻⁷·⁸⁶` per round) MUST NOT be used (§D.2, §0.7-(2)).
6. `nMatMulV4Height >` tip at release on every mined network; never lowered.
7. `MATMUL_V4_MAX_PAYLOAD_WORDS = MaxDimension²` replaces the v2 cap for v4-height checks.

---

## H. Header & serialization changes

### H.1 Header: unchanged at 182 bytes

v4 **keeps the 182-byte header** (`BTX_HEADER_SIZE = 182`, static_assert `src/primitives/block.h:27-28`; order per `SERIALIZE_METHODS` `:51-54`). `GetHash()` remains SHA256d over the 182 bytes (`src/primitives/block.cpp:11-14`), so header relay, block index, and hash-keyed structures are untouched. Field reinterpretation at v4 heights: `matmul_digest` = product-committed digest of exact-INT32 C; `matmul_dim` = `nMatMulV4Dimension`; `seed_a/seed_b` = V4 seeds (H.4); others unchanged.

**Forward-compat note (not this fork):** `matmul_dim` is uint16 (cap 65,535). A future `n > 65,535` would widen it to uint32 (`BTX_HEADER_SIZE`→184, update static_assert + `SERIALIZE_METHODS`; changes `GetHash` preimages — its own hard fork). v4 does not do this; payload size (H.3) binds long before the dim field.

### H.2 v4 block payload

> **Profile note (§0.7-(3)):** H.2–H.3 specify the **full-C (strict-binding) profile**. Under the **default sketch profile** the payload is `Ĉ ∈ 𝔽_q^{m×m}` (8·m² bytes = 2 MiB at n = 4096, b = 8; §E.1), which fits every existing size limit — none of the H.3 size-limit changes are then required.

Reuses the trailing-payload serialization (`block.h:119-153`) with new rules:
- `matrix_c_data` — **required**; exactly `n²` uint32 words, row-major, each the two's-complement exact ℤ entry `C_ij = Σ_t A_it·B_tj` (`|C_ij| ≤ 15,625·n`; out-of-bound words are non-canonical → invalid).
- `matrix_a_data`, `matrix_b_data` — **must be empty** (A,B fully determined by seeds; non-empty → invalid `v4-forbidden-ab-payload`).

A single exact-INT32 `C` serves all `k` CRT lanes (reduce mod `p_i` on demand); payload size is independent of `k` and `b`.

### H.3 Payload size

`payload_bytes = 4·n²` (+7 bytes framing):

| n | words (n²) | payload | size |
|---|---|---|---|
| 4,096 | 16,777,216 | 67,108,864 | **64 MiB** |
| 8,192 | 67,108,864 | 268,435,456 | 256 MiB |
| 16,384 | 268,435,456 | 1,073,741,824 | 1 GiB |

At 90 s spacing, n=4096 ⇒ ~0.71 MiB/s ≈ 6 Mbit/s per full-block relay path. `nMatMulV4MaxDimension = 8192` excludes n=16,384 by consensus.

**Size-limit consequences (must land with the fork):**
1. `CheckBlock`'s `serialized_block_size` check (`validation.cpp:9764-9770`, `nMaxBlockSerializedSize = 24,000,000`, `params.h:274`) must, at v4 heights, operate on the payload-stripped serialization with a **separate** dedicated payload bound `4·matmul_dim² + 7`. Transaction weight limits (`nMaxBlockWeight`) are unchanged — PoW payload carries no weight.
2. `MAX_PROTOCOL_MESSAGE_LENGTH = 16,000,000` (`net.h:65`, enforced `net.cpp:788-789`) is below a 64 MiB block message; raise to accommodate `4·MaxDimension²` + tx capacity (≥ ~92 MB; a 300 MB ceiling covers n=8192).
3. Deserialization element caps (`MAX_SIZE = 33,554,432`): n=4096 (16.8 M elements) fits; **n=8192 (67.1 M) does not** — vector-length limits must be raised before any network sets `n > 4096`.
4. `MATMUL_V2_ABS_MAX_DIM{2048}`/`MATMUL_V2_MAX_PAYLOAD_WORDS` (`pow.cpp:137-138`) gate payload checks; add `MATMUL_V4_ABS_MAX_DIM{8192}`, height-selected.

### H.4 v4 seed derivation

New `DeterministicMatMulSeedV4` (alongside V1–V3 at `pow.cpp:53-100`), dispatched from `SetDeterministicMatMulSeeds` when `IsMatMulV4Active(height)`:

```
seed_which = SHA256d( "BTXMatMulSeedV4" || which || hashPrevBlock || height(le32)
                      || hashMerkleRoot || nBits(le32) || nNonce64(le64)
                      || matmul_dim(le16) || parent_mtp(le64) )     which ∈ {'A','B'}
```

Binds A,B to prevhash, height, merkle, nBits, the 64-bit nonce, dim, and parent MTP — **every (header,nonce) attempt instantiates a fresh full-rank pair** (freshness via `nNonce64`; template-replay resistance via `parent_mtp`). `ContextualCheckBlockHeader` keeps its recompute-and-compare seed equality check (`validation.cpp:9974-9995`), now dispatching V4.

### H.5 Relay and compact blocks

- Header relay never carries payload (empty-`vtx` shim, `block.h:122-129`, untouched).
- BIP152 compact blocks remain disabled at payload-carrying heights (rationale `chainparams.cpp:176-186`; `ProcessGetBlockData`), extended to all heights ≥ `nMatMulV4Height`.
- Under the full-C profile the 64 MiB payload makes full-block relay the dominant bandwidth cost; the default 2 MiB sketch keeps relay tx-dominated. DoS budgets (I.5) and the pending cap are sized against the shipped profile.

---

## I. Validation, mining & difficulty integration

### I.1 New/changed pow.cpp functions

| Function | Location | Change |
|---|---|---|
| `DeterministicMatMulSeedV4` | new (near `pow.cpp:53-100`) | H.4 preimage; prototype in `pow.h`. |
| `SetDeterministicMatMulSeeds` | `pow.cpp:102-132` | Add V4 dispatch (priority over V3/V2/V1). |
| `CheckMatMulProofOfWork_Phase1` | `pow.cpp:2665` | Add v4-height dim bounds `[Min,Max]`, `n % b == 0`; genesis special case retained. |
| `CheckMatMulPreHashGate` | `pow.cpp:2688` | **Bypassed** at v4 heights (return true). |
| `CheckMatMulProofOfWork_V4ProductCommitted` | **new** (near `:2912`) | Single v4 expensive check (I.2). |
| `IsMatMulV4PayloadSizeValid` | `pow.cpp:2819-2829` | v4 bounds; A/B empty; `matrix_c_data.size() == n²`. |
| `PopulateFreivaldsPayload` | `pow.cpp:2967` | v4 branch emits the committed payload (sketch Ĉ by default; exact-INT32 C under full-C); never A/B. |
| scheduling fns | `pow.cpp:3011-3122` | v4 heights always expensive-verify; legacy O(n³) Phase2 never fires for v4. |
| DoS budget fns | `pow.cpp:3123-3236` | Height-select v4 budgets (I.5); mechanism unchanged. |
| `SolveMatMul` | `pow.cpp:3241+` | v4 solver loop (I.3). |
| legacy `_Phase2/_Freivalds/_ProductCommitted` | `pow.cpp:2699-2965` | Unchanged; retained for `< nMatMulV4Height`; assert never invoked at v4 heights. |

### I.2 v4 verification cascade — `CheckMatMulProofOfWork_V4ProductCommitted(block, params, height)`

1. **Phase1** — `matmul_digest ≤ target`.
2. **Payload shape & canonicality** — sketch: m² words, each canonical mod q (full-C: `matrix_c_data.size() == n²`, every word `|C_ij| ≤ 15,625·n`); A/B empty.
3. **Digest recomputation** — `H_v4(σ_v4, C)` over `b×b` tiles equals `matmul_digest` (binds the header lottery to this exact C). O(n²) — hashes the shipped C, does not recompute A·B.
4. **Deterministic Freivalds, R = 3 rounds over `q = 2⁶¹−1`** (§D.3) — per round derive challenges from `H(matmul_digest ‖ round)`; check the payload against `A·(B·r)` **mod q**: sketch form `xᵀ·Ĉ·y ≡ (Uᵀx)ᵀ·A·(B·(V·y))` (§E.2; full-C form `C·r ≡ A·(B·r)`). Per-lane small-prime checks (`mod p_i`) MUST NOT be used — they collapse soundness to 1/p per round (§D.2). A,B **regenerated from seeds on the fly** (row-streamed): O(n²) time, O(n) memory beyond the payload. **No O(n³) recomputation anywhere in v4 verification.**

Wiring in `src/validation.cpp`: `CheckBlockHeader` → Phase1 (`:9584`, v4 dim bounds by height); `ContextualCheckBlockHeader` (`:9974-9995`) V4 seed recompute-and-compare, pre-hash gate skipped when `IsMatMulV4Active`; `ContextualCheckBlock` cascade (`:10112-10195`) insert a v4 branch ahead of the legacy ladder:

```
if (IsMatMulV4Active(nHeight)) {
    payload missing        → BLOCK_MUTATED   "missing-product-payload"
    A/B vectors non-empty  → BLOCK_MUTATED   "v4-forbidden-ab-payload"
    shape/canonical fail   → BLOCK_MUTATED   "invalid-product-payload"
    V4ProductCommitted fail→ BLOCK_CONSENSUS "high-hash"
    return;   // no Phase2 fallback, no transcript path
}
```

Pre-v4 ladder (`:10145-10196`) preserved for historical heights. DoS gating wraps the v4 branch exactly as today.

### I.3 Mining path

- `src/node/miner.cpp:849-1117` (MatMul fields `:1095-1114`): at v4 heights set `matmul_dim = nMatMulV4Dimension`, `nNonce64 = 0`, digest null, call `SetDeterministicMatMulSeeds` (now V4). Template seeds are placeholders (nonce in preimage), re-derived per nonce.
- `SolveMatMul` (`pow.cpp:3241+`) v4 loop: derive V4 seeds → PRG-expand A,B (balanced INT8) → one dense n×n INT8 matmul, exact INT32 accumulation on the accelerated backend (`accelerated_solver.*`, CUDA IMMA `cuda/matmul_accel.cu`, Metal `metal/matmul_accel.mm`) → `H_v4(σ_v4, C)` → accept if ≤ target. No pre-hash scan, no noise.
- `src/rpc/mining.cpp` `GenerateBlock` (`:4631`): `SolveMatMul` (`:4723`) + `PopulateFreivaldsPayload` (`:4743`, v4 fills `matrix_c_data` from the solver-returned C to avoid recompute); `ProcessNewBlock` (`:4799`) unchanged.

### I.4 Difficulty (ASERT)

ASERT machinery **kept as-is** (`CalculateMatMulAsertTarget` `:1829`, `MatMulAsert` `:2106`, `GetNextWorkRequired` `:2455`; half-life 3,600 s, spacing 90 s). Target form unchanged (`nBits` bounds `matmul_digest`); acceptance probability per attempt is uniform in the target, so ASERT needs no formula change. What changes is the **work unit**: a v3 attempt was dominated by the 18-bit pre-hash gate with an occasional n=512 matmul; a v4 attempt always pays a dense INT8 GEMM — under the default sketch payload the optimal per-nonce work is `k·n³·(2/b)` MACs (the §E.3 work unit; `k·n³` only under full-C). Attempts/s drops by a large hardware-dependent factor at the fork, so apply a **one-time target rescale + ASERT re-anchor at `nMatMulV4Height`** (mechanically identical to `nMatMulAsertRetune2`, `params.h:247-252`): `next_target = parent_target × Num/Den`, then re-anchor. The ratio must be **calibrated empirically** pre-release (benchmark the v4 reference miner — which MUST implement the optimal §E.3 `(U·A)(B·V)` evaluation, not the naïve full product — against observed v3 throughput) and encoded per network at tag time. Fresh networks set genesis/bootstrap `nBits` for the v4 work unit and leave rescale at 1/1. `btx-genesis.cpp`/`CreateBTXGenesisBlock` are untouched — genesis remains a pre-fork object.

**I.4.1 Difficulty is a price-free integrator of delivered compute (§0.7-(4)).** `CalculateMatMulAsertTarget(anchor_target, time_diff, height_diff, half_life, params)` (`pow.cpp:1829`) computes `exponent = ((time_diff − 90·(height_diff+1))·2¹⁶)/3600` and `next_target = anchor_target · 2^(exponent/2¹⁶)`. Its **complete input set** is (anchor target, two timestamps' difference, two heights' difference, 90 s spacing, 3,600 s half-life) — `MatMulAsert`/`GetNextWorkRequired` add only anchor selection and clamps. **There is no fee, exchange-rate, oracle, or any price-derived quantity anywhere in the difficulty path.** Difficulty is therefore an affine read-out of *delivered physical compute*: at ASERT's 90 s fixed point, `D_eq ∝ ν_net = TOPS_net·10¹²/W_nonce`. The only economic channel into difficulty is that price may motivate humans to point more or less hardware at the chain — which difficulty then *measures*, never *reads*. This is the mechanical content of §0.7-(4): no suppression of the print can lower difficulty, `n`, the work unit, or the floor, because none of them consume price.

**I.4.2 Response dynamics (from the aserti3 exponent).** Let `x = log₂(D/D_eq)` be difficulty's deviation from its compute-implied equilibrium. In continuous time `dx/dt = −(1 − 2^(−x))/3600` s⁻¹, linearizing to `x(t) = x₀·2^(−t/3600)` — **the deviation halves every 3,600 s of wall time (~40 nominal blocks); full convergence in ~4–5 h**, price never appearing. Two regimes:

- **(i) Genuine AI-compute growth.** For `TOPS_net(t) = TOPS₀·e^{gt}`, ASERT tracks with a constant steady-state lag `(90−t_b)/t_b = 3600·g/ln2`. Even at the *entire AI industry's* chip-stock growth (3.4×/yr, doubling ≈ 6.8 months — [Epoch AI](https://epoch.ai/data-insights/ai-chip-production)), blocks run only **0.020 % fast** (89.982 s), an emission distortion of +0.16 BTX/hr. Difficulty growth is thus an **audit trail of physical compute**: any trajectory far exceeding the Epoch envelope flags a rented-influx event (§N.3), not organic value.
- **(ii) Rent-mine-dump-withdraw (suppression transient).** A step influx multiplying nonce rate by `k` yields a **bounded one-time over-emission** `extra_blocks = (3600/(90·ln2))·Σₙ(ln k)ⁿ/(n·n!)`: **48 / 149 / 274 extra blocks** = 963 / 2,979 / 5,489 whole-network BTX at k = 2× / 5× / 10× (attacker share `(k−1)/k`), harvested over ~4–5 h at full rental cost, and *symmetric* on withdrawal (the schedule under-emits by the mirror integral — the ledger self-corrects, no parameter touched). This is the quantified content behind §S.4.4's "raises difficulty within hours," and it is **identical whether the influx is a mine-and-dump raid or genuine cloud onboarding** — ASERT cannot tell and does not need to; both are delivered compute.

### I.5 DoS budget retuning

Baseline: v3's measured bench is 569.4 µs **per round** at n=512 (`MatMulFreivaldsN512R2`, §D.4); per-round cost scales `(n/512)²`.

| Component (n=4096, R=3, k=1, sketch payload b=8) | Cost |
|---|---|
| Freivalds/round (base extrapolation) | 569.4 µs × 64 ≈ **36.4 ms** |
| Freivalds total (R=3; ×2 conservative for 61-bit lanes) | ≈ **109–219 ms** |
| Digest over 2 MiB sketch (SHA256d) | ≈ 5–10 ms (full-C 64 MiB: 45–130 ms) |
| Seed expansion of A,B (2n² ≈ 33.5 M B) | ≈ 30–60 ms |
| **Total/verification** | ≈ **140–280 ms; budget at 300 ms** |

- `nMatMulV4GlobalVerifyBudgetPerMin = 16` → ≤ ~4.8 s CPU/min; ~24× headroom over 0.67 blocks/min steady state.
- `nMatMulV4PeerVerifyBudgetPerMin = 4` (was 32) — one peer ≤ ~1.2 s CPU/min.
- `nMatMulV4MaxPendingVerifications = 4` (was 16) — pending payload ≤ 2 MiB (sketch; 256 MiB under full-C).
- Failure handling unchanged: misbehavior scores 20/100 (`pow.h:134-135`), ban threshold 1. Motivation for threshold 1: a bogus payload costs the victim ≤ ~0.3 s CPU before the ban; under the full-C profile the attacker also pays a 64 MiB upload (bandwidth-binding). Both are bounded by the budget + pending caps.
- IBD relaxation and `nMatMulValidationWindow = 1000` sampling unchanged; with sampling, full-history v4 IBD stays download-bound, not Freivalds-bound.

---

## J. File-by-file hard-fork modification checklist

"5 networks" = `CMainParams` (~:164), testnet (~:537), testnet4 (~:719), signet (~:931), regtest (~:1092) in `src/kernel/chainparams.cpp`.

| # | File | Where | Change |
|---|---|---|---|
| 1 | `src/consensus/params.h` | `:136-196`, helpers `:389-446` | Add all G.2 fields + `IsMatMulV4Active`; doc the retired G.3 fields. |
| 2 | `src/kernel/chainparams.cpp` | constants `:42-54`; 5 networks | Add `BTX_MATMUL_V4_HEIGHT`; assign every G.2 field in all 5 constructors; extend compact-block comment `:176-186`; construction asserts for G.4. |
| 3 | `src/primitives/block.h` | `:24-28`, `:51-54`, `:91-153` | **No structural change** (182-byte header, serialization). Update payload comment (`:96-101`) for v4 (C required, A/B forbidden); record uint32-dim forward-compat note. |
| 4 | `src/primitives/block.cpp` | `:11-14` | None (`GetHash` unchanged); verify via `matmul_header_tests.cpp`. |
| 5 | `src/pow.h` | `:134-229` | Prototypes: `DeterministicMatMulSeedV4`, `CheckMatMulProofOfWork_V4ProductCommitted`, `IsMatMulV4PayloadSizeValid`; update `ShouldRunMatMulExpensiveVerification` comment for v4. |
| 6 | `src/pow.cpp` | seeds `:53-132`; caps `:137-138`; ASERT `:1829/2106/2455`; Phase1/gate `:2665/2688`; validators `:2737-2829`; product-committed `:2912`; payload `:2967`; scheduling `:3011-3122`; budgets `:3123-3236`; `SolveMatMul` `:3241+` | All I.1–I.5 changes. |
| 7 | `src/validation.cpp` | `:9584`, `:9760-9770`, `:9974-9995`, `:10112-10198` | V4 seed equality; skip pre-hash gate at v4; v4 cascade branch (I.2) with reject codes; payload-stripped block-size + dedicated payload bound. |
| 8 | `src/net.h`/`net.cpp`/`net_processing.cpp` | `net.h:65`, `net.cpp:788-789`, `ProcessGetBlockData` | Raise `MAX_PROTOCOL_MESSAGE_LENGTH` + audit `MAX_SIZE` vector reads for 64 MiB messages; keep BIP152 serving disabled through v4. |
| 9 | `src/node/miner.cpp` | `:849-1117` | v4 dim; V4 seeds; comment update. |
| 10 | `src/rpc/mining.cpp` | `:4631/4723/4743/4799` | v4 solve + C-payload population from solver-returned C; no RPC interface change. |
| 11 | `src/matmul/field.{h,cpp}` | — | `V4_PRIMES`/count, balanced-residue sampling, per-lane reduction, CRT constants. |
| 12 | `src/matmul/freivalds.{h,cpp}` | — | Deterministic Freivalds over `q = 2⁶¹−1` on the exact-integer product (§D.3; sketch form §E.2 — never per-lane mod p_i, §D.2) with streamed seed-regenerated A/B (O(n) memory); round challenge derivation. |
| 13 | `src/matmul/transcript.{h,cpp}` | — | v4 digest: σ_v4-derived dense U,V; sketch Ĉ = U·C·V over 𝔽_q; digest H(σ ‖ Ĉ) (scheme 1, §E.1). Legacy `CanonicalMatMul` retained for pre-fork validation. |
| 14 | `src/matmul/noise.{h,cpp}` | — | **No new code**; retained for pre-fork history; assert never called at v4 heights. |
| 15 | `src/matmul/matrix.{h,cpp}`, `accelerated_solver.{h,cpp}`, `solver_runtime.{h,cpp}`, `backend_capabilities.{h,cpp}` | — | INT8-operand/INT32-accumulator path; v4 solver pipeline (no pre-hash, no noise); INT8-tensor-core capability flag + CPU fallback. |
| 16 | `src/cuda/matmul_accel.cu`, `cuda/cuda_scheduler.cpp` | `src/CMakeLists.txt:466-475` | INT8 IMMA n=4096 kernel, exact INT32 accumulation; scheduler sizing. |
| 17 | `src/metal/matmul_accel.mm`, `matmul_accel_kernels.metal`, `matmul_accel_env.cpp` | `src/CMakeLists.txt:395-460` | Metal simdgroup INT8 kernels; metallib target picks them up. |
| 18 | `src/CMakeLists.txt` | `:285-292`, `:391-476` | Register any new files; no target-structure change. |
| 19 | `src/test/matmul_*` + `src/test/fuzz` | — | G.4 invariant asserts; prime-lane + CRT vectors; V4 seed vectors; deterministic Freivalds accept/reject (single-lane corruption); fork-boundary validation (last v3 / first v4, wrong dim, forbidden A/B, missing/malformed/non-canonical C, digest mismatch); payload size-limit interaction; ASERT rescale/re-anchor; regtest e2e across height 100; budget retuning. |
| 20 | `src/btx-genesis.cpp` | `chainparams.cpp:315-323` | **Untouched** for existing networks; genesis stays pre-fork. |

**Explicitly NOT modified:** PQ signatures (`src/libbitcoinpqc`, `src/script/pqm.*`, `interpreter.cpp` ML-DSA/SLH-DSA), and the shielded pool + its formal-verification artifacts/generators. The v4 diff must contain no hunks under these paths; CI should enforce a path guard on the fork branch.

**Editor's load-bearing findings:** (1) v3 payload validators cap dim at 2048 (`pow.cpp:137`, `params.h:143`), *below* v4's 4096 — height-selected bounds are mandatory. (2) Under the full-C profile the 64 MiB C payload at n=4096 exceeds `nMaxBlockSerializedSize` (24 MB) and `MAX_PROTOCOL_MESSAGE_LENGTH` (16 MB), and n=8192 exceeds the `MAX_SIZE` element cap — H.3/J#7-8 are fork deliverables **only if** full-C is chosen; the default 2 MiB sketch requires none of them (§0.7-(3)).

---

## K. Hardware economics & the datacenter lever

### K.1 Tensor throughput landscape (dense, deterministic-relevant dtypes)

All figures are **dense** peak throughput; 2:4 structured-sparse peaks (marked \*) are shown for completeness but are irrelevant to v4, since PoW matrices are full-rank dense by construction.

> **Correction (governed by §P):** the consumer Blackwell INT8 rows below were originally ~2× low — they quoted the FP8-with-FP32-accumulate rate. GeForce halves *floating-point*-accumulate throughput but runs **INT8→INT32 at full rate**, and v4 uses INT8, so the true dense INT8 is **RTX 5090 = 838 TOPS, RTX 5080 = 450.2 TOPS** ([RTX Blackwell whitepaper, App. A/B](https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf)). The corrected per-device datacenter lever is **H100 ≈ 2.4× / B200 ≈ 5.4× over a 5090** (not the ~5×/~11× printed in the ratio prose of §K.3/§O). §P is authoritative for all consumer-GPU INT8 figures and cross-generation ratios; the numbers there supersede the estimates in this table and in §K.3/§O where they differ. Direction of every conclusion (datacenter wins per device and per watt; consumer/Apple pooled-viable) is unchanged.

| Device | FP64 | BF16/FP16 | FP8 | INT8 (s8×s8→s32) | Memory | Bandwidth |
|---|---|---|---|---|---|---|
| NVIDIA H100 SXM5 | ~60–67 TFLOPS | ~990 TFLOPS (1,979\*) | ~1,979 TFLOPS (3,958\*) | **~1,979 TOPS** (3,958\*) | 80 GB HBM3 | 3.35 TB/s |
| NVIDIA H200 | as H100 (same die) | as H100 | as H100 | **~1,979 TOPS** | 141 GB HBM3e | 4.8 TB/s |
| NVIDIA B200 | ~40 TFLOPS (cut vs Hopper) | 2,250 TFLOPS (4,500\*) | 4,500 TFLOPS (9,000\*) | **4,500 TOPS** (9,000\*) | 192 GB HBM3e | ~8 TB/s |
| GeForce RTX 5090 | — | 209.5 TFLOPS | ~419 TFLOPS | **838 TOPS** dense (1,676 sparse) — corrected, see §P | 32 GB GDDR7 | 1.79 TB/s |
| GeForce RTX 5080 | — | 112.6 TFLOPS | ~225 TFLOPS | **450.2 TOPS** dense — corrected, see §P | 16 GB GDDR7 | 0.96 TB/s |
| Apple M4 Max | — | 36.9 TFLOPS FP16 (GPU); ANE "38 TOPS INT8" dequantizes to FP16, true ~19 TFLOPS | n/a | **~19–37 TOPS effective** (no real INT8 speedup) | up to 128 GB unified | 546 GB/s |
| Apple M5 (10-core GPU, est.) | — | ~16–18 TFLOPS FP16 (GPU Neural Accelerators; no native BF16) | n/a | **~25–35 TOPS** (s8×s8→s32, est.) | up to 32 GB unified | 153 GB/s |
| Apple M5 Max (40-core GPU, est.) | — | ~70 TFLOPS FP16 (GPU Neural Accelerators) | n/a | **~110–140 TOPS** (s8×s8→s32, est.) | up to 128 GB unified | 460–614 GB/s |
| NVIDIA CMP 170HX (GA100, ex-Ethash) | — | ~42 TFLOPS FP16 | n/a | **~12.5 TIOPS** (integer ALU; no usable low-precision tensor GEMM) | 8 GB HBM2e | 1.5 TB/s |

Sources: [H100 datasheet](https://resources.nvidia.com/en-us-gpu/h100-datasheet-24306), [H200](https://www.nvidia.com/en-us/data-center/h200/), [B200](https://www.spheron.network/blog/nvidia-b200-complete-guide/), [Exxact](https://www.exxactcorp.com/blog/hpc/comparing-nvidia-tensor-core-gpus), [RTX 5090](https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/rtx-5090/), [5090 specs](https://www.spheron.network/blog/nvidia-rtx-5090-specs/), [Puget 5090/5080](https://www.pugetsystems.com/labs/articles/nvidia-geforce-rtx-5090-amp-5080-ai-review/), [Apple M4](https://en.wikipedia.org/wiki/Apple_M4), [M4 ANE](https://maderix.substack.com/p/inside-the-m4-apple-neural-engine-615), [CMP 170HX](https://niconiconi.neocities.org/tech-notes/nvidia-cmp-170hx-review/).

Two structural facts drive the design: (1) **the precision ladder is the lever** — at FP32/FP64 the datacenter-vs-consumer gap is small (Blackwell even cuts FP64), but at low precision it opens to 5–11× (BF16 B200/5090 ≈ 10.7×, H100/5090 ≈ 4.7×; FP8/INT8 B200/5090 ≈ 11×, H100/5090 ≈ 5×), and GeForce historically halves reduced-precision throughput with FP32 accumulate, widening the effective deficit; (2) **non-tensor devices fall off a cliff** — CMP 170HX has no usable low-precision tensor GEMM (~12.5 TIOPS ALU), and the Apple M4-generation ANE INT8 gives no real speedup — but the Apple M5 generation adds genuine in-GPU-core INT8→INT32 matmul units (§O.1), so M5-class silicon re-enters at its throughput tier rather than being excluded.

### K.2 The roofline argument

A dense n×n GEMM does 2n³ ops on Θ(n²) data, so the **full-`C`** intensity is `AI(n) = 2n³/6n² = n/3` ops/byte. At n=4096, AI ≈ 1,365, above every device ridge. **But the economically binding intensity is the *optimal miner's*, not full-`C`'s — see §K.2a** — because under the default sketch payload no honest miner forms all of `C` (§E.3). Large-n dense GEMM on the correct basis is still pinned against the **peak-FLOPS ceiling**, so per-nonce throughput ∝ the device's dense INT8 tensor throughput and nothing else: the device with the most INT8 TOPS wins, linearly. This inverts the v3 regime (n=512 cache-resident, SHA-lottery, integer ALUs — where Apple/CPU/CMP competed within small constant factors).

### K.2a Roofline on the optimal-miner basis (normative rationale for b=8)

The §E.3 optimal miner computes `Ĉ = (U·A)(B·V)` at `2n²m + nm²` MACs, streaming `A, B` once (`2n²` bytes) with the `m×n` intermediates cache-resident. Its arithmetic intensity is therefore

```
AI_opt ≈ 2·(2n²m) ops / (2n²) bytes = 2m = 2n/b   ops/byte
```

— a function of the tile `b`, **not** `n/3`. Peak-basis ridge points (dense INT8 TOPS ÷ bandwidth, §P.1-corrected):

| Device | INT8 TOPS | BW (TB/s) | Ridge `AI*` |
|---|---:|---:|---:|
| H100 | 1,979 | 3.35 | **591** |
| B200 | 4,500 | 8.0 | **563** |
| RTX 4090 | 660.6 | 1.008 | **655** |
| RTX 5090 | 838 | 1.79 | 468 |
| RTX 5080 | 450.2 | 0.96 | 469 |
| A100 | 624 | 2.04 | 306 |
| RTX 3090 | 285 | 0.936 | 304 |
| M5 Max | 130 | 0.55 | 236 |

At **b=16**, `AI_opt = 512` sits *below* the H100 (591), B200 (563), and 4090 (655) ridges — attainable throughput is bandwidth-clipped to `512×BW`: H100 87 %, B200 91 %, 4090 78 % — while consumer/A100 cards (lower ridges) run at 100 %. Net, the H100:5090 ordering slope erodes from 2.36× toward ~2.05×: **b=16 silently hands ~9–22 % of the datacenter lever to bandwidth-rich consumer cards**, hidden by quoting AI on the wrong (n/3) basis. At **b=8**, `AI_opt = 1,024 ≥ 1.56×` above *every* ridge, restoring the full compute ordering. This is the normative rationale for the §0.7 `b = 16 → 8` change; the roofline margin uses peak-basis ridges with L2-resident intermediates and is flagged for real-kernel confirmation (Appendix C).

### K.3 Per-nonce INT8 advantage, quantified

Per nonce (n=4096, k=1): 2n³ ≈ 1.374·10¹¹ INT8 ops.

| Device | Dense INT8 (TOPS) | Time/nonce (peak) | Slowdown vs H100 | vs B200 |
|---|---|---|---|---|
| B200 | 4,500 | 30.5 µs | 0.44× | 1× |
| H100 / H200 | 1,979 | 69.4 µs | 1× | 2.3× |
| RTX 5090 | **838** (§P.1) | 164 µs | **~2.4×** | **~5.4×** |
| RTX 5080 | **450** (§P.1) | 305 µs | **~4.4×** | **~10×** |
| Apple M4 Max | ~19–37 | 3.7–7.2 ms | **~54–104×** | **~122–237×** |
| Apple M5 Max (est.) | ~110–140 | ~1.0–1.25 ms | **~15×** | **~35×** |
| CMP 170HX | ~12.5 | 11.0 ms | **~158×** | **~360×** |

(Ratios are n-independent while compute-bound; §L. Under the default sketch payload the absolute per-nonce work and times scale by 2/b — §E.3 — leaving every ratio unchanged. Even crediting CMP 170HX its 42 TFLOPS FP16 — unusable, breaks determinism — it trails H100 ~47×.)

### K.4 Why INT8, not FP8 or BF16

FP8/BF16 offer equal/better raw dense throughput on datacenter parts, but FP matmul is **not bit-reproducible** (non-associative FP add; order varies with kernel/tile/schedule across and within architectures, [arXiv:2511.00025](https://arxiv.org/pdf/2511.00025)) — a consensus rule on FP GEMM would fork on hardware or need a ZK/attestation layer. INT8×INT8→INT32 is **exact and order-independent**: every conforming implementation yields identical C, so `digest(C) ≤ target` is well-defined and Freivalds is exact. INT8 loses nothing economically (dense INT8 = dense FP8 on H100 = 1,979, B200 = 4,500), preserving the full ~5×/~11× multiplier. **INT8 is the unique dtype that maximizes the datacenter lever AND preserves bit-exact, ZK-free consensus.** The small-prime/CRT field exists precisely to express field arithmetic as s8×s8→s32.

---

## L. Reconciling compute-bound vs memory-bound (the core tension)

### L.1 The tension

- **Owner requirement:** compute-bound — "the worst would be to have the compute go down because it's memory-hard not compute-hard." More tensor FLOPS must always yield more reward.
- **Advisor:** use memory-boundedness to exclude low-VRAM cards.

"Memory-hard" conflates two properties; v4 wants exactly one:

| Property | Effect | v4 stance |
|---|---|---|
| Memory-**bandwidth**-bound (Ethash-style, throughput ∝ GB/s) | Flattens the FLOPS advantage; rewards cheap high-bandwidth cards. CMP 170HX (1.5 TB/s, 0.39 TFLOPS FP32) is the existence proof — compute stops scaling (the owner's failure mode). | **Rejected** |
| Memory-**capacity**-gated (working set must be resident; per-byte traffic negligible) | Would be a binary admission test: below-threshold devices can't participate competitively; above-threshold compete purely on tensor FLOPS. | **Rejected — no verification-preserving form exists (§L.4).** The intuition is sound; the construction is provably unavailable in the O(n²)-verify / single-winner model. |

**Rule (revised): throughput = INT8 tensor FLOPS (compute-bound); bandwidth is never binding; admission is by INT8-tensor-path eligibility (§S.1), NOT by a capacity gate (which does not exist — §L.4).** The datacenter lever is compute and energy, permanently.

### L.2 Roofline / ridge-point reasoning — on the *optimal-miner* basis

Attainable = `min(peak_FLOPS, AI·peak_bandwidth)`, ridge `AI* = peak_FLOPS/peak_bandwidth`. The economically binding arithmetic intensity is **not** the full-`C` product's `AI(n) = n/3` — it is the *optimal sketch miner's* `(U·A)(B·V)` workload (§E.3), whose intensity is `AI_opt = 2n/b` ops/byte (derivation and the full ridge table are §K.2a). At the old **b=16**, `AI_opt ≈ 512` — *below* the peak INT8 ridges of H100 (591), B200 (563), and 4090 (655), bandwidth-clipping those cards to 78–91 % of peak and eroding the datacenter ordering slope. At the corrected **b=8**, `AI_opt ≈ 1,024 ≥ 1.56×` above every device ridge (worst: 4090 at 655), so every eligible device runs compute-bound and the ranking is strictly ordered by INT8 tensor TOPS:

| Device (dense INT8 TOPS / BW TB/s, §P.1) | Ridge AI\* | b=16 `AI_opt`=512 | **b=8 `AI_opt`=1,024** |
|---|---|---|---|
| H100 (1,979 / 3.35) | 591 | 87 % of peak (clipped) | **1.73× above (100 %)** |
| B200 (4,500 / 8.0) | 563 | 91 % (clipped) | **1.82× above** |
| RTX 4090 (660 / 1.008) | 655 | 78 % (clipped) | **1.56× above** |
| RTX 5090 (838 / 1.79) | 468 | 100 % | 2.19× above |
| A100 (624 / 2.04) | 306 | 100 % | 3.3× above |

Going bandwidth-bound would *help* consumer/junk cards (lower ridge points) and resurrect CMP-class; staying above every ridge keeps ranking strictly ∝ tensor TOPS. Minimum-traffic is the standard tiled-GEMM result (cuBLASLt IMMA already achieves it).

#### L.2.1 Work-unit-neutrality theorem (the floor and ordering are invariant to the work-unit size)

Let the per-nonce work be scaled by any constant `c` (via `n`, `k`, `b`, or full-C vs sketch). Every device's nonce rate scales by `1/c`; ASERT re-targets to hold 40 blocks/hr (§I.4); each device's share of the 800 BTX/hr emission, `(BTX/hr)_g = 800·T_g/TOPS_net`, is **unchanged**. Hence every break-even `P*_g = R_g·TOPS_net/(800·T_g)` and the §S.4.3 floor are **invariant under `c`**. Corollaries: (i) a bigger work unit makes *a nonce* dearer, not *a coin* — coins cost `ρ·TOPS_net/800` regardless; (ii) `TOPS_net = ν_net·W_nonce` is the hardware's true ops/s and is `b`-invariant, so `N_eq`, `P_prod`, `BTX_security_%`, and every hardware ratio are `b`-invariant (the §Q.4 note). **What is *not* neutral is anything that changes the *relative* `T_g` between classes** — which is exactly why the `b=8` roofline fix (§K.2a) matters (it restores datacenter `T_g`) while `n`/`k` do not move the economics. Independently derived by both the solver and security-economics re-derivations. This is why the only price-independent floor levers are *eligibility* (§S.1) and *relative efficiency* (§K.2a), never work-unit inflation.

### L.3 Capacity as a gate — rejected with proof (superseded by §L.4)

The intuition of §L.1 (residency gate → binary admission → datacenter-only) is appealing, but **no verification-preserving capacity gate exists**: any resident-set requirement is either (a) evaluable by the O(n²) verifier — in which case the miner shares the same shortcut and no residency is forced (verifier-linearity collapse), or (b) nonlinear enough to force miner residency — in which case the verifier is forced to O(n³) and blows the §D.5 budget; and even a per-nonce-varying footprint is defeated by grinding the selection PRF (I8/§L.4). The prior "Adopted, sized `32 GB < W < 80 GB`, filed as future hardening" disposition is **retracted**; §L.4 is the proof. As hardware improves, `n` is retargetable upward within the verify budget — compute scales up, never down — but that is a throughput knob, not a capacity gate.

### L.4 Impossibility of a verification-preserving capacity/bandwidth/working-set gate

**Model.** Nonce-parallel search; block validity depends only on the *winning* nonce's committed data; every full node verifies in O(n²) single-thread (< 1 s hard). `n` is capped at 4096–8192 by the Freivalds budget (§D.4/§D.5), so per-nonce operands are `2n²` ≈ 32 MiB — no gate. Any gate must therefore come from structure *around* the per-nonce matmul. Three lemmas close the space.

- **L1 — verifier-linearity collapse.** Anything the verifier can evaluate in O(n²) — operand entries derived O(1)-per-entry from a seed, or any succinct *linear* structure (matmul-expanded pools `D=X·Y`, low-rank pools, weighted combinations) — composes with the linear commitment/Freivalds check into an O(n²m) miner evaluation, forcing no materialization and no residency. Conversely, any *nonlinear, incompressible* derivation that defeats the miner's shortcut also defeats the verifier's: to run `A·(B·r)` the verifier must materialize A's `n²` entries, so if each costs more than O(1) the budget dies. (Worked: `D=X·Y` pools shortcut both ways as `U·(X_A·Y_A)(X_B·Y_B)·V`; `canon₂₅₁(X·Y)` breaks the miner *and* forces the verifier to O(n³); rank-1 pools are verifier-cheap and miner-cheap alike.)
- **L2 — selection filtering.** If the per-nonce footprint varies with the nonce (e.g. a nonce-PRF-selected subset of a large operand pool), a miner holding fraction φ of the pool grinds the O(1) selection PRF and mines *only* footprint-resident nonces; the digest is uniform over nonces, so restricting to a subset of the 2⁶⁴ space costs nothing. Concrete: an `L=3072`, `n=4096` pool (`W=51.5 GB`, `s=2` selections/side) leaves a 28-GB-resident RTX 5090 at φ=0.544, accepting φ⁴=8.7 % of nonces at ~10 ns extra SHA per accepted nonce against a 31.6 µs GEMM — a 0.03 % tax. **The 80-GB gate is worth zero.** This is exactly what invariant **I8** forbids.
- **L3 — batch-streaming with winner-recompute.** Make selections depend on prior tensor work (stage-1 sketch → PRF → stage-2 indices), and a streaming miner batches Q candidates per pool-pass; required in-flight state per candidate is **32 bytes** (keep only `H(σ‖Ĉ₁)`; losing candidates are discarded, the single winner's intermediates are recomputed once, post hoc, for one extra work unit per block). Q is effectively unbounded (28 GB / 32 B ≈ 10⁹), so per-candidate off-card traffic → 0 and a PCIe-attached 5090 with host DRAM mines at full compute rate. Forcing large per-candidate state is impossible: any state the verifier must check ships in the DA/DoS-capped payload (MiBs), and MiB-scale state still admits Q ≈ 10⁴ (≈1.9× penalty at 8.4 MiB — far below the 4.55× rental gap it would need).

**Corner cases (each dead):** a uniform non-amortizable footprint (`A_t = canon(Σ wᵢ(t)Dᵢ)` over all L) forces the *verifier* to `L·n² ≈ 50 s`; raising n to gate a 32 GB card needs n ≈ 65k → Freivalds ≈ 60–120 s; a resident-C window is fabricated on demand at win time (winner-recompute) and is unverifiable without shipping the C's; per-nonce ZK residency proofs take ~a block interval each (§F.2), six orders short.

**Economic corollary (even the target was partly illusory).** A rented H100 ($2.50/hr) vs a 5090 ($0.55/hr) must be > **4.55×** better *per nonce* to win on cost, but no single hardware ratio reaches it — INT8 2.36×, HBM bandwidth 1.87×, VRAM capacity 2.5× — because the AI market prices VRAM/NVLink/SLAs for LLM *serving*, which a 36-MiB-working-set PoW cannot consume. Only a > 4.55× *cliff* could have inverted the per-dollar ordering, and L2/L3 cap any cliff's residual below ~2×.

**Conclusion.** The enforceable per-nonce resident set is exactly `operands + committed state ≈ 2n² + 8m² ≈ 36 MiB` — fits a phone. There is no verification-preserving capacity, bandwidth, or working-set gate. The correct price-independent restatement of "intended hardware ordering" is therefore: **datacenter wins per card and per joule at every price; consumer wins per rental-dollar at every price; the solver maximizes the cost floor of the *cheapest eligible* producer and the slope of the per-card ordering** (the b=8 fix does exactly this) — it does not, and provably cannot, control which class *chooses* to show up at a given price (that is the market outcome §Q.21, and forcing it would require reading price — forbidden by §0.7-(4)).

---

## M. Parameter calibration

### M.1 Matrix dimension n — sensitivity analysis

Per nonce per prime: n³ MACs (2n³ ops); operand n² B (int8), accumulator 4n² B; per-problem footprint ≈ 6n². Times at dense-peak; multiply by k, divide by realized ε ≈ 0.6–0.75.

| n | 2n³ ops | H100 time | 5090 time | Footprint 6n² | >16 GB? | >32 GB? | fits 80 GB? | Freivalds/round/prime (~3n² MAC) | O(n²) verify note |
|---|---|---|---|---|---|---|---|---|---|
| 4,096 | 1.37·10¹¹ | 69 µs | 344 µs | 0.10 GB | no | no | yes | 5.0·10⁷ | ~0.15–0.3 s, 64 MiB payload — **within budget** |
| 8,192 | 1.10·10¹² | 0.56 ms | 2.75 ms | 0.40 GB | no | no | yes | 2.0·10⁸ | ~0.6–1 s, 256 MiB payload — **at the ceiling** |
| 16,384 | 8.80·10¹² | 4.4 ms | 22 ms | 1.61 GB | no | no | yes | 8.1·10⁸ | multi-second, 1 GiB payload — **exceeds verify budget** |
| 32,768 | 7.04·10¹³ | 36 ms | 176 ms | 6.44 GB | no | no | yes | 3.2·10⁹ | seconds+, 4 GiB — **excluded** |

*(Times shown are for the full n³ product; the optimal sketch miner runs at ×(2/b) = 1/4 of them at b=8, §E.3. Payload figures in the last column are full-C; the default sketch payload is 8·(n/b)² B — 2 MiB at n = 4096, b = 8, §E.1.)*

Per-nonce footprint alone does not gate 32 GB consumer VRAM until n ≈ 74,000 — where verification/payload are far past budget. **The single-matmul VRAM gate is therefore incompatible with cheap verification** (§0.7). Two consequences:

- **Launch (normative): n = 4096, single-C verification.** Compute-bound (AI ≈ 1,365, ≥ 2.3× every ridge), per-nonce ~0.1 ms on H100 → thousands of nonces per 90 s block, Freivalds verify ~0.15–0.3 s, payload 2 MiB sketch (64 MiB full-C alternative). The datacenter advantage is the ~5×/~11× INT8 compute lever (§K.3) plus the resident/thermal/scale-out edges of datacenter parts. n may rise to **8192** once the serialization limits (§H.3) are lifted, trading verification headroom for a larger work unit.
- **Capacity gate — closed, not deferred (§L.4).** A resident-C-window (hold m recent products, digest chained with random back-references) was considered as a way to gate 32 GB VRAM, but it is defeated by winner-recompute (the back-referenced C's are the miner's own prior candidates, fabricated on demand at win time) and is unverifiable without shipping the referenced C's. More generally, no verification-preserving capacity/bandwidth/working-set gate exists in the O(n²)-verify, single-winner model (§L.4). The launch and permanent datacenter lever is INT8 compute + energy.

**Recommendation: n = 4096, k = 1 (single exact-integer s8 matmul, §0.7), b = 8 (roofline-driven, §K.2a), sketch payload (2 MiB), Freivalds verification over q = 2⁶¹−1.** n=8192 is a governance-raisable option after the §H.3 plumbing lands; larger n and the optional k > 1 compute-multiplier (§B.3/§M.2) are deferred pending verification-budget headroom. The capacity gate is **not** deferred — it is closed (no verification-preserving construction exists, §L.4); the datacenter lever is compute + energy, permanently.

### M.2 k — compute lanes (baseline k = 1)

The normative baseline is **k = 1**: a single exact-integer s8 matmul (§0.7). Freivalds soundness is supplied entirely by the independent verification prime `q` (§D.3), so k plays no role in security. The optional §B.3 CRT variant sets k > 1 purely to multiply per-nonce compute: each extra lane is one more independent `s8×s8→s32` GEMM (+2n³ ops) with its own exact-INT32 lane product committed and Freivalds-verified over `q` — so both per-nonce work **and per-block verification cost** scale ×k (device *ratios* in §K.3 are unchanged, but the ×k verify cost eats the §D.5 budget, which is why k > 1 is off by default). Leave k = 1 unless a future retarget deliberately wants a larger work unit and can afford the verification headroom; prefer raising n (within §D.5) or difficulty first.

### M.3 b — commit tile size

C is committed via the dense sketch Ĉ = U·C·V, m = n/b (§E.1). b trades three quantities: (i) payload 8·m² = 8·(n/b)² bytes shrinks with b; (ii) the §E.3 work-shortcut factor b/2 grows with b; (iii) commitment granularity m² coarsens with b. Hash/commit cost must stay ≪ 1% of tensor time so the digest never becomes a v3-style SHA side-channel — satisfied at every candidate b, since the sketch is a by-product of the §E.3 optimal evaluation. **b = 16 network-wide at n = 4096** (§G.2): payload 512 KiB, shortcut 8×, m = 256; see §E.1 for the rejected b = 8 / b = 64 corners.

### M.4 Block time and work-unit sizing

Retain **90 s**. With the k = 1 baseline, the per-nonce work unit is the §E.3 sketch-optimal cost `W = 4n²m + 2nm² ≈ 2n³·(2/b)` ops (**not** naïve 2n³ — §0.7-(3), §I.4); the difficulty target on the product-committed digest tracks **aggregate network dense-INT8 TOPS**. Sketch-basis nonce rate `≈ ε·P_int8/W`: at n=4096, b=16 (m=256), ε=0.65, H100 ≈ 7×10⁴ nonces/s → ~6×10⁶/block (excellent variance). *(The §K.3 and §O per-device "nonces/s" columns are quoted on the conservative full-matmul reference basis 2n³ — ~8× lower — for illustration; the sketch shortcut scales every device's rate by the same ~8×, so device ratios and the datacenter/pooling economics are basis-invariant.)* Difficulty cadence/clamps carry over from v3, with the one-time fork rescale of §I.4. As successors raise P_int8, difficulty rises transparently; governance retargets n only when VRAM boundaries shift, not to chase FLOPS.

---

## N. Migration, mining ops & risk register

### N.1 Strategic pivot — stated explicitly

BTX's existing spec/site optimize for commodity fairness: viability "on any machine from the last decade" (`doc/btx-matmul-pow-spec.md`), commodity GPU/TPU alignment as the ASIC story (`doc/btx-matmul-pow-spec-analysis.md`), first-class Apple/Metal/CPU paths (`src/pow.cpp`). **v4 intentionally reverses this priority:** the marginal mining reward accrues to the device with the most dense low-precision tensor throughput — current-generation datacenter accelerators — and consumer (16–32 GB), Apple, CPU, and repurposed-mining hardware become structurally less competitive (§K.3). This is an objective change, not a side effect; all public docs/site/mining guides must be rewritten before activation, or shipping v4 under v3's fairness messaging is a credibility failure. Note that ordering is **not** exclusion: share-based pooling (§O.2) preserves proportional-to-compute rewards for consumer and Apple devices with a conforming INT8 path (Apple M5-class and later, §O.1), so "less competitive per device" does not mean "shut out." Conversely, pools built on non-INT8 junk hardware lose their economic basis entirely — the mine-and-dump analysis (btxpool.org) and the AI-rental cost floor that replaces zero-cost dumping are in §S.4. **Residual risk (spot-rental mine-and-dump during price spikes):** bounded by the §S.4.3 cost floor and the ASERT difficulty response — proceeds are capped at `price − spot-floor`/BTX and the rented-capacity influx raises difficulty within hours; monitor nonce-rate spikes vs spot-GPU price troughs (§N.3).

### N.2 Mining-ops implications

- **Pool software rebuild.** Work units become (header, seed, n, k, target); a share is a nonce whose digest meets a share target. Share validation = Freivalds + digest recompute (≈ 0.15–0.3 s at n=4096, §I.5), so pool servers need real verify capacity (budget one multicore CPU / small GPU per ~O(10³) shares/s; coarse share targets bound load). Vardiff re-derived for ~10³–10⁴ nonces/s per device rather than SHA hashrates.
- **Miner backend flags.** Gate on dense INT8 tensor GEMM (IMMA/cuBLASLt-class), sufficient device memory + headroom, and a passed determinism self-test (N.3-v). Backends without a genuine s8×s8→s32 path (Apple ANE and pre-M5 Metal, pre-tensor CUDA, CMP) are verification-only; **M5-class Metal 4 TensorOps backends are mining-eligible once they pass the N.3-v determinism self-test (§O.1)**. Consumer/Apple devices that are individually non-competitive still participate profitably via pooling (§O.2).
- **Verification/light-client path.** Full nodes verify with CPU Freivalds; **no GPU required to validate the chain** — a hard invariant through every retarget.

### N.3 Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| i | **Consumer Blackwell INT8 closer than modeled** (5090 INT8-with-INT32-acc may hit ~2× the FP8 figure, shrinking H100's edge toward ~2.5×, [Puget](https://www.pugetsystems.com/labs/articles/nvidia-geforce-rtx-5090-amp-5080-ai-review/)). | Medium | Medium | At launch the lever is compute (~5×/~11×), not a hard VRAM gate. Benchmark real 5090 INT8 IMMA pre-mainnet; B200-class retains ~11× regardless. If per-card economics prove too close, revisit the deferred capacity gate (verification-preserving form) or raise k/n. |
| ii | **Strassen constant-factor edge** (integer entries: up to 8–30× on huge matrices; ~1.19× at n≈7,680, [Strassen](https://en.wikipedia.org/wiki/Strassen_algorithm)) — so 2n³ is economic, not physical. | Medium | Medium | Set difficulty against measured honest *dense* cost, not theoretical n³; s8 input-range barrier blocks direct s8×s8→s32 Strassen (block combos exceed s8); monitor nonce-rate anomalies. Any residual edge is a normal miner optimization. |
| iii | **Field too small for soundness** (per-round Freivalds ~1/p ≈ 2⁻⁸/prime; the composite modulus M is no better — an adversary localizes the error to one CRT plane, §D.2). | Low | High if mis-specified | Lift to the exact integer product and run Freivalds over the independent prime q = 2⁶¹−1 (§D.3): R = 3 → ≤ 2⁻¹⁸⁰ (sketch) / ≤ 2⁻¹⁸³ (full-C). Never check over ℤ_M or per-lane mod p_i. Consensus tests encode the bound. |
| iv | **Centralization toward datacenters** — hashpower concentrates among capital/power-advantaged operators; 51% surface shifts to a few clouds/HPC operators. | High (the goal's cost) | High | Accepted and disclosed (N.1). Offsets: spot-rental markets lower entry vs ASIC fabs; (n,k) governance-retargetable if concentration exceeds thresholds; monitor Nakamoto coefficient on-chain. |
| v | **Determinism bugs across INT8 implementations** (exact in principle, [arXiv:2511.00025](https://arxiv.org/pdf/2511.00025), but library bugs — saturating vs wrapping, sparsity flags, quant pre-passes — could diverge). | Medium | High (fork) | Extend v3's cross-vendor spot-check: golden C digests over CUDA/ROCm/CPU reference; mandatory miner self-test at startup; the pure-integer CPU implementation is the consensus definition, tensor paths must match bit-for-bit. |
| vi | **Verification/DA cost at large n** (Freivalds O(n²) but verifier regenerates 2n² operand bytes + downloads C). | Medium | Medium–High | Hard invariant (§0.7): full-node verify < ~0.3 s CPU, payload 2 MiB sketch (64 MiB full-C) at n=4096; caps n growth (raise k before n; n≤8192 only after §H.3); stream PRF regeneration (O(n) RAM on verifiers). |

---

---

## O. Evolving consumer matmul hardware & inclusive pooling

### O.1 Consumer matmul hardware is a moving target (Apple M5 and beyond)

§K ranks devices by one metric: **dense INT8 tensor throughput with exact integer accumulation**. It is worth stating explicitly what that ranking does *not* do: it does not hard-exclude any device class. v4 has no whitelist and no architectural gate beyond "can you perform the s8×s8→s32 GEMM of §B bit-exactly and hold the working set." Any device that gains a genuine integer matmul path re-enters the competition automatically, at whatever throughput tier its silicon earns. The Apple M4→M5 transition is the first live example, and it landed between v4 drafts.

**What changed with M5.** Apple announced the M5 on October 15, 2025 with a "next-generation GPU architecture featuring a Neural Accelerator in each core," claiming *over 4× peak GPU compute for AI versus M4* and over 6× versus M1, plus a unified-memory-bandwidth bump to 153 GB/s (~30% over M4's 120 GB/s) ([Apple Newsroom](https://www.apple.com/newsroom/2025/10/apple-unleashes-m5-the-next-big-leap-in-ai-performance-for-apple-silicon/), [Tom's Hardware](https://www.tomshardware.com/pc-components/cpus/apple-unveils-m5-chip-with-10-core-cpu-and-10-core-gpu-company-says-3nm-chip-offers-4x-peak-gpu-performance-over-m4-for-ai-45-percent-graphics-uplift)). M5 Pro (16–20 GPU cores, up to 307 GB/s) and M5 Max (32–40 GPU cores, 460–614 GB/s, up to 128 GB unified) followed on March 3, 2026 ([Wikipedia: Apple M5](https://en.wikipedia.org/wiki/Apple_M5)). Unlike the M4 — whose GPU had no matrix units and whose ANE "38 TOPS INT8" dequantizes to FP16 with no genuine integer path (§K.1) — the M5's Neural Accelerators are **dedicated matrix-multiply units inside each GPU core**, directly programmable via Metal 4 Tensor APIs / Metal Performance Primitives ([Apple Newsroom](https://www.apple.com/newsroom/2025/10/apple-unleashes-m5-the-next-big-leap-in-ai-performance-for-apple-silicon/), [Apple Tech Talk 111432](https://developer.apple.com/videos/play/tech-talks/111432/), [Apple ML Research](https://machinelearning.apple.com/research/exploring-llms-mlx-m5)).

**The make-or-break question — dtype and accumulation.** For v4, raw "AI compute" is irrelevant unless there is an exact-integer path. Here the evidence is good but not first-party-complete:

- Third-party microbenchmarking of the A19/M5 Neural Accelerators finds two hardware-accelerated matmul formats: **FP16 (FP16 or FP32 accumulate)** and **INT8 with INT32 accumulation** — i.e., precisely the s8×s8→s32 primitive v4's field arithmetic (§B) is built on. Measured rates: ~1,024 FP16 MACs/core/cycle and ~2,048 INT8 OPS/core/cycle; 7.5 TFLOPS FP16 / 13.5 TOPS INT8 on the 5-core A19, extrapolating to ~70 TFLOPS FP16 / **~130 TOPS INT8 on a 40-core M5 Max** ([Zakharko, *Investigating the GPU Neural Accelerators on Apple A19/M5*](https://tzakharko.github.io/apple-neural-accelerators-benchmark/)). Native BF16 was *not* found in the accelerator hardware — irrelevant to v4 either way, since BF16 is non-deterministic (§K.4).
- Apple's own tooling corroborates: Metal 4 TensorOps ("matrix multiplication and convolution primitives purpose built to leverage neural accelerators on M5") added **8-bit and 4-bit integer tensors in OS 26.4**, with Apple citing up to 4–8× GEMM speedups depending on precision ([Apple Tech Talk 111432](https://developer.apple.com/videos/play/tech-talks/111432/)). Independent projects already exploit the M5's INT8 TensorOps for W8A8 inference ([Mininglamp cider](https://github.com/Mininglamp-AI/cider)).
- **Caveats, stated honestly:** Apple publishes no first-party INT8 TOPS figure (only relative multipliers), so all absolute numbers above are third-party measurements plus extrapolation; the MPP `matmul2d` specification documents supported type rows but hides accumulator width and hardware placement ([Rigel, arXiv:2606.12765](https://arxiv.org/html/2606.12765v1)); and the INT8 tensor path is only exposed from OS 26.4. Per §N.3-v, no Metal backend may be flagged mining-capable until it passes the determinism self-test bit-for-bit against the CPU consensus reference. Integer accumulation is order-independent in principle, so if the path is what the microbenchmarks indicate, it qualifies; if a library quirk (saturation, hidden quantization pre-pass) breaks bit-exactness, the device stays verification-only, exactly like M4.

**Where M5 lands (estimates).** Taking ~25–35 TOPS dense INT8 for the 10-core M5 and ~110–140 TOPS for the 40-core M5 Max (clock-scaled from the A19 measurements; clearly labeled estimates):

| Device | Dense INT8 (est.) | Time/nonce (n=4096) | Nonces/s | vs RTX 5080 | vs RTX 5090 | vs H100 | vs B200 |
|---|---|---|---|---|---|---|---|
| Apple M5 (10-core GPU) | ~25–35 TOPS | 3.9–5.5 ms | ~180–255 | ~7.5× behind | ~13× | ~66× | ~150× |
| Apple M5 Max (40-core GPU) | ~110–140 TOPS | ~1.0–1.25 ms | ~800–1,000 | ~1.7× behind | ~3× | ~15× | ~35× |

An M5 Max at ~130 TOPS is roughly **half an RTX 5080, a third of an RTX 5090, and 1/15 of an H100** — a genuine, if modest, miner. Contrast M4: no integer matmul path at all → effectively excluded (its "~19–37 TOPS" in §K.1/§K.3 is FP16-effective and unusable for consensus). M5: exact INT8 path (pending self-test) → participates at its throughput tier. The design intent (§K, §N.1) is unchanged — datacenter parts keep a 15–66× per-device edge — but the mechanism is *ordering by throughput*, not exclusion, and consumer silicon is visibly climbing the order. Future consumer parts (M6, RTX 60-series) should be expected to keep moving; difficulty (§I.4) absorbs this automatically, since it tracks aggregate network throughput, not any device list.

**Determinism caveat (normative cross-ref).** Only an exact-integer INT8 (s8×s8→s32) path counts toward consensus mining. An accelerator offering only FP16/BF16/FP8 matmul — however fast — does not help the deterministic baseline: FP GEMM is not bit-reproducible and would require the ZK/attestation machinery of §F.4(a) (see §K.4). The M5's FP16 units are therefore irrelevant to v4; its INT8 units are the entire story.

### O.2 Inclusive pooling: proportional rewards, not exclusion

**Objective, restated precisely (project requirement).** §0.5-#2's "washing out the retail guys" means: retail hardware cannot *profitably solo-dominate*, and earns strictly less *per device* than datacenter accelerators — by the ~5×/~11×/~15×/~66× factors of §K.3/§O.1. It does **not** mean retail is excluded. Every device with a conforming INT8 path earns rewards **proportional to its contributed compute** via pooling. This subsection specifies how, and confirms it needs nothing from consensus.

**Share-based pooling over Freivalds-verified shares.** Pooling works exactly as in classic PoW, transplanted onto the v4 verification machinery:

1. The pool issues a work unit (header template, seed, n, k, **share target**) per §N.2, with the share target set far easier than the network target (e.g., 2⁶–2¹⁴× easier, per-worker vardiff).
2. A miner submits any nonce whose product-committed digest (§A.3/§0.7) ≤ share target, together with the compact sketch payload (§E.1).
3. The pool verifies each share with the same O(n²) Freivalds check full nodes use (§D, §E.2) — no O(n³) recompute — and credits the worker under PPLNS or PPS.
4. A share that also meets the network target is a block; the pool broadcasts it and distributes the reward pro rata.

Because the per-nonce cost is one full dense INT8 matmul (the §A.6/§E.3 work unit), **a share is itself a proof of real matmul work**: passing Freivalds against the seed-derived A, B requires knowledge of the true product up to soundness ≤ 2⁻¹²⁸ (§D.3), so shares cannot be faked, precomputed across headers (§C anti-amortization), or ground out with SHA tricks (the epsilon gate is gone, §A.5). Pool accounting inherits consensus-grade soundness for free.

**Even low-throughput devices produce a smooth share stream.** Per-nonce time at n = 4096 is milliseconds even on weak hardware (§K.3, §O.1): M4-class ~3.7–7.2 ms → ~140–270 nonces/s (were it eligible); **M5 ~180–255 nonces/s; M5 Max ~800–1,000 nonces/s**; H100 ~14,000 nonces/s. So even the weakest eligible device evaluates hundreds of candidate nonces per second, and the share target can be tuned to convert that into anywhere from ~0.1 to hundreds of shares/s per worker. At a typical vardiff setpoint of ~0.1–1 share/s/worker, a PPLNS window of a few minutes contains tens of shares per device — ample for low-variance proportional accounting. The H100 still earns ~15–66× more than an M5-class device per unit time (§O.1) — that is the intended datacenter lever — but the small device is **not shut out**: it earns exactly its proportional slice.

**Aggregation example.** A pool of 1,000 M5 Max machines (~130 TOPS each, est.) aggregates ~130 POPS of dense INT8 — the equivalent of ~66 H100s or ~29 B200s (§K.1 figures). A 10,000-device mixed consumer pool (M5/M5 Max/RTX 50-series, ~100 TOPS average) aggregates ~1,000 POPS ≈ a ~500-H100 datacenter rack. Such pools win blocks at exactly their throughput fraction of the network and stream per-share payouts back to members. Consumer participation is thus economically alive at any difficulty — it is a question of electricity cost per TOPS, not of admission.

**Pool-side share-verification load.** Each share costs the pool one Freivalds pass: ~95 ms single-threaded CPU at the n = 4096 baseline with the sketch payload, ≤ 0.25 s conservative (§D.4). That is ~4–10 shares/s per core; a commodity multicore server or a single small GPU (Freivalds is bandwidth-bound matvecs and offloads trivially) sustains **O(10³) shares/s**, matching the §N.2 budget. The governing tunable is the share target: it sets shares/s per worker, trading payout/accounting granularity against pool verify load, and per-worker vardiff plus rate limits (as in Stratum practice) keep aggregate flow inside the budget regardless of pool size.

**Variance and fairness.** Solo, a single M5-class device contributing ~10⁻⁵–10⁻⁶ of network throughput would wait months to years between blocks at 90 s spacing — economically dead even though its expected value is fair. Pooling removes exactly this variance: expected earnings are unchanged (minus pool fee), but arrive as a steady per-share stream. This is the mechanism that keeps consumer and Apple participation meaningful under a deliberately datacenter-favoring difficulty, and it is the standard economics of every mature PoW chain — v4 simply makes shares *cheap to verify* (Freivalds) and *impossible to fake* (full matmul per nonce), which are the two properties a pool needs.

**Consensus impact: none (confirmed).** Pooling is entirely off-consensus. Share targets, share submission, PPLNS/PPS, and vardiff live in pool protocol; consensus sees only the final block, validated by the unchanged cascade of §I.2. No new header fields, no new `Consensus::Params`, no changes to §G/§H are required. The only implied engineering work is the §N.2 pool-software rebuild: a Stratum-v2-style extension whose work unit is (header template, seed, n, k, share target) and whose share submission carries (nonce, digest, sketch payload) — a mining-ops deliverable, not a fork item.

---

## P. Cross-generation hardware: how each class fares in v3 vs v4 (solo and pooled)

*This section is descriptive, not normative. It reconciles §K.1/§K.3 against primary sources (NVIDIA architecture whitepapers and datasheets, Apple announcements, third-party microbenchmarks) and walks each hardware class through the v3→v4 regime change. **Where a figure here conflicts with §K.1/§K.3, this section's primary-sourced figure governs** (corrections listed at the end). Headline correction: the RTX 5090 dense INT8 is **838 TOPS**, not the ~400 printed in §K — the ~400 figure is the FP8-with-FP32-accumulate rate; GeForce's 2× reduced-precision cut applies only to floating-point accumulate, while **INT8→INT32 runs full-rate**. The true per-device datacenter lever is therefore H100 ≈ 2.4× and B200 ≈ 5.4× over a 5090 (not ~5×/~11×). Direction of every conclusion is unchanged; magnitudes are corrected.*

### P.0 The two regimes, one line each

- **v3 (old):** an 18-bit SHA-256 pre-hash gate (~1/262,144 nonces reach the matmul) followed by a small n=512 exact matmul over GF(2³¹−1), cache-resident (~2 MiB), on **integer ALUs / shader cores** — no tensor cores anywhere in the hot path. Winner ≈ SHA-256 throughput × integer-ALU throughput at low memory latency. Tensor cores and HBM contributed **nothing**.
- **v4 (new):** one fresh dense **n=4096 INT8 matmul per nonce** (k=1, no SHA gate), exact s8×s8→s32, Freivalds-verified in O(n²). Winner = **dense INT8 tensor TOPS**. Devices without an exact-integer matmul path cannot mine (they can still verify — verification needs no tensor units).

### P.1 Master comparison table

Dense (non-sparse) figures; 2:4 sparsity peaks (\*) are irrelevant to v4. Per-nonce time on the full-matmul reference basis 2n³ ≈ 1.374×10¹¹ INT8 ops at n=4096 (the §E.3 sketch basis scales every device by the same 2/b, ratios unchanged). The n=4096 working set (~100 MB) fits every device, so at launch **eligibility = exact INT8 matrix path**, not VRAM.

| Device (year) | Dense INT8 TOPS | FP16 tensor TFLOPS | VRAM | Bandwidth | Matrix units | v4 mining | t/nonce | vs H100 |
|---|---|---|---|---|---|---|---|---|
| **Apple M1 / Pro / Max / Ultra** (2020–22) | — (no matrix path) | 2.6–20.8 FP32 shader | ≤128 GB unified | 68–800 GB/s | **No** | **verify-only** | — | ∞ |
| **Apple M2 / M3 / M4 (+Max)** (2022–24) | — (ANE dequantizes to FP16) | 3.6–19.5 FP32 shader | ≤128 GB | ≤546 GB/s | **No** | **verify-only** | — | ∞ |
| **Apple M5** (Oct 2025) | ~27–33 (est.) | ~16–18 (est.) | ≤32 GB | 153.6 GB/s | **Yes** (Neural Accel/core) | **Yes** | ~4.6 ms | ~66× |
| **Apple M5 Pro** (Mar 2026) | ~55–65 (est.) | ~35 (est.) | ≤64 GB | 307 GB/s | **Yes** | **Yes** | ~2.3 ms | ~33× |
| **Apple M5 Max** (Mar 2026) | ~130 (est.) | ~70 (est.) | ≤128 GB | 460–614 GB/s | **Yes** | **Yes** | ~1.06 ms | ~15× |
| **RTX 3090** (2020, Ampere) | **284.7** | 71.2/142.3 | 24 GB GDDR6X | 936 GB/s | Yes (3rd-gen TC) | **Yes** | 483 µs | 7.0× |
| **RTX 3090 Ti** (2022) | **320** | 80 | 24 GB | 1,008 GB/s | Yes | **Yes** | 429 µs | 6.2× |
| **RTX 4090** (2022, Ada) | **660.6** | 165.2/330.3 | 24 GB GDDR6X | 1,008 GB/s | Yes (4th-gen TC) | **Yes** | 208 µs | 3.0× |
| **RTX 5090** (2025, Blackwell) | **838** (1,676\*) | 209.5/419 | 32 GB GDDR7 | 1,792 GB/s | Yes (5th-gen TC) | **Yes** | 164 µs | 2.4× |
| **RTX 5080** (2025) | **450.2** (900.4\*) | 112.6/225.1 | 16 GB GDDR7 | 960 GB/s | Yes | **Yes** | 305 µs | 4.4× |
| **A100 80GB** (2020, DC) | **624** (1,248\*) | 312 | 80 GB HBM2e | 2,039 GB/s | Yes | **Yes** | 220 µs | 3.2× |
| **H100 SXM** (2022, Hopper) | **1,979** (3,958\*) | 989 | 80 GB HBM3 | 3.35 TB/s | Yes | **Yes** | 69.4 µs | **1× (ref)** |
| **H200** (2024) | **1,979** (same die) | 989 | 141 GB HBM3e | 4.8 TB/s | Yes | **Yes** | 69.4 µs | 1× |
| **B200 (HGX)** (2024–25) | **4,500** (9,000\*) | 2,250 | 180 GB HBM3e | 7.7 TB/s | Yes | **Yes** | 30.5 µs | 0.44× |
| **GB200 (per GPU)** | **5,000** (10,000\*) | 2,500 | 186 GB HBM3e | 8 TB/s | Yes | **Yes** | 27.5 µs | 0.40× |
| **CMP 170HX** (2021, ex-Ethash) | — (tensor cores unusable; ~12.5 TIOPS ALU) | ~42 shader | 8 GB HBM2e | 1,355 GB/s meas. | Fused off | **verify-only** | — | ∞ |

Sources: [RTX Blackwell WP App. A/B](https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf) (5090 INT8 838 dense / 5080 450.2; GeForce INT8 is full-rate, only FP-accumulate is halved), [Ada WP](https://images.nvidia.com/aem-dam/Solutions/geforce/ada/nvidia-ada-gpu-architecture.pdf) (4090 660.6), [GA102 WP v2.1](https://www.nvidia.com/content/PDF/nvidia-ampere-ga-102-gpu-architecture-whitepaper-v2.1.pdf) (3090 284.7), [3090 Ti](https://gpupoet.com/gpu/learn/card/nvidia-geforce-rtx-3090-ti), [A100 DS](https://www.nvidia.com/content/dam/en-zz/Solutions/Data-Center/a100/pdf/nvidia-a100-datasheet-nvidia-us-2188504-web.pdf), [H100 DS](https://resources.nvidia.com/en-us-gpu-resources/h100-datasheet-24306), [H200](https://www.nvidia.com/en-us/data-center/h200/), [B200 DS](https://www.primeline-solutions.com/media/categories/server/nach-gpu/nvidia-hgx-h200/nvidia-blackwell-b200-datasheet.pdf), [Hopper WP](https://www.advancedclustering.com/wp-content/uploads/2022/03/gtc22-whitepaper-hopper.pdf), [CMP 170HX](https://niconiconi.neocities.org/tech-notes/nvidia-cmp-170hx-review/), [Apple silicon](https://en.wikipedia.org/wiki/Apple_silicon), [Apple M5](https://en.wikipedia.org/wiki/Apple_M5), [M5 newsroom](https://www.apple.com/newsroom/2025/10/apple-unleashes-m5-the-next-big-leap-in-ai-performance-for-apple-silicon/), [M5 Pro/Max newsroom](https://www.apple.com/newsroom/2026/03/apple-debuts-m5-pro-and-m5-max-to-supercharge-the-most-demanding-pro-workflows/), [Zakharko M5 microbenchmark](https://tzakharko.github.io/apple-neural-accelerators-benchmark/). M1–M4 have **no** GPU matrix units (the A19/M5 Neural Accelerator is "the first appearance of dedicated matrix multiplication acceleration hardware on Apple GPUs"); M4 ANE "38 TOPS" is a dequantize-to-FP16 path, consensus-ineligible. M5-family INT8 estimates scale the measured A19 rate (~2,048 INT8 OPS/core/cycle, 13.4 TOPS on 5-core A19) by GPU-core count; pending the §N.3-v determinism self-test.

### P.2 Per-class verdicts: v3 → v4

v3 proxy = integer-ALU throughput (whitepaper INT32/non-tensor): RTX 3090 **17.8** TIOPS, 4090 **41.3**, 5080 **56.3**, 5090 **104.8**, CMP 170HX **12.5**, H100 ≈ **33**. Note the v3 compression: an H100 out-ALUs a 3090 by only ~1.9× and a CMP 170HX by ~2.6× — at 10–15× the price — with its 1,979 INT8 TOPS + 3.35 TB/s HBM idle. (A 5090 actually *out-ALUs an H100 ~3×* under v3.)

| Class | v3 (SHA lottery + n=512 ALU matmul) | v4 (n=4096 INT8 tensor matmul) |
|---|---|---|
| **Apple M1–M4** | **Competitive** — cache-resident integer work + ARM SHA extensions + low-latency unified memory; mined within small factors of discrete GPUs. | **Verify-only** — no matrix units / no exact integer path. A Mac that mined v3 does **zero eligible v4 work**; still validates the chain fully (Freivalds is O(n²) on any CPU). |
| **Apple M5 / Pro / Max** | Same as M4 (accelerators irrelevant to SHA/ALU). | **Re-enters** — genuine s8×s8→s32 per-core matrix hardware. M5 Max ≈ 130 TOPS → **~1/15 H100**, ~29% of a 5080, ~16% of a 5090; base M5 ~1/66 H100. Modest but real; pooled-viable (P.3). |
| **RTX 3090 / 3090 Ti (Ampere)** | Among the best perf/$ SHA+ALU parts of the era. | **Still eligible** — Ampere tensor cores do real dense INT8 (284.7/320). Falls to **~1/7 / ~1/6.2 H100**. Key asymmetry vs Apple: a 2020 consumer NVIDIA card survives; a 2023 Apple flagship does not. |
| **RTX 4090 (Ada)** | Competitive (41.3 TIOPS — above H100's ~33). | Eligible at 660.6 → **~1/3 H100**, and **beats an A100 (624)** per device. |
| **RTX 5090 / 5080 (Blackwell)** | v3's top consumer parts (a 5090 out-ALUs an H100 ~3×). | Best consumer v4 miners: 838 / 450.2 → **~1/2.4 and ~1/4.4 H100**, ~1/5.4 and ~1/10 B200. Reranked below datacenter, not excluded. |
| **A100 / H100 / H200 / B200–GB200** | **Uncompetitive per dollar** — no SHA edge; tensor cores + HBM idle. | **Win per device** — 1,979 / 4,500 / 5,000 dense INT8 = 2.4–5.4× a 5090, 7–16× a 3090, 15–35× an M5 Max, ~2× better TOPS/W (H100 ≈ 2.8 vs 5090 ≈ 1.5). The intended reversal (§K). |
| **CMP 170HX (& pre-Turing GPUs)** | **The v3 archetype winner** — 12.5 TIOPS + 1.5 TB/s HBM2e on a cheap ex-mining card, ~parity-class with a 5090 on v3 economics. | **~0 eligible work** — tensor cores non-functional, FP32 FMA locked to 394 GFLOPS, no s8×s8→s32 path; its bandwidth (the reason it existed) buys nothing against a compute-bound AI≈1,365 GEMM. The card that thrived under hash PoW is exactly what v4 retires. |

**The reversal in one sentence:** under v3, a $300 ex-mining CMP and a MacBook were parity-class with datacenter silicon whose tensor cores idled; under v4, the CMP does zero eligible work, M1–M4 Macs drop to verify-only, M5 Macs re-enter at ~1/15 of an H100 — and every consumer NVIDIA card back to Ampere keeps mining, just reranked 2.4–7× below Hopper.

### P.3 Pooled scaling (cross-ref §O.2)

Aggregation is linear in TOPS (independent work units, Freivalds-cheap shares), so "N devices = one datacenter part" is exact:

| Device | Dense INT8 TOPS | N ≈ one H100 (1,979) | N ≈ one B200 (4,500) |
|---|---|---|---|
| RTX 5090 | 838 | **2.4** | **5.4** |
| RTX 4090 | 660.6 | 3.0 | 6.8 |
| A100 80GB | 624 | 3.2 | 7.2 |
| RTX 5080 | 450.2 | 4.4 | 10.0 |
| RTX 3090 Ti | 320 | 6.2 | 14.1 |
| RTX 3090 | 284.7 | 7.0 | 15.8 |
| Apple M5 Max | ~130 | ~15 | ~35 |
| Apple M5 Pro | ~60 | ~33 | ~75 |
| Apple M5 | ~30 | ~66 | ~150 |
| Apple M1–M4 / CMP 170HX | — | **∞ (verify-only)** | ∞ |

Worked pools (§O.2 machinery): 1,000× RTX 3090 ≈ 285 POPS ≈ 144 H100 / 63 B200; 1,000× RTX 5090 ≈ 838 POPS ≈ 423 H100 / 186 B200; 1,000× M5 Max ≈ 130 POPS ≈ 66 H100 / 29 B200; a 10,000-device mixed consumer pool (~100 TOPS avg) ≈ 1,000 POPS ≈ 505 H100 — a datacenter rack row. Every device clears hundreds–thousands of nonces/s at n=4096 (M5 ~200/s, 3090 ~2,100/s, 5090 ~6,100/s, H100 ~14,400/s), so vardiff targets of ~0.1–1 share/s/worker give low-variance PPLNS even for the weakest eligible device.

**Two asymmetries stated plainly:** (1) **v4 does not exclude consumer NVIDIA** — Ampere/Ada/Blackwell all carry full-rate dense INT8; v4 *reranks* (2.4–7× below H100) rather than ejecting. Three 4090s ≈ one H100. (2) Among Apple the line is **generational**: M1–M4 out (no matrix hardware), M5-family in at ~15–66 devices per H100; the M5 Max's 128 GB unified memory also gives headroom if n is ever retargeted up (§L).

### P.4 Intent check (against §0.5 objectives)

| Goal | Outcome | Verdict |
|---|---|---|
| Datacenter wins per device (§0.5 #1,#9) | H100 = 2.4× 5090, 3.0× 4090, 15× M5 Max; B200 = 5.4×/6.8×/35×; +~2× TOPS/W, rack density. | **Met** (see nuance b) |
| Old SHA-era hardware falls away (§0.5 #13) | CMP 170HX: v3 parity-class → v4 zero eligible work. | **Met, vividly.** |
| Matrix-less Apple excluded; capable Apple included (§O.1) | M1–M4 verify-only; M5/Pro/Max mine at their tier. | **Met.** |
| Consumer/Apple still participate, esp. pooled (§0.5 #16, §O.2) | All NVIDIA back to Ampere eligible; 2.4 5090s or 15 M5 Maxes ≈ 1 H100; linear pooled aggregation. | **Met — stronger than the spec's stated ratios** (nuance a). |

**Nuances for owner sign-off:** (a) the per-device lever vs a 5090 is **2.4×/5.4×, not ~5×/~11×** (those used FP8-FP32-accumulate rates; INT8→INT32 is full-rate on GeForce) — direction unchanged, magnitude corrected before activation. (b) a consumer RTX 5090 (838) and 4090 (660.6) **out-mine an A100 (624)** per device, so "datacenter wins" holds against *Hopper/Blackwell-generation* datacenter parts, not NVIDIA's 2020 datacenter part; state the goal as "current-generation datacenter accelerators win." (c) consumer NVIDIA remaining eligible + pooled-viable is a **feature** per §0.5 #16. (d) §P ranks *throughput per card* — who wins blocks when mining; *who chooses to mine at a given BTX price* is the distinct opportunity-cost question, answered by the per-GPU AI-rental break-evens of §Q.21 (consumer cards, at roughly half the datacenter's $/TOPS rental opportunity cost, rationally enter first as the price rises).

---

## Q. Network compute accounting & the btxprice valuation model across the v3→v4 fork

> **Status:** informative/economic companion to the normative consensus sections. Cross-refs: gate removal §A.5, work-unit bound §A.6/§E.3, one-time difficulty rescale §I.4, hardware table §K.1/§K.3, work-unit sizing §M.4, strategic pivot §N.1, pooling §O.2.
> External model under analysis: the [btxprice.com valuation model](https://btxprice.com/valuation-model) ([btxprice.com](https://btxprice.com)). Figures in §Q.3–§Q.4 are pre-calibration estimates, superseded by the measured §I.4 benchmark once available.

### Q.0 Summary

The v3→v4 fork changes *what a nonce is*. In v3 a nonce attempt is a 4-compression SHA-256d header hash that reaches the n=512 matmul only 1 time in 2¹⁸; in v4 every nonce is one fresh dense n=4096 INT8 tensor-core GEMM. Consequently the chainwork-derived rate `M_BTX` reported by `getnetworkhashps(6720)` — the sole compute input to btxprice.com's raw-compute floor — will **drop by roughly five orders of magnitude at the fork while the network's real, useful matrix compute rises by two to six orders of magnitude**. Read naively, the metric inverts reality. This section derives the discontinuity, the exact recalibration of btxprice's `w` constant needed for continuity, and a replacement metric (network INT8-TOPS / H100-equivalents / AI-compute-$) that measures what v4 actually produces.

**Through-line of the §Q economics (read the section in this order):** **(a)** security is *continuous* through the fork and read by the recalibrated Bitcoin-comparable `P_btc` (§Q.5, §Q.9, §Q.18); **(b)** useful compute is *revealed* and read by `TOPS_net`/H100-eq (§Q.6, §Q.10–§Q.11); **(c)** the productive-value / mining economics is the **per-GPU mine-vs-rent switchover** (§Q.21) — which GPU, at what BTX price, mines rather than rents to the AI market — whose marginal-miner equilibrium *is* the production-cost floor `P_prod` (§Q.6 ≡ §S.4.3) bracketing the market price from below (§Q.20).

### Q.1 The btxprice.com model as it stands (v3 baseline)

From [btxprice.com/valuation-model](https://btxprice.com/valuation-model):

- **Raw compute floor:** `P_raw = P_BTC · (SEH / H_BTC)`, with `SEH = w · M_BTX_1w`, `H_BTC` = Bitcoin 1-week hashrate, `w` = calibration constant, `M_BTX_1w` = BTX 1-week MatMul rate from `getnetworkhashps(6720)`.
- **Security %:** `BTX_security_% = 100 · w · M_BTX_1w / H_BTC` — currently **1.5897 %**.
- **Current rate:** `M_BTX` = **315,669,420.87 MatMul/sec** (≈ 3.157×10⁸/s).
- **Calibration constant:** `matmul_security_weight w = 45,251,427,826.03` (≈ 4.525×10¹⁰).
- **Sanity:** `w·M_BTX` = 1.4285×10¹⁹ H/s-equivalent ≈ 1.59 % of `H_BTC` ≈ 9×10²⁰ H/s. ✓
- **Estimator:** work-per-block from the exact 6,720-block chainwork delta ÷ block count (6,720 × 90 s = 7 days); upward moves linear, downward under a 7-day-half-life soft cap; 10-min buckets; 90 s target.
- **Forward assumption:** 12-month forward difficulty estimate **12.71 %**.

Every quantity except `P_BTC`/`H_BTC` is downstream of one number, `M_BTX`. So the fork's effect on the model reduces to its effect on the semantics of `M_BTX`.

### Q.2 What `M_BTX` counts: v3 vs v4 semantics of `getnetworkhashps(6720)`

`getnetworkhashps` is chainwork arithmetic: per-block work = `2²⁵⁶/(target+1)` = expected nonce *attempts* to find a block, so the 6,720-block delta ÷ time is the network's **nonce-attempt rate**, whatever an attempt costs. The label "MatMul/sec" is aspirational; the true unit is nonces/s.

**v3.** A nonce begins with `σ = SHA256d(header)` (182-byte header: 4 SHA-256 compressions) and must pass the 18-bit pre-hash gate (`CheckMatMulPreHashGate`, `src/pow.cpp:2688-2697`) before the matmul; only 1 in 2¹⁸ = 262,144 reaches the n=512 GEMM over GF(2³¹−1) on **integer ALUs**. Therefore:

- `M_BTX` = 3.157×10⁸/s is a rate of **cheap σ-gate hash attempts**, not matmuls.
- Actual n=512 matmul rate = `M_BTX / 2¹⁸` ≈ **1,204 full matmuls/s network-wide**.
- Amortized per-matmul: gate ≈ 2¹⁸ σ-hashes ≈ **1.5×10⁹ ALU ops**; matmul ≈ n³ = 1.34×10⁸ field-mults × ~7–8 ALU ops ≈ **1.0×10⁹ ALU ops** → **~50/50 SHA/ALU-matmul split, zero tensor-core cycles.**
- Per-nonce amortized cost ≈ **~10⁴ 32-bit ALU ops/nonce**.

**v4.** Gate removed (`ε = 0`); every nonce is one fresh dense n=4096 s8×s8→s32 GEMM, k=1, exact INT32 accumulation, Freivalds-verified. Per-nonce enforced work:

- Full-C reference: `2n³` = **1.3744×10¹¹ INT8 ops/nonce**.
- Sketch-optimal (**b=8, m=512** — what a rational miner pays, per the §K.2a roofline fix): `4n²m + 2nm²` = **3.6507×10¹⁰ INT8 ops/nonce** (ratio to full-C = 3.76 ≈ b/2 = 4). *(The earlier b=16 basis gave `W_nonce = 1.7717×10¹⁰`; see the b-invariance note below.)*

> **b-invariance of the economics (§L.2.1/§S.4.3 work-unit-neutrality).** Changing `b` (16→8) doubles the nominal work unit `W_nonce` and therefore *halves* the per-H100 nonce rate (`ν_H100`: 7.26×10⁴ → **3.63×10⁴ nonces/s**), but leaves every economic quantity **exactly unchanged**: `TOPS_net = ν_net × W_nonce` is the hardware's true ops/s (the two factors move inversely and cancel), so `N_eq`, the production floor `P_prod`, `BTX_security_%`, and every hardware ratio are identical. Worked figures below that were computed on the b=16 basis (`W_nonce = 1.7717×10¹⁰`, `ν_H100 = 7.26×10⁴`) remain valid for all economic conclusions; only the nominal nonce-rate *scale* changes. btxprice should adopt `W_nonce = 3.65×10¹⁰` (b=8) as the launch constant.

So post-fork `getnetworkhashps` counts **full n=4096 tensor-core matmuls/s** — the label finally becomes literal.

**Per-nonce cost ratio (v4 ÷ v3):**

| Basis | ops per v4 nonce | ops per v3 nonce | ratio |
|---|---|---|---|
| Sketch-optimal | 1.7717×10¹⁰ INT8 | ~1.0×10⁴ ALU | **≈ 1.8×10⁶×** |
| Full-C | 1.3744×10¹¹ INT8 | ~1.0×10⁴ ALU | **≈ 1.4×10⁷×** |

Decomposition: gate removal 2¹⁸ ≈ 2.6×10⁵; n=512→4096 = 512× per matmul (66× on the sketch basis); the σ-vs-matmul cost structure supplies the rest. **Each v4 nonce is ~2×10⁶ (sketch) to ~10⁷ (full-C)× more raw work than a v3 nonce.**

### Q.3 The `M_BTX` discontinuity: direction and magnitude (Z)

The nonce-rate drop is the *time* ratio (ops move to far-faster tensor cores):

```
Z = t_nonce(v4)/t_nonce(v3) = (ops_v4/ops_v3) × (ALU throughput / INT8 tensor throughput)
```

RTX 5090 (~105 T 32-bit-ALU-ops/s; **838 INT8 TOPS**, §P.1): v3 ≈ 5×10⁹ nonces/s (realistic); v4 (sketch, ε=0.65, b=16 basis) = 838×10¹²×0.65 / 1.7717×10¹⁰ ≈ **3.07×10⁴ nonces/s** → **Z ≈ 1.6×10⁵**; other devices **Z ≈ 10⁵–10⁶**. *(Z scales with the work unit — halve the nonce rate / double Z at the launch b=8; ×~4 under full-C. Immaterial: Ω is **read from chainparams, never estimated**, §Q.9.2.)*

Network illustration: 100 H100s = 7.26×10⁶ nonces/s vs today's 3.157×10⁸ = a **43× drop** in `M_BTX`, while real useful compute is up ~400,000× (Q.4). **Raw `M_BTX` under-represents — inverts — the compute change**; un-recalibrated, btxprice's `SEH` reports a ~99.999 % "hashrate collapse" at the fork.

Post-fork per-device nonce rates (sketch basis, ε=0.65, W=1.7717×10¹⁰):

| Device | Dense INT8 TOPS | Delivered (ε=0.65) | v4 nonces/s |
|---|---|---|---|
| B200 | 4,500 | 2,925 | 1.65×10⁵ |
| H100/H200 | 1,979 | 1,286 | 7.26×10⁴ |
| RTX 5090 | ~400 | 260 | 1.47×10⁴ |
| RTX 5080 | ~225 | 146 | 8.3×10³ |
| Apple M5 Max | ~130 | ~85 | 4.8×10³ |
| Apple M5 | ~30 | ~20 | 1.1×10³ |
| Apple M4 | ~0 usable | — | 0 (verify-only, §O.1) |

*Note: the RTX 5090/5080 rows use pre-§P figures (~400/~225 dense) kept for the Z-derivation's history; §P.1's primary-sourced correction (838/450.2 dense — INT8 is full-rate on GeForce) governs, giving 544.7/292.6 delivered dTOPS → **3.07×10⁴ / 1.65×10⁴ nonces/s**. The §Q.21 economics uses the corrected values. Z's order of magnitude is unaffected.*

### Q.4 Effective useful matrix compute, before vs after (X and Y)

**Before (v3).** Real matmul rate = 1,204 n=512 matmuls/s → useful ops = 1,204 × 2×512³ = **3.23×10¹¹ ops/s ≈ 0.32 TOPS network-wide** (32-bit ALU field ops, not tensor). The entire v3 network does **~1/4,000 of one H100's matrix arithmetic**, with ~half its cycles burned on SHA-256 of no matrix value.

**After (v4).** Effective matrix compute = delivered network INT8 tensor throughput `TOPS_net = ε · Σ P_int8` — ~100 % of mining cycles are dense INT8 GEMM (verification is O(n²) noise).

**Same-hardware boost X** (v3 fleet flips the switch):

```
X ≈ f_gate × f_tensor × f_util
  f_gate   ≈ 2×      (SHA-gate cycles redirected; 1.9–2.4× for 47–60 % SHA share)
  f_tensor ≈ 5–30×   (integer-ALU field emulation → native INT8 tensor path)
  f_util   ≈ 1.2–2×  (n=512 cache-resident → n=4096 compute-bound, AI = n/3 ≈ 1,365)
  X ≈ 12–120×,  headline ≈ 30×  (direct RTX 5090 check ≈ 17–35×) ✓
```

**Composition boost Y** (fleet → datacenter INT8; per-device H100/5090 ≈ 4.9×, B200/5090 ≈ 11.2×, H100/M5 Max ≈ 15×; tensor-less v3-optimal hardware exits): fleet-weighted **Y ≈ 5–10×**.

Combined **X·Y ≈ 10²–10³× on a value-conserved fleet**; unbounded beyond that as commodity AI capacity joins (one marginal H100 ≈ 4,000× today's entire useful rate).

### Q.5 Recalibrating btxprice: the `w` rescale (exact)

Continuity at fork height `t_f` on an unchanged fleet requires `w_v4 · M_BTX(t_f⁺) = w_v3 · M_BTX(t_f⁻)`, and `M_BTX(t_f⁺)/M_BTX(t_f⁻) = 1/Z`, so:

```
w_v4 = w_v3 · Z = w_v3 · (device-time per v4 nonce / per v3 nonce)
```

Numerically `w_v4 ≈ 4.525×10¹⁰ × ~5×10⁵ ≈ 2×10¹⁶` (order 10¹⁵–10¹⁶); check `w_v4·M_v4` ≈ 1.43×10¹⁹ = `w_v3·M_v3`. ✓

**Do not estimate Z — read it from consensus.** §I.4 mandates a one-time `next_target = parent_target × Num/Den` rescale + ASERT re-anchor at `nMatMulV4Height`. Since `getnetworkhashps` = `2²⁵⁶/(target+1)` arithmetic, the fork rescales reported nonce-rate by exactly that constant, so `w` rescales by the reciprocal — read from chainparams at tag time — and continuity of `SEH` and `BTX_security_%` is preserved by construction. **See §Q.9.2 for the convention-proof form: publish the single scalar `Ω ≡ w_v4/w_v3 = Num/Den = Z > 1` with the three tag-time sign checks; the earlier "Den/Num" shorthand here inverts §I.4's target-rescale direction and is superseded by Ω.**

Estimator plumbing fixes: (1) **never span the fork with the 6,720-block window** (split deltas below/above `nMatMulV4Height`, or scale pre-fork per-block work by `Den/Num`); (2) **bypass the 7-day downward soft cap at the fork** (the drop is a unit change, not a decline); (3) **re-base the 12.71 % forward estimate** (post-fork growth tracks INT8 accelerator deployment, a steeper curve).

### Q.6 From "% of Bitcoin" to AI-compute: the metric v4 deserves

v3 compute is economically ~worthless outside the security-equivalence frame (half SHA-256, half GF(2³¹−1) ALU emulation = 0.32 TOPS ≈ a **de minimis flow** — `V_ai = TOPS_net·(rental $/dTOPS-yr)` computed on live inputs; no fixed value — as AI compute for the whole network). v4 compute is dense s8×s8→s32 GEMM — the same commodity AI clouds rent hourly. Natural units: INT8-TOPS, H100-equivalents, dollars.

**Reinterpret `getnetworkhashps`:**

```
TOPS_net = getnetworkhashps(6720) × W_nonce,   W_nonce = 4n²m + 2nm² = 3.65×10¹⁰   (n=4096, b=8, m=512)
H100_eq  = TOPS_net / (ε_H100 × 1,979×10¹²) ≈ TOPS_net / 1.286×10¹⁵
```

`W_nonce` is the §E.3/§M.4 consensus work unit (b=8 launch value; the b=16 value 1.7717×10¹⁰ appears in worked examples — the two give identical `TOPS_net`/`H100_eq`, §Q.4 b-invariance note). So `TOPS_net` is a lower bound (full-C miners do b/2 = 4× more at b=8). Check: one H100 at 3.63×10⁴ nonces/s (b=8) → 1.286×10¹⁵ ops/s = 1,286 TOPS = its delivered throughput ✓ — identical to the 7.26×10⁴-nonces/s b=16 check, since ν and W_nonce move inversely.

**Cost-of-production price floor (proposed btxprice addition — a PRICE in $/BTX, ≡ the §S.4.3 marginal-cost floor):**

```
P_prod ($/BTX) = (compute $ / time) / (BTX minted / time) = N_eq · r / 800
```

`N_eq = TOPS_net / 1,286` delivered H100-equivalents; `r` = $/H100-eq-hr; **800 BTX/hr** = 20 BTX subsidy × 40 blocks/hr at 90 s blocks (§S.4.3). This is *exactly* the §S.4.3 floor — one formula, one notation. It is **not a valuation and not a price model** — it is the **supply-side marginal cost to mine one coin** [$/BTX], a **soft** lower bracket the marginal miner won't persistently sell below (it tracks price both ways and moves with `N_eq`, so it is an anchor, not a hard support — §S.4.3, §0.7-(4); and it is a *read-out*, never a protocol input). It is dimensionally comparable to `P_raw`/`P_btc` (§Q.17.0) but answers a different question (cost-to-produce, not what-it's-worth). Mid-2026 H100 on-demand ≈ **$2–3/GPU-hr** (median ≈$2.99: [IntuitionLabs](https://intuitionlabs.ai/articles/h100-rental-prices-cloud-comparison), [getdeploying](https://getdeploying.com/gpus/nvidia-h100), [Thunder Compute](https://www.thundercompute.com/blog/nvidia-h100-pricing), [CloudZero](https://www.cloudzero.com/blog/h100-gpu-cost/)). At rental rate `r` and an illustrative `N_eq`-H100-eq network: `P_prod = N_eq × r / 800` (computed on live inputs; no fixed value) — i.e. the fleet spends `N_eq × r` per hour and mints 800 BTX/hr, so the per-coin production cost scales linearly with both `N_eq` and `r`. **This is per-coin marginal cost, NOT the network's hourly worth.**

**Per-GPU foundation (§Q.21).** `P_prod` is not a primitive — it is the aggregate/marginal view of the per-GPU mine-vs-rent break-even `P*_g = R_g × TOPS_net/(800·T_g)` (§Q.21.1); identically, `P*_H100 ≡ P_prod`, i.e. `P_prod` above is exactly the H100's own switchover price at the given network size (computed live; no fixed value). The **operative** floor is `P*` of the marginal *active* class: at low `P_BTX` the margin is consumer silicon whose AI-rental $/TOPS is ~half the H100's, so the effective floor sits ~40–50% below the H100-denominated figure until datacenter capacity enters (§Q.21.3–§Q.21.4).

**Annual-flow footnote (a FLOW, $/yr — not a price, never comparable to one):** the same capacity carries an aggregate AI-market value `V_ai = TOPS_net × c_TOPS·yr`, with `c_TOPS·yr = r × 8,760 hr / 1,286 dTOPS` = **$17.0 per delivered-TOPS-year** at `r = $2.50/hr` (the per-H100-eq-year figure is `1,286 × c_TOPS·yr`, computed on live inputs; no fixed value). Worked example (100-H100-eq network): `getnetworkhashps` = 7.26×10⁶ nonces/s → `TOPS_net` = **128,600 TOPS = 100 H100-eq** → `V_ai = TOPS_net × c_TOPS·yr` (computed live; no fixed value). Versus v3 today: `M_BTX` *looks* 43× bigger yet backs a near-zero `V_ai` vs a many-orders-larger post-fork `V_ai` — a ~10⁵–10⁶× understatement, matching Z. Dimensions guardrail: `V_ai` is $/yr (dividing by supply would give $/BTX·yr, a yield, still a flow); it must **never** be compared to, plotted against, or `max()`-ed with a $/BTX price such as `P_raw`/`P_btc` or `P_prod` (§Q.17.0).

Recommended post-fork: keep `P_raw`/`BTX_security_%` (with `w_v4`) as the Bitcoin-anchored relative-comparable (demand-side, aspirational — **not a floor**), add `TOPS_net`/`H100_eq` as the headline compute series and `P_prod` as the same-dimension supply-side cost floor. Present them as a **three-object bracket, not competing valuations** (§Q.20): `P_prod` (floor) ≤ observed market price ≤ `P_btc` (relative-comparable ceiling-ish anchor) — never `max()`-ed, with `P_prod` anchored to an external compute market independent of Bitcoin.

### Q.7 Headline (the crisp answer)

**Moving v3→v4, the network's effective (useful matrix) compute rate increases by ≈30× on the same hardware (range ~12–120×: ≈2× from deleting the SHA-gate half of the cycle budget × ≈5–30× from leaving integer-ALU field emulation for native INT8 tensor cores × ≈1.2–2× from n=512→4096 utilization), and by a further ≈5–10× as hardware composition shifts to datacenter INT8 parts — ≈10²–10³× combined on a value-conserved fleet, with unbounded further growth as commodity AI capacity joins (one H100 alone ≈4,000× today's entire 0.32-TOPS useful rate). The raw nonce-rate metric `M_BTX` will instead DROP by Z ≈ 3×10⁵–10⁶× per unit of hardware (each v4 nonce costs ~2×10⁶× the ops of a v3 σ-gate attempt: 2¹⁸ gate removal × 66–512× matrix-size jump, partially offset in time by tensor throughput), and must either be recalibrated — `w_v4 = w_v3 × Z`, read exactly from the §I.4 `Num/Den` fork constant, ≈4.5×10¹⁰ → ~10¹⁶ — or, better, replaced by the INT8-TOPS metric `TOPS_net = getnetworkhashps × 1.7717×10¹⁰`, which reports the true growth in units the AI-compute market already prices.**

### Q.8 Sources

- [btxprice.com valuation model](https://btxprice.com/valuation-model); [btxprice.com](https://btxprice.com)
- Hardware: [H100 datasheet](https://resources.nvidia.com/en-us-gpu/h100-datasheet-24306) · [H200](https://www.nvidia.com/en-us/data-center/h200/) · [B200](https://www.spheron.network/blog/nvidia-b200-complete-guide/) · [RTX 5090](https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/rtx-5090/) · [Puget 5090/5080](https://www.pugetsystems.com/labs/articles/nvidia-geforce-rtx-5090-amp-5080-ai-review/)
- H100 rental (2026): [IntuitionLabs](https://intuitionlabs.ai/articles/h100-rental-prices-cloud-comparison) · [getdeploying](https://getdeploying.com/gpus/nvidia-h100) · [Thunder Compute](https://www.thundercompute.com/blog/nvidia-h100-pricing) · [CloudZero](https://www.cloudzero.com/blog/h100-gpu-cost/)

---

### Q.9 Continuity model: the two-metric representation

> **Status:** informative; extends §Q.5–§Q.6 into a full representation model for [btxprice.com](https://btxprice.com). Cross-refs: §I.4 (fork rescale), §Q.2 (nonce semantics), §Q.4 (X, Y), §E.3/§M.4 (work unit). **This subsection also corrects the sign convention of the §Q.5 shorthand — see Q.9.2.**

### Q.9.1 The continuity invariant, fully derived

The btxprice security metric is `SEH = w · M_BTX_1w`, `BTX_security_% = 100·w·M_BTX_1w/H_BTC`, `P_raw = P_BTC·SEH/H_BTC`. At the fork instant `t_f` the physical fleet is unchanged — same devices, capital, energy. An attacker must still match that fleet, and every v4 efficiency gain accrues identically to attacker and defender, so the Z factors cancel from the attack-cost ratio: **attack cost is invariant at `t_f`**, and the security metric must be **continuous** there. Continuity of `SEH` requires

```
w_v4 · M_BTX(t_f⁺) = w_v3 · M_BTX(t_f⁻)                      (Q.9-1)
M_BTX(t_f⁺) = M_BTX(t_f⁻)/Z  (unit change, §Q.3)  ⇒  w_v4 = w_v3·Z    (Q.9-2)
```

One rescale makes `SEH`, `BTX_security_%`, `P_raw` all continuous by construction. Worked (midpoint Z=5×10⁵): pre-fork `SEH` = 4.5251×10¹⁰ × 3.1567×10⁸ = 1.4285×10¹⁹ H/s-eq = 1.5897% of `H_BTC` ≈ 8.985×10²⁰ ✓; post-fork `M(t_f⁺)` = 631.3 nonces/s, `w_v4` = 2.2626×10¹⁶, `SEH` = 1.4284×10¹⁹ ✓ identical, **no step**. Range `w_v4` = 4.525×10¹⁰ × (3×10⁵…10⁶) = **1.36×10¹⁶ … 4.53×10¹⁶** (order 10¹⁶).

### Q.9.2 The exact fork constant Ω — and a sign correction

**Do not estimate Z — read it from consensus.** §I.4 mandates `next_target = parent_target × Num/Den` at `nMatMulV4Height`. Because v4 attempts/s *drop* by Z, blocks get Z× easier, so the target gets Z× **larger**: `Num/Den = Z > 1`. `getnetworkhashps` = `2²⁵⁶/(target+1)` arithmetic, so reported nonce rate multiplies by the reciprocal `Den/Num = 1/Z`. Substituting into (Q.9-1): `w_v4 = w_v3 × Num/Den = w_v3 × Z`.

> **Correction to the §Q.5 shorthand.** §Q.5 wrote "`w_v4 = w_v3 × Den/Num`" alongside "`w_v4 = w_v3·Z`"; these are consistent only if (Num,Den) name the *reported-rate* rescale rather than §I.4's *target* rescale. To make the direction impossible to get wrong, publish one dimensionless scalar:
>
> ```
> Ω ≡ w_v4/w_v3 = target(t_f⁺)/target(t_f⁻) = M(t_f⁻)/M(t_f⁺) = Z
> ```
>
> with three tag-time sign checks: **Ω > 1**, **w_v4 > w_v3**, **reported M_BTX drops by Ω**. Expected Ω ≈ 3×10⁵–10⁶. Any implementation whose displayed security % moves at the fork has Ω inverted.

### Q.9.3 Estimator plumbing (drop-in changes)

1. **Fork-split window — never average across incommensurate units.** While `h_f` is inside the 6,720-block window: `SEH_1w = [w_v3·ΔCW(pre) + w_v4·ΔCW(post)] / T_window`. Post-fork per-block chainwork is exactly `1/Ω` of pre-fork on the same fleet, so both terms are in identical security units. Never divide a raw mixed-unit chainwork delta by 6,720.
2. **Soft-cap bypass at `h_f`.** The 7-day-half-life downward cap treats drops as decay; un-bypassed, a Z=3×10⁵–10⁶ rebase takes `log₂(Z) ≈ 18–20` half-lives ≈ **18–20 weeks** of fabricated "collapse." Mark the `h_f` sample a unit rebase, exempt from the cap. With fixes 1+2 the displayed `SEH` never drops — assert in CI.
3. **Re-base the 12.71% forward estimate.** It regresses on v3 difficulty history (dead units after `h_f`). Freeze as a legacy lower band, restart the regression at `h_f`, prior the interim growth on the INT8-accelerator deployment curve (v4 `M_BTX` growth *is* fleet INT8-TOPS growth, §Q.6 — far steeper than 12.71%/yr).

### Q.9.4 The two metrics, side by side

| | **(a) Security-equivalence** | **(b) AI-compute** |
|---|---|---|
| Series | `BTX_security_%`, `SEH`, `P_raw` | `TOPS_net = getnetworkhashps × 1.7717×10¹⁰`; `H100_eq = TOPS_net/1.286×10¹⁵`; price floor `P_prod = N_eq·r/800` [$/BTX]; flow `V_ai = TOPS_net×$17/dTOPS·yr` [$/yr] (§Q.6, §Q.17.0) |
| Measures | Capital+energy committed = attack cost | Valuable AI matmul actually produced |
| At fork | **CONTINUOUS** — recalibrate `w_v4 = w_v3·Ω`; 1.5897%→1.5897% | **STEPS UP ~30×** — 0.32 TOPS → ~5.6–18.6 TOPS same fleet (Q.10) |
| `w` role | `w_v3` below `h_f`, `w_v3·Ω` at/above | none — absolute units |
| Why | Same hardware at `t_f`; attacker gains the same Z; attack cost invariant | v3 burned ~½ cycles on SHA + rest on ALU field emulation (0.32 TOPS); v4 production ≈ capability |

The step and the flat line answer different questions about the same fleet: security = *cost to replicate the network* (unchanged at `t_f`); AI-compute = *what the cycles are worth outside* (v3 wasted ~97% of latent tensor capability, v4 spends ~100% on hourly-rentable INT8 GEMM). The step is a **utilization/efficiency reveal, not new hardware and not a security event.** Rendering the efficiency gain as a security jump double-counts; rendering the security continuity as "no improvement" hides the point of v4.

---

### Q.10 Latent capacity and the hidden-power question

### Q.10.1 Back-cast methods

**Method A — efficiency back-cast (primary):** `L = 0.32 TOPS × X`, X ≈ 12–120 → **3.8…38 TOPS**, headline 0.32×30 ≈ **10 TOPS**.
**Method B — hardware-mix (cross-check):** all-RTX-5090 fleet → 0.0631 device-eq × 260 TOPS = 16.4 TOPS; half tensor-less → ~8; all tensor-less → ~0.
**Method C — consensus-implied (most authoritative, available at tag time):** `TOPS_net(t_f⁺) = [3.157×10⁸/Ω]×1.7717×10¹⁰` → Ω=3×10⁵: **18.6 TOPS**; 5×10⁵: **11.2**; 10⁶: **5.6**.

Agreement: **latent ≈ 4–40 TOPS, central ≈ 10 TOPS** = ~0.008 H100-eq (~1/130th of an H100), worth a `V_ai`-scale AI-compute value (computed live via `V_ai = TOPS_net·(rental $/dTOPS-yr)`; no fixed value) versus the smaller `V_ai` v3 actually produced. Implied v3 capability utilization ≈ 0.32/9.7 ≈ **3%** (and even that was field-emulation ops with no external market). Uncertainty is dominated by hardware mix (Method B spread ~0–40); the band collapses to a point at `t_f⁺` when Method C turns the back-cast into a measurement.

### Q.10.2 How the AI-compute graph treats the fork

**Recommendation: show both.** Solid headline series = **measured useful work only** (0.32 TOPS pre-fork, `getnetworkhashps × W_nonce` post-fork, honest step included — no back-cast ever headline). Overlay the **pre-fork latent band (4–40 TOPS, dashed, central 10)** with the vertical gap at `h_f` labeled **"efficiency the v3 solver wasted (~30×)"**. Mandatory caveat: *back-cast assumes the v3 fleet carries tensor silicon; the mix is unobserved, true latent may sit anywhere in the band incl. near its floor for a tensor-less fleet.* After `t_f⁺`, replace the band's right endpoint with the Method-C measured point.

---

### Q.11 Graph specifications (v3→v4)

> Four time-series charts for [btxprice.com](https://btxprice.com) (a fifth, chart **E** — the per-GPU mine-vs-rent switchover diagram, price on the x-axis rather than height — is specified in §Q.21.4). Time axis: block height with a labeled `h_f = nMatMulV4Height` marker (date secondary). Shared annotation: *"MatMul v4 fork — work-unit change (Ω rescale). Security continuous; AI output steps."*

**(A) "BTX security vs Bitcoin %" — continuous, no-cliff.** Y linear ~0–3%. Series `100·w(h)·M_BTX_1w/H_BTC` with per-era `w` and fork-split window. Flat at 1.5897% through `h_f` (**no discontinuity**), then organic growth. Acceptance test: `|%(h_f⁺) − %(h_f⁻)| < window noise`.

```
 %BTC
 2.0 |                            ..·
1.59 |—•—•—•—•—•—•—•╂—•—•—•—•·˙
     |              ┆h_f  (no cliff)
     +──────────────┴────────────── height
```

**(B) "Raw nonce rate M_BTX" — diagnostic only; never headline raw.** Y log 10²–10⁹. Raw `getnetworkhashps`. ~3.157×10⁸ into the fork, **vertical cliff to ~3×10²–10³** (drop by Ω; reads as 99.999+% collapse). Treatment (pick one): (1) hide on an advanced/diagnostics page; (2) plot per-era normalized (×1/Ω pre-fork) → continuous line ≡ chart A numerator; (3) if raw shown, force a hatched "unit change" break band at `h_f` with both unit labels ("σ-gate attempts/s" | "n=4096 INT8 matmuls/s") and disable %-change readout across `h_f`. Soft cap must never render this as an 18–20-week decay ramp.

```
 nonce/s (log)
 10⁸ |━━━━━━━━━━━━━━┓
     |  "σ-gate     ┃ ▓▓ unit-change band
 10⁵ |   attempts"  ┃ ▓▓  (drop = Ω, by construction)
     |              ┗━━━━━━━━━━━  "n=4096 INT8 matmuls"
 10² |              ┆h_f
     +──────────────┴────────────── height
```

**(C) NEW — "Network AI-compute (TOPS_net / H100-eq)" — the reveal chart.** Y log 0.1→10⁶; right axis `H100_eq = TOPS_net/1.286×10¹⁵`. Solid = measured useful work: flat 0.32 TOPS pre-fork, **step at `h_f`** to `TOPS_net` (~5.6–18.6 same-fleet), then ×5–10 (composition Y) toward 10²–10³× (100 H100-eq = 128,600 TOPS). Dashed pre-fork band 4–40 TOPS (latent, central 10); gap arrow **"efficiency the v3 solver wasted (~30×)"**; band caveat per Q.10.2.

```
 TOPS (log)                              ___···  ×5–10 composition (→10²–10³×)
 10²  |                           __——˙˙
 10   | ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ●━━━˙          ← measured TOPS_net
      |  latent back-cast    ┆ ↕ gap = "efficiency the
 1    |  band 4–40 (dashed)  ┆    v3 solver wasted (~30×)"
 0.32 |━━━━━━━━━━━━━━━━━━━━━━┥
      |   measured useful    ┆h_f
      +──────────────────────┴──────────── height
```

**(D) NEW — "Price bracket ($/BTX): cost-of-production floor, market price, security-comparable" — three same-dimension lines.** Y log $/BTX; all series are **prices (stocks, §Q.17.0)**, and they **bracket** the market — never `max()`-ed (§Q.20). (1) `P_prod = N_eq·r/800` (supply-side cost **floor**, §Q.6 ≡ §S.4.3): ≈ $0 pre-fork under v3 (0.32 TOPS junk-fleet compute → near-zero cost, §S.4.1 — the near-zero floor is the dumping regime, not a missing signal), switches on at `h_f`, then rises ∝ `N_eq`. (2) observed market price: sits between the two. (3) `P_btc` (§Q.18): demand-side relative-comparable (**not a floor**), continuous through `h_f` via `w_v4`, then also rises ∝ `N_eq`. Shade the `P_prod → P_btc` band labeled **"disequilibrium the market prices"** — because both bracket lines scale ∝ `N_eq`, their ratio is constant (§Q.20): on the log axis they are **parallel**, **no crossover** (the former "crossover" annotation is retracted — it compared a $/BTX price to a $/BTX·yr flow and froze `P_btc` while growing the flow). Annotate that v4's thesis (§S.4.3/§S.4.5) is to **raise `P_prod`**, narrowing the band from below. Optional dotted overlay: `P_prod_inf` (inference basis, §Q.19) hugging `P_prod` within ±10%. Never plot the annual flow `V_ai` ($/yr) on this axis.

```
 $/BTX (log)
       |                     P_btc      ___···
 ~10³  |━━━━━━━━━━━━━━━━━━━━●━━━———˙˙            (demand comparable; NOT a floor; ∝ N_eq)
       |   ▒▒ "disequilibrium the market prices" ▒▒  (constant ratio — parallel,
       |          ·· market price ··                    NO crossover; v4 raises floor↑)
       |                     P_prod     ___···
 ~10⁻⁴ |                    ●———˙˙                (cost FLOOR, ∝ N_eq; ·· P_prod_inf ±10%)
  ~$0  |••••••••••••••••••••┆   v3: P_prod ≈ 0 (junk-hw dumping regime, §S.4.1)
       |                    ┆h_f
       +────────────────────┴──────────────── height
```

---

### Q.12 btxprice team handoff (implementation checklist)

> Self-contained. Current constants: `w_v3 = 45,251,427,826.03`, `M_BTX ≈ 3.157×10⁸/s`, security % = 1.5897%, 6,720-block (7-day) window, 90 s blocks, 7-day-half-life downward soft cap, 12.71% forward estimate.

1. **The one fork constant.** From BTX chainparams at tag: `nMatMulV4Height (=h_f)`, `nMatMulV4AsertRescaleNum/Den`. Publish `Ω = Num/Den = w_v4/w_v3 = M_BTX(h_f⁻)/M_BTX(h_f⁺)`. Hard-fail gates: `Ω > 1`; `Ω ≈ 3×10⁵–10⁶`; reported `getnetworkhashps` drops by exactly Ω. (Direction: §I.4 rescales the *target* by Num/Den; reported hash-rate rescales by Den/Num = 1/Ω.)
2. **Recalibrate w — era-indexed.** `w(h)=w_v3` for h<h_f; `w(h)=w_v3×Ω` for h≥h_f (≈2.26×10¹⁶ at Ω=5×10⁵). Check `w_v4·M(h_f⁺) = w_v3·M(h_f⁻) = 1.4285×10¹⁹` → security stays 1.5897%.
3. **Fork-split the window** (item Q.9.3-1). Never average pre/post nonce rates.
4. **Soft cap:** exempt the `h_f` transition (unit rebase, not decline); with 2–3 the SEH series shows no drop — regression-test it.
5. **Forward estimate:** freeze 12.71% as legacy band; restart regression at `h_f`; interim central = INT8-accelerator deployment growth; display as a band.
6. **Add the compute series and the production floor** (post-fork `getnetworkhashps` = literal n=4096 INT8 matmuls/s): `TOPS_net = getnetworkhashps × 1.7717×10¹⁰`; `H100_eq = N_eq = TOPS_net/1.286×10¹⁵`; price floor `P_prod = N_eq × r/800` in $/BTX (r = $/H100-eq-hr, refresh quarterly; ≡ §S.4.3). Pre-fork chart-C values: measured useful `M_BTX/2¹⁸ × 2·512³ ≈ 0.32 TOPS`; latent band 4–40 (central 10), dashed, caveated. Present the **three-object bracket, no `max()` composite**: `P_prod` (supply-side cost floor) ≤ market price ≤ `P_raw`/`P_btc` (demand-side relative-comparable, not a floor); `P_prod` is a cost, not a valuation; the spread is the disequilibrium the market prices (§Q.20). The annual flow `V_ai = TOPS_net × $17/dTOPS·yr` [$/yr] is footnote-only and never compared to a price (§Q.17.0).
7. **Add the per-GPU switchover series (§Q.21).** Poll per-GPU AI-rental rates `R_g` quarterly with timestamps (datacenter: provider medians for H100/H200/B200; consumer: vast.ai/RunPod marketplace medians for RTX 5090/4090/3090, A100; Apple: none — use the power-only floor). Per GPU compute `BTX/hr_g = 800·T_g/TOPS_net`, break-even price `P*_g = R_g/(BTX/hr_g)` [$/BTX], break-even rental `R*_g = BTX/hr_g × P_spot` [$/hr]; render the §Q.21.2 table + chart E (§Q.21.4). Identity checks: `P*_H100 ≡ P_prod` (item 6); operative floor = `P*` of the marginal active class, not necessarily the H100's.
8. **Charts** per §Q.11 (A continuous; B diagnostics-only with unit-change band; C step + latent band; D three-object $/BTX bracket `P_prod` ≤ market ≤ `P_btc` — no crossover annotation; E per-GPU switchover, §Q.21.4). Relabel v3-era "MatMul/sec" → "nonce attempts/s" (literal only at v4).
9. **Messaging guardrail (verbatim-usable):** *"The v4 fork changes the unit of work, not the security of the chain. BTX security (% of Bitcoin) is continuous through the fork — same hardware, same attack cost, no jump. What steps up ~30× is useful AI output per unit hardware: v3 spent ~97% of the fleet's latent tensor capability on SHA gates and ALU emulation; v4 turns it on. The new TOPS/H100-eq charts show an efficiency/utilization reveal — not new hardware, and not a security increase."* Never present the AI-compute step as a security gain; never show the raw nonce cliff without the unit-change band.
10. **Dry-run** on regtest (`nMatMulV4Height=100`; use a synthetic Ω to exercise items 2–4) before mainnet `h_f`.

---

### Q.13 Interpretation: resolving the four framings

> **Status:** informative. Companion to §Q.0–§Q.7. This subsection settles how to *talk about* the fork's effect on "the network's compute." Four reasonable framings of the same event appear to contradict each other. They do not — they are statements about **two different quantities**, and every honest claim must say which one it is about.

### Q.13.1 The two quantities

- **`S(t)` — security / attack-cost.** The capital-plus-energy cost of assembling enough compute to out-work the honest network (the 51% budget). What `P_raw` / `BTX_security_%` proxy (§Q.1), and what chainwork measures *after* the §Q.5 `w` recalibration.
- **`U(t)` — useful/productive compute.** The rate of economically valuable dense-matrix arithmetic the network actually performs, in units the AI market prices: `TOPS_net = getnetworkhashps(6720) × 1.7717×10¹⁰` (§Q.6), dollarized two ways: as the annual flow `V_ai = TOPS_net · $17/dTOPS-yr` [$/yr] and, per newly minted coin, as the production-cost price floor `P_prod = N_eq·r/800` [$/BTX] (§Q.6 ≡ §S.4.3; never mix the two — §Q.17.0).

**At the fork, `S` is continuous and `U` steps up ~30× on the same hardware (~10²–10³× combined with composition shift, §Q.4).** Compatible because they measure different things:

| | `S` (attack cost) | `U` (useful compute) |
|---|---|---|
| v3 value | 1.5897% of Bitcoin | **0.32 TOPS** ≈ a de minimis `V_ai` as AI compute (computed live; no fixed value) |
| At the fork | **Continuous** — same fleet/capital/electricity; an attacker's hardware enjoys the same v4 efficiency gains, so the *ratio* (cost to out-compute) is unchanged to first order. | **Steps up ~30×** same-hardware (12–120×) — work per joule changes from SHA + integer-ALU field emulation to native INT8 tensor GEMM. |
| Why | Security is *relative* (attacker vs honest majority); a solver-efficiency change applied to both sides cancels. | Useful output is *absolute*; a solver-efficiency change applied to production does not cancel — it is the whole point. |

Physical resolution: the v3 fleet's INT8 tensor capacity was **installed but idle** — ~50% of cycles on SHA-256 of no matrix value, ~50% emulating GF(2³¹−1) on integer ALUs, surfacing only 0.32 TOPS while tensor cores sat dark. The capacity was *physically present* (hence `S` continuity), *masked by the solver* (hence the ~30× jump in `U`), and *invisible to the SHA-nonce metric* (hence the new `TOPS_net` metric).

### Q.13.2 The four framings, answered

**(a) "More effective compute in a real way vs Bitcoin?"** — **YES in useful-output/economic-value terms; NO in raw-security terms.** In `U`-terms the same hardware produces ~30× more useful matrix arithmetic, and that arithmetic is dense INT8 GEMM — the commodity AI clouds rent by the hour — where Bitcoin's SHA-256 output has no external market. In `S`-terms nothing jumps (~1.59% of Bitcoin on an unchanged fleet). Any "more compute vs Bitcoin" claim must be a **value-of-work** claim, never a security claim.

**(b) "Exactly the same, keep numbers consistent?"** — **YES for the security metric; §Q.5 is the mechanism.** `w_v4 = w_v3 × Ω` (Ω = Num/Den = Z > 1, §Q.9.2) preserves `SEH`/`BTX_security_%`. The raw nonce rate drops ~10⁵–10⁶× as a **unit change**; reporting it un-rescaled prints a fictitious 99.999% collapse. "Keep it consistent" is right — *for this metric*.

**(c) "Uncovers hidden power the inefficient solver masked?"** — **YES, precisely.** The v3 fleet's tensor cores executed zero mining cycles. v4 routes the work onto units that were always there. Decomposition: ≈2× (SHA reclaimed) × ≈5–30× (ALU emulation → native tensor) × ≈1.2–2× (n=512→4096) ≈ 30×. "Uncovered latent capacity" accurate; "created new capacity" not.

**(d) "Already there and accounted for, so no new claims?"** — **Already there: yes. Accounted for: no.** The capacity was installed (consistent with security continuity) but no metric surfaced it: `M_BTX` counted σ-gate attempts, and only 0.32 TOPS of matrix arithmetic was ever performed (a de minimis `V_ai`). Post-fork it is both *used* and *measured* (`TOPS_net`/`H100_eq`/`P_prod`). So a new **capacity-utilization and value** metric IS warranted, while the **security** metric correctly reports nothing jumped. Reporting both, clearly labeled, is the discipline of this section.

### Q.13.3 One-line reconciliation

**The fork does not add a single transistor (`S` continuous); it stops wasting ~97% of the transistors already there (`U` up ~30×) and starts measuring what they produce in the units the AI market prices.** Any statement about the fork's effect on "compute" is ill-formed until it names whether it is about `S` or `U`.

---

### Q.14 BTX v4 compute vs Bitcoin: sterile vs productive security spend

> **Status:** informative. Cross-refs §Q.6, §S.1/§S.4.3, §N.1, v3 spec §3.2 (`doc/btx-matmul-pow-spec.md`).

### Q.14.1 The qualitative claim, precisely

Bitcoin and BTX v4 both convert capital + energy into attack cost. The difference is **what the spend consists of and whether it has value outside the chain it secures**:

1. **Bitcoin's SHA-256 work is economically sterile outside securing BTC.** No market rents SHA-256d compressions; competitive hardware (SHA ASICs) does nothing else; the nonce has zero external value. By design — but 100% of the security budget is, to the outside economy, pure burn.
2. **BTX v4's work is the exact commodity the AI market prices.** A v4 nonce is one dense n=4096 INT8 tensor-core GEMM — same operation, silicon, precision as production AI inference. The competitive hardware *is* AI-rental hardware with a liquid hourly market (H100 ≈ $2–3/GPU-hr mid-2026: [IntuitionLabs](https://intuitionlabs.ai/articles/h100-rental-prices-cloud-comparison), [getdeploying](https://getdeploying.com/gpus/nvidia-h100), [Thunder Compute](https://www.thundercompute.com/blog/nvidia-h100-pricing), [CloudZero](https://www.cloudzero.com/blog/h100-gpu-cost/); spot ≈$0.34/hr: [Spheron](https://www.spheron.network/blog/gpu-cloud-pricing-comparison-2026/)). Every TOPS-hour has a market-quoted opportunity cost — per minted coin, the production floor `P_prod` (§Q.6 ≡ §S.4.3) — and an aggregate replacement value (the flow `V_ai`, §Q.6).
3. **v3 was Bitcoin-like, not v4-like:** ~half SHA-256, ~half integer-ALU emulation — neither externally bought — netting 0.32 TOPS ≈ a de minimis `V_ai`. The fork **converts the security spend from sterile to productive**: from work with no external reference price to work whose reference price is published hourly.

### Q.14.2 The PoUW distinction — where the value lives (do not overclaim)

The useful-work literature ([Primecoin, King 2013](https://primecoin.io/bin/primecoin-paper.pdf); [Ball–Rosen–Sabin–Vasudevan, ePrint 2017/203](https://eprint.iacr.org/2017/203); [Ofelimos, ePrint 2021/1379](https://eprint.iacr.org/2021/1379); [Komargodski–Shen–Weinstein, arXiv:2504.09971](https://arxiv.org/abs/2504.09971)) distinguishes work whose *outputs* are wanted from work that merely resembles it. BTX must be exact:

- **v4's work *products* are NOT externally useful.** Operands `A, B` are seed-derived pseudorandom (§A.2); the product `C` answers no customer's question and is discarded after the sketch commitment. The v3 spec already draws this line and it carries forward: v1/v3 is "AI-native PoW," and calling it "Proof-of-Useful-Work" "would misrepresent the system's actual properties" (`doc/btx-matmul-pow-spec.md` §3.2). A PoUW claim would require arbitrary external input matrices + a data-availability layer, which v4 deliberately does not ship.
- **v4's work *inputs* ARE dual-use and market-priced.** What changes is the market character of the inputs: the hardware, energy, and skill that produce a v4 block are the identical bundle an AI cloud sells, redeployable to paying AI workloads in minutes. This gives the *security spend itself* an external valuation (the flow `V_ai = TOPS_net × $17/dTOPS-yr`, $/yr), an opportunity-cost price floor (`P_prod`, §S.4.3), and a recruitment pool (every idle accelerator on earth) that sterile-hash coins lack.

Shippable formulation: **v4 is AI-native proof-of-work on dual-use, market-priced hardware — not proof-of-useful-work.** The matrices are lottery tickets; the machine that prints them is a working AI accelerator, and the network's aggregate throughput is real, measurable, market-denominated AI compute capacity.

### Q.14.3 What this does and does NOT imply

| Implied — claim it | Not implied — never claim it |
|---|---|
| The security budget is *productive*: it maintains a fleet whose capacity has independent market value (flow `V_ai`; per-coin floor `P_prod`), not pure burn. | That BTX is **more secure than Bitcoin**, or more secure *per dollar*. Attack cost is set by dollars of compute defending the chain; Bitcoin's defended budget is ~63× larger (`BTX_security_%` ≈ 1.59%). |
| Miner economics anchor to an external market: rational sell floor = AI-rental opportunity cost (§S.4.3), replacing v3's zero-cost dumping. | That productive work makes attacks *harder per dollar*. It does not; commodity **rentability cuts both ways** — the same liquid market that recruits honest capacity lets an attacker rent without capital lock-in (bounded/difficulty-damped per §S.4.4/§N.1, but real; Bitcoin's ASIC lock-in is a security property v4 trades away). |
| Mining gains a same-dimension supply-side **cost floor** independent of Bitcoin: `P_prod` [$/BTX] (§Q.6 ≡ §S.4.3), which brackets the market price from below (`P_raw`/`P_btc` is the demand-side comparable above it — §Q.20). `P_prod` is a cost, not a valuation. | That the network "does AI work for customers," "trains models," or produces externally consumed results. It does not (Q.14.2). |
| v4 fixes v3's pathology: ~97–99% of the fleet's arithmetic capability idle or on sterile cycles, now redirected to the market-priced operation. | That Bitcoin is "doing it wrong." Sterile burn is a coherent choice (no dual-use exit, maximal lock-in); v4 makes a different, explicitly stated trade (§N.1). |

---

### Q.15 Honest-claims guidance (do / don't)

> **Status:** informative but **binding on project communications** (btxprice.com, website, mining guides, social). Rule of thumb: every compute claim must be tagged **[security]** (`S`, continuous) or **[useful compute]** (`U`, steps up ~30×). Mixed-tag claims are the lies.

### Q.15.1 Claims you CAN make

| # | Approved claim | Tag | Basis |
|---|---|---|---|
| 1 | "v4 unlocks ~30× more useful matrix compute per unit hardware (12–120×), ~10²–10³× network-wide with the datacenter shift." | useful compute | §Q.4, §Q.7 |
| 2 | "Compute is now market-priced AI compute: `TOPS_net = getnetworkhashps × 1.7717×10¹⁰`, backing `TOPS_net × $17/dTOPS-yr` per year (a flow) and a production-cost floor of `N_eq·r/800` $/BTX (a price)." | useful compute | §Q.6 |
| 3 | "Security is continuous across the fork; `BTX_security_%` preserved by `w_v4 = w_v3 × Ω` (Ω = Num/Den = Z > 1, §Q.9.2)." | security | §Q.5, §I.4 |
| 4 | "Nonce rate drops ~10⁵–10⁶× because each v4 nonce embodies ~2×10⁶× more work — a unit change, like re-quoting meters as kilometers." | metric semantics | §Q.2–§Q.3 |
| 5 | "Unlike SHA-256, whose work has no external market, v4's per-nonce operation (dense INT8 GEMM) is the commodity AI clouds rent by the hour." | useful compute | §Q.14.1 |
| 6 | "Mining now carries a **real, AI-market-indexed marginal cost** in place of v3's near-zero junk-hardware cost; the **zero-cost engine** behind price-insensitive mine-and-dump is removed (dumping is no longer *free*). This is a **soft cost anchor that tracks price both ways, not a hard price support**, and it does not by itself defeat a determined suppressor — §0.7-(4)." | economics | §S.4.3–§S.4.5 |
| 7 | "v3 surfaced only 0.32 TOPS of actual matrix arithmetic (a de minimis `V_ai`); v4 makes production ≈ installed capability." | useful compute | §Q.4, §Q.6 |
| 8 | "The security spend is now productive: it maintains a measurable, market-denominated AI-compute fleet instead of sterile hashing." | economics | §Q.14 |

### Q.15.2 Claims you CANNOT make — with the compliant replacement

| # | Forbidden claim | Why false | Say instead |
|---|---|---|---|
| 1 | "Hashrate jumped 30×." | Mixes tags: `U` rose ~30×; nonce rate *fell* ~10⁵–10⁶×; security-weighted work flat. | "Useful compute per unit hardware rose ~30×; security-weighted work (`w·M_BTX`) is unchanged." |
| 2 | "The network is 30× more secure." | `S` is continuous; the attacker gains the same efficiency. | "Security is continuous — and now grows with every accelerator that joins." |
| 3 | "BTX hashrate collapsed 99.999%." | Unit change, not decline. | Claim 4 of §Q.15.1 + the recalibrated `BTX_security_%`. |
| 4 | "BTX out-computes Bitcoin." | On security-equivalent work BTX is ~1.59% of Bitcoin; the true claim is about work *character*. | "BTX's compute is market-priced AI compute; Bitcoin's is sterile hashing. Per unit of security spend BTX's is productive — Bitcoin's total spend remains ~63× larger." |
| 5 | "BTX matrices do useful AI work / trains models / PoUW." | Operands seed-derived; products discarded; v3 §3.2 rejects the label. | "AI-native PoW: same operation, silicon, precision as production AI inference, on dual-use market-priced hardware — but the matrices are consensus-generated, not customer workloads." |
| 6 | "More secure than Bitcoin per dollar because the work is useful." | Usefulness doesn't change attack dollars; rentability mildly cuts the other way. | "Same security-per-dollar logic as any PoW; BTX's dollars buy productive capacity instead of pure burn." |
| 7 | "`P_prod`/`V_ai` is what the network earns." | Replacement-value/opportunity floor, not revenue. | "`P_prod` prices the marginal coin at AI-market compute cost; `V_ai` values the fleet's annual capacity — anchored to what the hardware *would* earn if rented, not to income." |
| 8 | "The fork added compute to the network." | No hardware changed; capacity was installed and idle. | "The fork stopped wasting compute already installed: the old solver masked it; the new one uses and measures it." |

**Operational rule for btxprice.com:** ship *both* dashboards — `BTX_security_%` (recalibrated, flat through the fork) and `TOPS_net`/`H100_eq`/`P_prod` (the step) — and never render the raw un-recalibrated nonce rate as a headline series. The flat line and the step, side by side, *are* the honest story; either alone, mislabeled, is the dishonest one.

---

### Q.16 Public explanation (fork-day copy)

> **Status:** informative; approved verbatim for btxprice.com and project channels at `nMatMulV4Height`.

> **What changed at the v4 fork — and what didn't.** At the fork, BTX changed what one "nonce" means: under v3 a nonce was a cheap SHA-256 lottery ticket that only occasionally triggered a small matrix multiplication on the GPU's general-purpose cores; under v4 every nonce *is* one full 4096×4096 INT8 matrix multiplication on tensor cores. Because each new nonce packs about a million times more work, the reported nonce rate drops sharply at the fork — that is a **change of units, not a decline**, exactly like re-quoting a distance in kilometers instead of meters — and our security metric (`BTX_security_%`) is recalibrated by the exact consensus constant so it reads **continuously through the fork**: the same hardware secures the chain the moment after as the moment before, and an attack costs just as much. What genuinely steps up is the network's **useful output**: v3's solver wasted almost all of the fleet's silicon on SHA hashing and software-emulated arithmetic, surfacing only ~0.32 TOPS of real matrix compute — a de minimis flow at AI-market rates — while the tensor cores sat idle; v4's efficient solver unlocks that latent capacity, producing roughly **30× more useful matrix compute on the very same machines** (and 100–1,000× as AI-grade hardware joins). And unlike SHA-256 hashing, which no one outside a blockchain will ever pay for, the operation BTX now runs — dense INT8 matrix multiplication — is the exact commodity AI clouds rent by the hour, so the network's compute is measured in TOPS and valued at published AI-market prices. To be precise about what we are *not* claiming: the matrices themselves are generated by the protocol, not by AI customers — BTX is AI-native proof-of-work on market-priced hardware, not "useful work" for hire — and the fork does not make the chain more secure than it was; it makes the security spend *productive* instead of sterile, and finally measures it in units the real world prices.

---

### Q.17 Two valuation anchors: Bitcoin-security-model price and AI-production-cost price

#### Q.17.0 Dimensions first: stock vs flow (normative for every formula and chart in §Q.17–§Q.20)

| Object | Units | Kind | Role | Market it reads |
|---|---|---|---|---|
| `P_prod` (§Q.6/§Q.19, rental basis) | $/BTX | **stock** | **supply-side cost FLOOR** — marginal cost to mine one coin ≡ §S.4.3 | AI-compute rental market |
| `P_prod_inf` (§Q.19, inference basis) | $/BTX | **stock** | cost-floor cross-check of `P_prod` | AI-inference token market |
| *(observed market price)* | $/BTX | **stock** | what a coin actually trades at — sits **between** `P_prod` and `P_btc` | exchange order book |
| `P_btc` (§Q.18) | $/BTX | **stock** | **demand-side relative-comparable** — aspirational, NOT a floor | Bitcoin monetary market (BTC spot × security ratio) |
| `V_ai` (§Q.6 footnote) | $/yr (÷S → $/BTX·yr) | **FLOW** | annual AI-capacity value backing the network | AI-compute rental market |

**Rule: only compare — or plot on one axis — objects of the same dimension, and even then do not `max()` them (they answer different questions, §Q.20).** `P_btc`, `P_prod`, and `P_prod_inf` are same-dimension [$/BTX] but are **not competing price models**: `P_prod` is a supply-side *cost floor* (what it costs to mine a coin), `P_btc` is a demand-side *relative-comparable valuation* (what a coin would fetch if priced like Bitcoin per unit security — aspirational, **explicitly not a floor**), and the observed market price sits between them (§Q.20's three-object bracket). `V_ai` is an annual flow; comparing or `max()`-ing it against any price is a stock-vs-flow dimensional error. *Correction record:* an earlier draft of §Q.17–§Q.20 defined "`P_ai`/`P_inf`" as `TOPS_net × $/TOPS-yr / S` — units **$/BTX·yr, a flow** — then compared and `max()`-ed it with `P_btc` [$/BTX] and derived a "crossover at ~1.42×10⁵ H100-eq." That comparison was dimensionally invalid (and mixed the compute market into Bitcoin's monetary market); the crossover was an artifact of it and is **retracted** (§Q.20 gives the correct constant-ratio result). The flow objects are superseded by the price `P_prod`/`P_prod_inf`; the flow survives only as `V_ai`, explicitly labeled.

The v4 fork makes BTX's proof-of-work *the same commodity the AI-inference market prices*: dense s8×s8→s32 GEMM (§A.5, §E.3). That gives two same-dimension ($/BTX) anchors that **bracket** the observed market price from opposite sides — a supply-side cost floor and a demand-side comparable — not two rival "price models":

| Anchor | Side | Question it answers | External market | Fork behavior |
|---|---|---|---|---|
| **`P_prod` / `P_prod_inf`** (§Q.6/§Q.19) | supply floor | "What does it *cost*, at AI-market rates, to produce one newly minted BTX?" | GPU rental $/hr (`P_prod`); inference $/token (`P_prod_inf`) | ≈ 0 pre-fork; **meaningful only under v4** |
| **`P_btc`** (§Q.18) | demand comparable | "What would a coin be *worth* if valued like Bitcoin per unit security (and what does attacking it cost)?" | Bitcoin spot + hashrate | **Continuous** via the §I.4/§Q.9.2 `w` recalibration |

> **Honesty constraint (normative for btxprice presentation).** The v4 PoW matrices are seed-derived pseudorandom (§B); the network produces **no sellable inference and no externally useful work products** (§Q.14.2). Both bases of the production floor (`P_prod`, `P_prod_inf`) and the flow `V_ai` price the **capacity / opportunity cost** of the INT8 hardware the difficulty proves is attached to the chain — what that silicon *could* earn — never revenue the network earns. Dashboard copy must say "cost-of-production floor," "opportunity-cost floor," or "hardware-equivalent capacity value" — never "revenue." All are downstream of one consensus observable, `getnetworkhashps(6720)`, so btxprice needs no new chain data — only new constants (§Q.20).

### Q.18 Bitcoin-model price `P_btc` (recalibrated security anchor)

```
P_btc = P_BTC · SEH / H_BTC ,   SEH = w_v4 · M_BTX_v4(1w)
```

**Continuity across the fork.** With `w_v4 = w_v3·Ω` (Ω = w_v4/w_v3 = target rescale = M(t_f⁻)/M(t_f⁺), §Q.9.2) and reported nonce rate rescaling by `1/Ω`, the boundary product is preserved: `w_v4·M(t_f⁺) = (w_v3·Ω)·(M(t_f⁻)/Ω) = w_v3·M(t_f⁻)`. So `SEH`, `BTX_security_%`, and `P_btc` are continuous by construction — both constants read from chainparams at tag time. `P_btc` is a demand-side **security-comparable** (aspirational — **explicitly not a floor**, §Q.20): what a coin *would* fetch if the hardware mining BTX were valued like ≈1.59 % of Bitcoin's hashpower at Bitcoin's own valuation of security.

**Worked value (July 2026 inputs):**
- `w_v3·M_BTX` = 4.525×10¹⁰ × 3.157×10⁸ = **1.4285×10¹⁹ H/s-eq** (§Q.1).
- `P_BTC` ≈ **$62,550** (July 14 2026, [Fortune](https://fortune.com/article/price-of-bitcoin-07-14-2026/)).
- `H_BTC` ≈ **9.08×10²⁰ H/s** (908 EH/s July 11; range 866–1,010 EH/s: [CoinWarz](https://www.coinwarz.com/bitcoin-hashrate), [news.bitcoin.com](https://news.bitcoin.com/bitcoins-14th-difficulty-reset-slashes-mining-pressure-by-6-7-trillion/)).

```
SEH/H_BTC = 1.4285×10¹⁹ / 9.08×10²⁰ = 0.01573 (1.573%)
P_btc     = P_BTC × SEH/H_BTC     (computed on live inputs; no fixed value)
  (band computed over the July H_BTC range 866–1,010 EH/s and the site's 1.5897% convention)
```

**`P_btc = P_BTC · SEH/H_BTC`** — the continuity anchor, the only line guaranteed smooth through `nMatMulV4Height`, denominated in Bitcoin's security market (computed live; no fixed value).

**Inherited-calibration caveat (honesty; model agent finding).** `P_btc`'s *absolute level* rests entirely on btxprice's inherited v3 constant `w_v3` — a calibration equating the small v3 fleet to 1.59 % of Bitcoin's hashpower, whose capital-equivalence basis is not independently verifiable — and it grows ∝ `N_eq`, which *overstates* attack-cost growth as `$/TOPS`-cheap capacity joins. Keep `P_btc` labeled relative-comparable/aspirational, and carry a **price-free attack-cost cross-check** that needs no `w` at all: `C_51_rent = N_eq·r` [$/hr to rent a matching fleet], `C_51_buy = N_eq·capex_H100` [$ to buy one] — both [MODEL], BTX-price-free (fork fleet ≈ $0.02/hr rent-equiv; 100 H100-eq = $250/hr rent / ≈$3M buy). Display of `C_51` is a comms choice, but it should exist internally so `P_btc`'s eye-watering absolute level is never mistaken for a hard attack-cost claim.

### Q.19 Inference-basis production-cost price `P_prod_inf` (reference-benchmark-anchored)

`P_prod` (§Q.6 ≡ §S.4.3) prices the marginal newly minted BTX at GPU **rental** rates. `P_prod_inf` prices the same compute-hour at what it would gross *sold as inference output* — tokens — divided by the same mint rate. Both are prices, $/BTX (§Q.17.0):

```
P_prod_inf ($/BTX) = (inference $ / hr) / (BTX minted / hr) = TOPS_net × r_tok × 3600 × p_tok × u / 800
```

`TOPS_net = getnetworkhashps(6720) × W_nonce` (delivered, §Q.6); `r_tok` = output tok/s per delivered-TOPS; `p_tok` = market $/output-token; `u` = serving/utilization factor; **800 BTX/hr** = mint rate (20 BTX × 40 blocks/hr, §S.4.3). Note what does *not* appear: circulating supply `S`. A production cost divides the compute **flow** ($/hr) by the mint **flow** (BTX/hr); dividing an annual dollar flow by the coin *stock* `S` — as an earlier draft did — yields $/BTX·yr, a flow masquerading as a price (§Q.17.0).

**(a) Reference throughputs (H100, 1 H100 = 1,286 delivered INT8 TOPS at ε=0.65).** [NVIDIA TensorRT-LLM perf](https://nvidia.github.io/TensorRT-LLM/performance/perf-overview.html) (FP8, per-GPU):

| Reference | ISL/OSL | tok/s/H100 | `r_tok` = ÷1,286 |
|---|---|---:|---:|
| Llama-3.1-8B TP1 | 128/128 (peak) | 26,401 | 20.5 |
| Llama-3.1-8B TP1 | **1000/1000** | 14,992 | **11.66** |
| Llama-3.3-70B TP2 | 128/128 (peak) | 3,046 | 2.37 |
| Llama-3.3-70B TP2 | **1000/1000** | 2,090 | **1.63** |

Cross-check: MLPerf Inference v4.1 Llama-2-70B offline = 3,066 tok/s/H100 ([NVIDIA](https://developer.nvidia.com/blog/nvidia-blackwell-platform-sets-new-llm-inference-records-in-mlperf-inference-v4-1/), [MLCommons](https://mlcommons.org/2024/03/mlperf-llama2-70b/)) — within 0.7% of the 70B peak. ✓ Use the realistic 1000/1000 rows as central.

**(b) Market $/1M output tokens (mid-2026):**

| Provider | 8B (out) | 70B (out) |
|---|---:|---:|
| DeepInfra | $0.08 | $0.40 |
| Groq | $0.08 | $0.79 |
| Together.ai | $0.18 | $0.88 |
| Fireworks | $0.20 | $0.90 |

Sources: [AI Pricing Guru](https://www.aipricing.guru/meta-llama-pricing/), [pricepertoken DeepInfra/Together](https://pricepertoken.com/endpoints/compare/deepinfra-vs-together), [Groq](https://groq.com/pricing), [Together](https://www.together.ai/pricing), [pricepertoken Fireworks/Together](https://pricepertoken.com/endpoints/compare/fireworks-vs-together). Central `p_tok`: **8B $0.10/Mtok, 70B $0.60/Mtok** (output only — input processing ignored, conservative).

**(c) Chained arithmetic (method, illustrative fleet size 100 H100-eq ⇔ TOPS_net = 128,600 dTOPS, §Q.6; mint = 800 BTX/hr) — every dollar figure below is `P_prod_inf` or an intermediate of it, computed live from the formula in this section; no fixed value is normative:**
- *8B central:* `TOPS_net × r_tok(8B) × 3600 × p_tok(8B) × u / 800` → `P_prod_inf` (computed live).
- *70B central:* `TOPS_net × r_tok(70B) × 3600 × p_tok(70B) × u / 800` → `P_prod_inf` (computed live).
- *Rental basis, same fleet (§Q.6):* `P_prod = N_eq × r / 800` (computed live).
- *Larger fleet (linear in N_eq):* both bases scale linearly with `N_eq`; no fixed value at any particular fleet size.

**Sensitivity (method: each cell = `N_eq` × (tok/s/H100 × 3,600 × p_tok) × u / 800 — a `P_prod_inf` value computed on live inputs; no fixed value). Column/row structure retained; cells are the computed `P_prod_inf($/BTX)` output, not baked-in numbers:**

| Reference × $/Mtok (INPUT) | u=0.25 | u=0.5 | u=1.0 |
|---|---:|---:|---:|
| 8B @ $0.08 | computed | computed | computed |
| 8B @ $0.10 (central) | computed | computed | computed |
| 8B @ $0.18 | computed | computed | computed |
| 70B @ $0.40 | computed | computed | computed |
| 70B @ $0.60 (central) | computed | computed | computed |
| 70B @ $0.90 | computed | computed | computed |
| *rental `P_prod` ref (r as polled, u-independent)* | *computed* | *computed* | *computed* |

(Each cell is `N_eq × tok/s/H100 × 3,600 × p_tok × u / 800`, evaluated at whatever `N_eq`, `p_tok`, and `u` the dashboard is showing — no cell value is normative or fixed.)

**(d) Convergence cross-check — the place where "both AI methods agree" (against each other, never against `P_btc`).** Three independent AI-market bases price the marginal coin within ±10% of each other at central assumptions when evaluated on the same live inputs: the rental basis (`P_prod`), the 8B-inference basis, and the 70B-inference basis of `P_prod_inf` (computed live; no fixed values — full sensitivity spans roughly an order of magnitude across the `u` band). Per H100-hr at u=1 the token chains gross a multiple of the rental rate (token prices embed the serving stack, margin, and sub-peak recovery); the realistic u≈0.5 haircut brings them back close to the rental line. **`P_prod` (rental) is the harder, conservative floor** (a miner can actually redeploy at it with no serving stack); **`P_prod_inf` is the corroborating cross-check / upper edge of the floor band.** Both are capacity-cost valuations, not revenue — and both live in $/BTX, so §Q.20 may lawfully put them on the same chart as `P_btc`.

### Q.20 The three-object bracket (no composite) + btxprice handoff

`P_prod`, the observed market price, and `P_btc` are all prices in $/BTX (§Q.17.0), so one chart may carry all three. They are **not competing valuations** — they bracket the market price from the supply side and the demand side:

| Object ($/BTX) | Side | Pre-fork | Post-fork | Tells the viewer |
|---|---|---|---|---|
| `P_prod` — cost-of-production **floor** (compute market, §Q.6 ≡ §S.4.3) | supply (lower) | ≈ **$0** (v3 = 0.32 TOPS junk-fleet compute → near-zero cost, §S.4.1) | `P_prod = N_eq·r/800` per newly-minted coin (computed on live inputs; no fixed value), ∝ `N_eq`; inference cross-check via `P_prod_inf` (§Q.19) | **soft** lower anchor — the marginal miner's opportunity cost; tracks price both ways, *not* a hard support (§S.4.3, §0.7-(4)) |
| *observed market price* | — | trades far above the ~$0 floor, far below `P_btc` | rises as the floor rises | where supply meets demand today — **an output, and possibly a suppressed one** (§S.4, §0.7-(4)) |
| `P_btc` — security-**comparable** (Bitcoin monetary market, §Q.18) | demand (upper) | `P_btc = P_BTC·SEH/H_BTC` (computed on live inputs; no fixed value) | continuous via `w_v4`, then ∝ `N_eq` | aspirational — what a coin *would* fetch if valued like Bitcoin per unit security; **not a floor** |

**No `max()` composite, and `P_prod` is a cost, not a valuation.** The former headline `max(P_btc, P_ai)` is removed on two grounds: (1) it `max()`-ed a $/BTX price against a $/BTX·yr flow (dimensionally invalid, §Q.17.0); (2) even between the two *prices*, `max()` is wrong — a supply-side cost floor and a demand-side comparable are not interchangeable "floors" to take the larger of. Present the **bracket**: `P_prod` ≤ market price ≤ `P_btc`. The spread `P_btc / P_prod` is the **disequilibrium the market is pricing** — the distance between what a coin costs to mine and what it would be worth at Bitcoin-grade security valuation.

> **Manipulation caveat (§0.7-(4)) — do not treat the observed price as ground truth.** The *observed market price* in this bracket is an **output the market discovers, and it can be adversarially suppressed** (mine-and-dump, wash trading, manufactured "fake-supply" selling, §S.4). When it is, it sits near the low `P_prod` end **not because that is fair value but because manufactured supply is holding it there** — so a wide `P_btc/P_prod` spread is *partly* manipulation, not purely honest disequilibrium, and the low-end `P_prod` read-out (small `N_eq`, consumer-marginal) is the **suppressed/attack state of §Q.21, not the resting equilibrium**. Two consequences: (i) presentation must label the market-price line as an observed, possibly-suppressed output — never as the network's "true" value; (ii) v4 compresses the spread **from below and structurally** — by raising the marginal *cost* of production so zero-cost dumping dies — and **never** by moving a consensus parameter toward the suppressed print (that would hand the manipulator the difficulty/floor as a second lever). The bracket is a *range the market resolves over time*, not a target the protocol chases.

**Why the pre-fork floor is near-zero — this IS the dumping diagnosis (a feature of the analysis, not a bug).** Under v3, `P_prod` ≈ $0 because a high emission (800 BTX/hr) is produced by cheap, paid-off junk hardware at ~electricity-only cost (§S.4.1): mining a coin costs almost nothing, so **dumping at any price is profitable**, and the market price sits far below the `P_btc` security-comparable (computed live; no fixed value). **v4's entire economic thesis (§S.4.3/§S.4.5) is to RAISE this floor:** real INT8 hardware carries a real AI-rental opportunity cost, lifting `P_prod` from ~$0 toward a meaningful $/BTX, narrowing the `P_prod → P_btc` gap and ending cheap dumping. **The floor rising over time is the fix**, not a contradiction; the wide `P_btc / P_prod` spread is precisely the disequilibrium v4 is designed to compress from below.

**N_eq is set by mining profitability — both anchors scale ∝ N_eq, so the ratio is ~constant and there is no crossover.** Miners enter until `P_prod ≈ market price` (below it they redeploy to AI rental, §S.4.3; ASERT difficulty clears the market) — the per-GPU mechanism behind this equilibrium, *which* GPU class enters at *which* `P_BTX` and why the marginal class's break-even pins the floor, is §Q.21.4 — so `N_eq` is endogenous, not a free axis to slide to a "crossover." And *both* anchors scale linearly with network size: `P_btc = P_BTC·w_v4·R_nonce/H_BTC` with `R_nonce ∝ N_eq` (7.26×10⁴ nonces/s per H100-eq, §Q.3), and `P_prod = N_eq·r/800`. `N_eq` cancels from the ratio:

```
P_btc / P_prod = [P_BTC · w_v4 · ν / H_BTC] / [r / 800]        ν = 7.26×10⁴ nonce/s per H100-eq
```

A fleet ×k multiplies **both** anchors by k (growth to a larger `N_eq` lifts `P_prod` and `P_btc` by the identical factor, both computed live — no fixed values), so the ratio is invariant in `N_eq`, moving only with `P_BTC/(H_BTC·r)` and the tag-time Ω. *The earlier "crossover at N\* ≈ 1.42×10⁵ H100-eq" is retracted:* it froze `P_btc` at a fixed level while growing a $/BTX·yr flow with `N_eq` — an artifact of the stock-vs-flow error compounded by the frozen numerator. Correct statement: the floor and the comparable rise together and never cross; the spread narrows only as `P_prod`'s *inputs* (r, hardware quality) rise relative to Bitcoin's, i.e. as v4's floor-raising thesis plays out.

**The quantified pivot (unchanged in substance):** pre-fork the production floor is ≈$0 (the dumping regime); post-fork `P_prod` is a **real cost floor that did not exist under v3** — the identical `getnetworkhashps` observable that implied a ~$0 marginal cost under v3 (junk-fleet floor, §S.4.1) implies a real, computed-live `P_prod = N_eq·r/800` per newly-minted coin under v4, with the annual capacity flow `V_ai` going from a de minimis figure to `TOPS_net·(rental $/dTOPS-yr)` (computed live; no fixed value — flow, footnote — §Q.6).

**btxprice implementation block:**

```
# Inputs (polled)
P_BTC   : BTC spot                    — exchange/aggregator API     (10 min)
H_BTC   : BTC 1w hashrate             — mempool.space/coinwarz      (10 min)
R_nonce : BTX getnetworkhashps(6720)  — BTX RPC (split window at nMatMulV4Height, §Q.9.3)
S       : circulating supply          — BTX RPC (display/market-cap only; NO price anchor divides
          by S — the production floor divides by the MINT RATE, a flow, not the coin stock)

# Constants
Ω        = Num/Den from chainparams (§I.4) ;  w_v4 = w_v3 × Ω        # Ω>1, ≈3e5–1e6 (§Q.9.2)
W_nonce  = 1.7717e10 INT8 ops (§E.3/§M.4)
TOPS_net = R_nonce × W_nonce / 1e12  (dTOPS) ;  N_eq = H100_eq = TOPS_net/1286
MINT     = 800 BTX/hr  (20 BTX × 40 blocks/hr @ 90 s; §S.4.3)
r_rental = $2.50 /H100-eq-hr (spot $0.34 – avg $3.61; refresh quarterly)
c_rental = $17.0 /dTOPS·yr  (= r_rental × 8,760 / 1,286; flow constant, V_ai only)
r_tok_8B = 11.66 tok/s/dTOPS (peak 20.5)   # TRT-LLM Llama-3.1-8B FP8 1000/1000
r_tok_70B= 1.63  tok/s/dTOPS (peak 2.37)   # TRT-LLM Llama-3.3-70B FP8 TP2; MLPerf ✓
p_tok_8B = $0.10e-6/tok (0.08–0.18) ;  p_tok_70B = $0.60e-6/tok (0.40–0.90)
u        = 0.5 (band 0.25–1.0)

# Formulas — every price anchor is $/BTX (a stock); no price is ever an annual flow ÷ S
P_btc      = P_BTC × w_v4 × R_nonce_1w / H_BTC             # $/BTX — security-comparable valuation
P_prod     = N_eq × r_rental / MINT                        # $/BTX — cost-of-production floor ≡ §S.4.3
P_prod_inf = TOPS_net × r_tok × 3600 × p_tok × u / MINT    # $/BTX — inference-basis cross-check

# Per-GPU switchover (§Q.21) — T_g = delivered dTOPS (0.65 × dense, §P.1); R_g = polled rental $/hr
#   (H100 2.50 · H200 3.95 · B200 5.89 · GB200 ~12 · A100 0.73 · 5090 0.55 · 4090 0.35 ·
#    5080 0.20 · 3090 0.15 · Apple —; refresh quarterly with timestamps, §Q.21.2 sources)
BTXhr_g    = 800 × T_g / TOPS_net                          # BTX/hr GPU g mines (share basis, §O.2)
P_star_g   = R_g / BTXhr_g                                 # $/BTX — g's mine-vs-rent break-even price
R_star_g   = BTXhr_g × P_spot                              # $/hr  — rent below this ⇒ mine (per GPU)
             # identities: P_star(H100) ≡ P_prod ; operative floor = P_star(marginal active class)
present    : THREE-OBJECT BRACKET on one $/BTX chart, never max()-ed:
             P_prod (supply-side cost floor) <= observed market price <= P_btc (demand-side
             relative-comparable, aspirational, NOT a floor). P_prod is a COST, not a valuation.
             shade spread = disequilibrium the market prices ; ratio P_btc/P_prod ~const in N_eq
V_ai       = TOPS_net × c_rental                           # $/yr FLOW — footnote only; annual
                                                           # AI-capacity value backing the network
# Refresh: r_tok quarterly (TRT-LLM/MLPerf) ; p_tok monthly (provider pages) ; r_rental quarterly.
# GUARDRAIL 1 — capacity, not revenue (ship with UI): P_prod/P_prod_inf/V_ai value the CAPACITY /
# OPPORTUNITY COST of the hardware the difficulty proves exists — matrices are pseudorandom, the
# network sells no inference and earns no AI revenue. Cost floors / references, not income claims,
# not a price promise.
# GUARDRAIL 2 — dimensions: never compare, plot on one axis, or max() a $/BTX PRICE (P_btc, P_prod,
# P_prod_inf) with a $/yr or $/BTX·yr FLOW (V_ai). Prices go on the price chart; flows stay in the
# footnote. There is no max() headline.
```

**Sources:** [Fortune BTC 07-14-2026](https://fortune.com/article/price-of-bitcoin-07-14-2026/) · [CoinWarz hashrate](https://www.coinwarz.com/bitcoin-hashrate) · [news.bitcoin.com difficulty reset](https://news.bitcoin.com/bitcoins-14th-difficulty-reset-slashes-mining-pressure-by-6-7-trillion/) · [TensorRT-LLM perf](https://nvidia.github.io/TensorRT-LLM/performance/perf-overview.html) · [NVIDIA MLPerf v4.1](https://developer.nvidia.com/blog/nvidia-blackwell-platform-sets-new-llm-inference-records-in-mlperf-inference-v4-1/) · [MLCommons Llama-2-70B](https://mlcommons.org/2024/03/mlperf-llama2-70b/) · [H100 datasheet](https://resources.nvidia.com/en-us-gpu/h100-datasheet-24306) · [AI Pricing Guru](https://www.aipricing.guru/meta-llama-pricing/) · [pricepertoken DeepInfra/Together](https://pricepertoken.com/endpoints/compare/deepinfra-vs-together) · [pricepertoken Fireworks/Together](https://pricepertoken.com/endpoints/compare/fireworks-vs-together) · [Groq](https://groq.com/pricing) · [Together](https://www.together.ai/pricing) · [IntuitionLabs H100 rental](https://intuitionlabs.ai/articles/h100-rental-prices-cloud-comparison) · [btxprice.com/valuation-model](https://btxprice.com/valuation-model)

---

### Q.21 Mining-vs-AI-rental switchover: the per-GPU break-even metric

> **Status:** informative; the per-GPU microfoundation of the §Q.6/§S.4.3 production floor and the §Q.20 bracket. Cross-refs: hardware table §P.1 (dense INT8 TOPS govern), efficiency ε §Q.3/§Q.6, emission 800 BTX/hr §S.4.3, ASERT §I.4. Everything here is downstream of one chain observable (`getnetworkhashps` → `TOPS_net`) plus polled AI-rental rates. Dimensional discipline per §Q.17.0 throughout: mining revenue and rental are **$/hr flows**; the break-even *price* `P*_g` is a **$/BTX stock** obtained by dividing a $/hr flow by a BTX/hr flow — never by the coin stock `S`.

#### Q.21.1 The model — one decision, per GPU

A rational owner of GPU `g` faces one hourly choice: point it at BTX, or rent it to the AI market.

```
mine BTX  ⟺  (BTX/hr)_g × P_BTX  ≥  R_g            [$/hr vs $/hr]

(BTX/hr)_g = 800 × T_g / TOPS_net                    [BTX/hr]   (proportional-reward share, §O.2)
P*_g  = R_g / (BTX/hr)_g = R_g × TOPS_net/(800·T_g)  [$/BTX]    break-even BTX price
R*_g  = (BTX/hr)_g × P_BTX                           [$/hr]     break-even rental rate
```

`T_g` = GPU `g`'s **delivered** INT8 throughput (dense §P.1 × ε≈0.65, §Q.3); `TOPS_net` = network delivered throughput (§Q.6); `800 BTX/hr` = 20 BTX × 40 blocks/hr (§S.4.3); `R_g` = the AI-rental rate `g` can actually fetch, $/hr. Above `P*_g` the GPU mines; below it, it rents. Equivalently: **if the AI market won't pay more than `R*_g` for your card, mine BTX with it** — the owner's "X ¢/hr" threshold, but per card, not one number. (Nonce-rate form, for pool telemetry: `g` clears `7.26×10⁴ × T_g^dense/1,979` nonces/s, §M.4/§Q.3 sketch basis — BTX/hr is the same share either way.)

**Electricity.** Both activities run the card at load, and in both the owner pays for power (marketplace hosts pay their own electricity), so the power cost `c_g = TDP_g × p_elec` largely **cancels** from the mine-vs-rent comparison; it survives as the **absolute-viability floor** `P⁰_g = c_g/(BTX/hr)_g` — the only binding threshold where no rental market exists (Apple).

**Unification with §Q.6.** `P_prod = N_eq·r/800` is this model evaluated at the H100: `P*_H100 = r × TOPS_net/(800 × 1,286) = (TOPS_net/1,286)·r/800 ≡ N_eq·r/800 = P_prod`. The aggregate floor is the **marginal miner's** per-GPU break-even; §Q.21.4 gives the equilibrium.

#### Q.21.2 The per-GPU switchover table

**Reference scenario (state both knobs):** network `TOPS_net = 128,600 dTOPS` (= 100 H100-eq, the §Q.6 illustrative launch network) and an illustrative reference price `P_BTX` (symbolic — not a fixed value; the mine-rev and verdict columns are re-evaluated live at whatever `P_BTX` the dashboard shows). Power at **$0.08/kWh** (US industrial average ≈8.5–9¢/kWh, 2026: [EIA](https://www.eia.gov/electricity/monthly/epm_table_grapher.php?t=epmt_5_6_a); sensitivity band $0.05–0.10). Rental rates are mid-2026 on-demand centrals; sources below the table.

| GPU | dense TOPS (§P.1) | delivered T_g (×0.65) | BTX/hr | mine rev $/hr (= `(BTX/hr)_g·P_BTX`) | AI-rental R_g $/hr | rental $/POPS·hr | TDP → power $/hr | net mine $/hr | **P\*_g = R_g·TOPS_net/(800·T_g)** | verdict (price-dependent) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| GB200 (per GPU) | 5,000 | 3,250 | 20.22 | computed | ~$12 (early) | $3.69 | ~1,200 W → $0.096 | computed | computed | computed live |
| H200 | 1,979 | 1,286 | 8.00 | computed | $3.95 | $3.07 | 700 W → $0.056 | computed | computed | computed live |
| B200 | 4,500 | 2,925 | 18.20 | computed | $5.89 | $2.01 | 1,000 W → $0.080 | computed | computed | computed live |
| H100 SXM | 1,979 | 1,286 | 8.00 | computed | $2.50 | $1.94 | 700 W → $0.056 | computed | computed (≡ P_prod) | computed live |
| A100 80GB | 624 | 406 | 2.52 | computed | $0.73 | $1.80 | 400 W → $0.032 | computed | computed | computed live |
| RTX 5090 | 838 | 545 | 3.39 | computed | $0.55 | $1.01 | 575 W → $0.046 | computed | computed | computed live |
| RTX 4090 | 660.6 | 429 | 2.67 | computed | $0.35 | $0.82 | 450 W → $0.036 | computed | computed | computed live |
| RTX 3090 | 284.7 | 185 | 1.15 | computed | $0.15 | $0.81 | 350 W → $0.028 | computed | computed | computed live |
| RTX 3090 Ti | 320 | 208 | 1.29 | computed | ~$0.15 (thin) | ~$0.72 | 450 W → $0.036 | computed | computed | computed live |
| RTX 5080 | 450.2 | 293 | 1.82 | computed | $0.20 | $0.68 | 360 W → $0.029 | computed | computed | computed live |
| Apple M5 Max | ~130 | ~84.5 | 0.53 | computed | ≈ none (no market) | ≈ $0 | ~40 W (est.) → $0.003 | computed | computed (P⁰, power-only) | computed live |
| Apple M5 | ~30 | ~19.5 | 0.12 | computed | ≈ none | ≈ $0 | ~20 W (est.) → $0.002 | computed | computed (P⁰) | computed live |

Worked rows (method; all others identical in form — every dollar output below is computed live from the formulas of §Q.21.1, not a fixed value):

- **H100:** `T = 0.65×1,979 = 1,286 dTOPS` → `BTX/hr = 800×1,286/128,600 = 8.00` → mine revenue `= 8.00 × P_BTX`, compared against rental `$2.50/hr` → verdict computed live. `P* = R_g/(BTX/hr)_g = $2.50/8.00`, which is exactly the §Q.6 `P_prod` at this network size ✓ (computed live; no fixed value). `R* = 8.00×P_BTX`: an H100's mining revenue matches its $2.50 rental exactly when `P_BTX = P*` (computed live).
- **RTX 5090:** `T = 0.65×838 = 544.7` → `BTX/hr = 800×544.7/128,600 = 3.39` → mine revenue `= 3.39 × P_BTX`, compared against rental `$0.55/hr` → verdict computed live. `P* = $0.55/3.39` (computed live); `R* = 3.39 × P_BTX` — *if your 5090 can't fetch more than `R*` on the marketplace, mining BTX pays better at the reference price.*
- **RTX 3090:** `BTX/hr = 800×185.1/128,600 = 1.15` → mine revenue `= 1.15 × P_BTX` vs rental `$0.15/hr` → verdict computed live; `P* = $0.15/1.15` (computed live). Power check nets out the `$0.028/hr` power draw against mine revenue — thin in absolute terms, but the card's alternative is a thinner $0.15/hr rental.

**Rental-rate sources (mid-2026, on-demand):** H100 $2.50 central, $2–3 band (§Q.6: [IntuitionLabs](https://intuitionlabs.ai/articles/h100-rental-prices-cloud-comparison), [getdeploying](https://getdeploying.com/gpus/nvidia-h100), [Thunder Compute](https://www.thundercompute.com/blog/nvidia-h100-pricing)); H200 median ≈$3.95, specialists $3.72–4.39, hyperscalers to ~$10.9 ([getdeploying H200](https://getdeploying.com/gpus/nvidia-h200), [RunPod](https://www.runpod.io/pricing) $4.39, [Vast.ai](https://vast.ai/pricing/gpu/H200) $3.75); B200 $5.89 ([RunPod](https://www.runpod.io/pricing); [Lambda](https://lambda.ai/pricing) $4.99, Spheron from $3.70, AWS p6 to $14.24 — [getdeploying B200](https://getdeploying.com/gpus/nvidia-b200), [Spheron](https://www.spheron.network/blog/nvidia-b200-cloud-pricing-2026/)); GB200 ~$10.5–27/GPU-hr, early/illiquid, ~$12 central ([getdeploying GB200](https://getdeploying.com/gpus/nvidia-gb200)); A100 80GB marketplace $0.68–0.73 ([Vast.ai A100](https://vast.ai/pricing/gpu/A100-SXM4)), managed $1.39–1.49 ([RunPod](https://www.runpod.io/pricing)) — miner-relevant central $0.73; RTX 5090 marketplace from $0.40 ([Vast.ai 5090](https://vast.ai/pricing/gpu/RTX-5090)), on-demand average $0.58, full range $0.13–1.05 ([getdeploying 5090](https://getdeploying.com/gpus/nvidia-rtx-5090), [RunPod](https://www.runpod.io/pricing) secure $0.99) — central $0.55; RTX 4090 from $0.15 marketplace ([Vast.ai](https://vast.ai/pricing)) to $0.69 managed ([RunPod 4090](https://www.runpod.io/gpu-models/rtx-4090)) — central $0.35; RTX 5080 from $0.13–0.17, median ≈$0.23 ([Vast.ai 5080](https://vast.ai/pricing/gpu/RTX-5080), [gpus.io](https://gpus.io/en/gpus/rtx5080)) — central $0.20; RTX 3090 from $0.13 ([Vast.ai 3090](https://vast.ai/pricing/gpu/RTX-3090)) — central $0.15; 3090 Ti: no quoted tier, proxied at 3090 (thin market flag). **TDPs:** H100 SXM 700 W ([datasheet](https://resources.nvidia.com/en-us-gpu-resources/h100-datasheet-24306)); H200 700 W ([NVIDIA](https://www.nvidia.com/en-us/data-center/h200/)); B200 1,000 W ([B200 datasheet](https://www.primeline-solutions.com/media/categories/server/nach-gpu/nvidia-hgx-h200/nvidia-blackwell-b200-datasheet.pdf)); GB200 ~1,200 W/GPU in NVL72 (est., [NVIDIA GB200 NVL72](https://www.nvidia.com/en-us/data-center/gb200-nvl72/)); A100 SXM 400 W ([datasheet](https://www.nvidia.com/content/dam/en-zz/Solutions/Data-Center/a100/pdf/nvidia-a100-datasheet-nvidia-us-2188504-web.pdf)); RTX 5090 575 W / 5080 360 W ([NVIDIA 50-series](https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/rtx-5090/)); RTX 4090 450 W ([NVIDIA](https://www.nvidia.com/en-us/geforce/graphics-cards/40-series/rtx-4090/)); RTX 3090 350 W / 3090 Ti 450 W ([NVIDIA](https://www.nvidia.com/en-us/geforce/graphics-cards/30-series/rtx-3090-3090ti/)); Apple M5/M5 Max: no published TDP — ~20/~40 W package under sustained GPU load (est.).

**Sensitivity (exact scaling laws — no re-derivation needed):** `P*_g ∝ TOPS_net` (double the network → every break-even price doubles, computed live from `P*_g = R_g·TOPS_net/(800·T_g)`) and `P*_g ∝ R_g` (rental reprices → `P*` moves 1:1, e.g. re-evaluating at H100 spot `$0.34/hr` instead of the on-demand central). `R*_g ∝ P_BTX × T_g / TOPS_net`. Verdicts flip, the formulas don't.

#### Q.21.3 The $/TOPS insight: who *chooses* to mine ≠ who *wins* per card

Divide each rental rate by delivered throughput — the **opportunity cost per unit of mining power** ($ per delivered POPS-hour, i.e. per 10³ dTOPS·hr). Since `P*_g = (R_g/T_g) × TOPS_net/800`, **the mine-entry order is exactly the ascending $/TOPS order** — the ratio, not the card's size, decides who mines:

| rank (mines first) | GPU | rental $/POPS·hr | P\*_g = R_g·TOPS_net/(800·T_g) |
|---|---|---:|---:|
| 0 | Apple M5 / M5 Max | ≈ $0 (no rental market) | computed (power-only, P⁰) |
| 1 | RTX 5080 | $0.68 | computed |
| 2 | RTX 3090 Ti | ~$0.72 | computed |
| 3 | RTX 3090 | $0.81 | computed |
| 4 | RTX 4090 | $0.82 | computed |
| 5 | RTX 5090 | $1.01 | computed |
| 6 | A100 80GB | $1.80 | computed |
| 7 | H100 | $1.94 | computed |
| 8 | B200 | $2.01 | computed |
| 9 | H200 | $3.07 | computed |
| 10 | GB200 | $3.69 | computed |

The structure is stark: **consumer/gaming silicon sells its TOPS at $0.68–1.01/POPS·hr; datacenter silicon at $1.80–3.69 — a 1.8–5.4× premium** (the AI market pays for VRAM, NVLink, interconnect, SLAs, datacenter siting — none of which the §A matmul uses), and Apple's TOPS have essentially **no rental bid at all**. So the cards most inclined to mine BTX at any given price are precisely the **low-$/TOPS consumer cards with thin AI-rental demand** — and Apple M5s, whose opportunity cost is a rounding error above electricity.

**Reconciliation with §K/§P (honest form).** §K/§P answer *"who wins a block / most throughput per card"* — datacenter, unambiguously (H100 = 2.4× a 5090, B200 = 5.4×; §P.1). §Q.21 answers *"who chooses to mine at a given price"* — and there the ranking **inverts**, because the H100 mines 2.4× more BTX/hr than a 5090 but forgoes 4.5× the rental ($2.50 vs $0.55). This does partially tension the "datacenter always wins" narrative, and the resolution is a conditional, not a contradiction: **datacenter wins per card whenever it shows up; opportunity cost decides whether it shows up.** At low `P_BTX` the network is consumer-INT8-dominated (plus Apple) at a correspondingly low production floor; as `P_BTX` rises past the A100/H100/B200 break-even prices (computed live from `P*_g`, at 100-H100-eq scale) that capacity rationally enters, and because datacenter capacity is *deep* (§K), once it enters it dominates `TOPS_net`, per-card block share, and the floor. §K's lever is about **capability and scale**; §Q.21 prices **the switch that turns it on**. Corollary for §Q.6: the H100-denominated `P_prod` **overstates the floor whenever the marginal miner is consumer silicon** — with a 5090-class margin the effective floor is `1.01/1.94 ≈ 52%` of the H100 figure (≈42% on a 3090/4090 margin). State the operative floor as `P*` of the marginal *active* class.

> **Do not misread this as a design target (§0.7-(4)).** The "low `P_BTX` → consumer-Apple-dominated → low floor" regime is a **descriptive read-out at whatever price obtains**, and today's print may be *adversarially suppressed* (mine-and-dump / fake-supply selling, §S.4). It is **not** the network's resting equilibrium and **not** a basis for choosing any consensus parameter. The switchover *mechanism* (`P*_g = R_g·TOPS_net/(800·T_g)`, a hardware property) is price-independent and holds across the whole range; what slides with price is merely *which classes are active*. At a non-suppressed price the datacenter thresholds clear and the floor climbs toward the §K/§P ordering — so v4's design is calibrated to the hardware ordering and verification budget, never to the point on this curve the market happens to sit at (least of all a manipulated one).

#### Q.21.4 The switchover curve and the entry equilibrium

As `P_BTX` rises, GPU classes cross from rent→mine in ascending-`P*` order: Apple → 5080/3090/3090 Ti → 4090 → 5090 → A100 → H100 → B200 → H200 → GB200 *(each threshold is `P*_g = R_g·TOPS_net/(800·T_g)`, computed live; the ordering follows the §Q.21.3 ascending-$/TOPS rank; all thresholds slide ∝ `TOPS_net`)*. But entry is self-damping: each entrant raises `TOPS_net`, which raises **every** `P*` proportionally (difficulty via ASERT, §I.4). Capacity therefore fills in ascending $/TOPS order until the **marginal** class is indifferent:

```
Equilibrium:  P*_marginal = P_BTX   ⟺   R*_marginal = R_marginal
              TOPS_net* = 800 × P_BTX / (R/T)_marginal        [(R/T) in $/dTOPS·hr]
```

and at that margin the §Q.6 floor coincides with the market price — `P_prod`-generalized-to-the-marginal-class **is** the marginal-miner equilibrium of this switchover (one mechanism, two views; do not compute them separately). Cheaper-$/TOPS classes below the margin mine at an inframarginal profit; pricier classes stay in the AI market.

**Worked equilibria (method — every numeric result below is computed live from a given `P_BTX`, not a fixed value):**

- **At a low, consumer-marginal `P_BTX`** (e.g. 5090-class is the marginal entrant): `TOPS_net* = 800 × P_BTX / (R/T)_5090`, composed of **consumer silicon**. Check the datacenter stays out: `P*_H100` evaluated at that `TOPS_net*` exceeds `P_BTX` ⇒ H100 rents. 5080/3090/4090 mine at inframarginal margins; the effective floor sits at the consumer-denominated `P_BTX`, below what the H100-denominated `P_prod` formula alone would print — the gap is computed live, not fixed.
- **At a higher `P_BTX`** where the H100 class is in the money: datacenter capacity enters until `TOPS_net* = 800 × P_BTX / (R/T)_H100`. Check indifference: H100's mining revenue at that `TOPS_net*` equals its rental rate ✓ (marginal). The 5090 remains deep inframarginal; H200 keeps renting until its own threshold clears. Floor = `P_prod = N_eq·r/800` = `P_BTX` at the margin ✓ — the §Q.6/§S.4.3 identity, computed live at whatever `P_BTX` obtains.

So the equilibrium narrative in one line: **low price → small consumer-Apple network at a low floor; rising price → datacenter switchover thresholds cleared in $/TOPS order → `TOPS_net`, per-card dominance (§K), and the floor all climb together, marginal class pinned at indifference.** (Downside is symmetric and soft: price below the margin → exit → `TOPS_net` falls → all `P*` fall until the remaining marginal miner is again indifferent — the §S.4.3 **soft-anchor** dynamic (difficulty tracks price *both ways*; it is a mechanism, not a hard price support, and no price feeds back into a parameter — §0.7-(4)); in the limit the last capacity standing is the ≈zero-opportunity-cost class, Apple/idle consumer, at the electricity-only floor `P⁰`.)

**Chart (E) — "Per-GPU switchover: mine vs rent" (btxprice; extends the §Q.11 set).** Log-log. **X-axis `P_BTX` [$/BTX]; Y-axis $/hr** — one dimension per axis, never mixed (§Q.17.0). Per GPU class, two curves: a **horizontal line at its AI-rental rate `R_g`** and a **slope-1 mining-revenue line `(BTX/hr)_g × P_BTX`** computed at live `TOPS_net`. Their intersection projects down to `P*_g` on the x-axis; **below the intersection the class rents (region unshaded), above it mines (shade the region, filling in class by class as price rises)** — the shaded frontier *is* the switchover curve. Overlay a vertical line at spot `P_BTX` and a marker on the marginal class. Companion table (dashboard): the §Q.21.2 columns with live `P*_g`/`R*_g`, refreshed with rental polls; annotate that all mining-revenue lines shift down in lockstep as `TOPS_net` grows (crossings slide right, ∝ `TOPS_net`). The break-even *prices* may additionally be shown on the §Q.11-D $/BTX chart as tick marks under `P_prod` (same dimension); the $/hr curves may not.

#### Q.21.5 Guardrails (honest use)

1. **Opportunity-cost economics, not a price prediction.** `P*_g`/`R*_g` describe rational capacity allocation at quoted rental rates; they say nothing about where `P_BTX` will trade. Demand lives in §Q.18/§Q.20's other bracket arm.
2. **Rental markets are illiquid at the edges.** Apple M5-class has essentially no rental market (opportunity cost ≈ residual/electricity → the `P⁰` floor is the honest threshold, and "mine" is near-costless default, not arbitrage); 3090 Ti is proxied; GB200 quotes are early-adopter and wide ($10.5–27). Treat those `P*` as soft bounds.
3. **List price ≠ take-home.** Marketplace list rates (vast.ai et al.) exceed host take-home (platform fees, idle time, egress/support burden), so consumer `R_g` here are *upper* bounds on true opportunity cost and the consumer `P*_g` are conservative (true switchover slightly lower / mining slightly more attractive than shown). Datacenter on-demand rates similarly embed provider margin over an owner-operator's realizable rate.
4. **Everything moves.** `P*_g ∝ TOPS_net × R_g`: difficulty growth raises thresholds mechanically; rental repricing (H100 rates fell ~2× during 2024–26) lowers them. Timestamp every rental poll; never quote a `P*` without its `(TOPS_net, R_g)` snapshot.
5. **Per-GPU, share-based.** The model assumes §O.2 proportional pooled rewards (BTX/hr = expected share). Solo-mining variance, pool fees, and vardiff overhead sit on top and only *raise* effective break-evens.
6. **Descriptive, never prescriptive — and the input price may be manipulated (§0.7-(4)).** This entire metric consumes `P_BTX` as an *exogenous* variable; it produces which-card-mines-at-what-price, and nothing here may flow back into a consensus parameter. Because `P_BTX` can be adversarially suppressed (mine-and-dump, wash/fake-supply selling, §S.4), the low-price outcomes above are an **attack state**, not the equilibrium: reading them as "the network is naturally consumer-dominated, so keep the bar low" is exactly the manipulation the price-independence invariant forbids. Use this chart to *explain* miner behavior and to show how the floor rises once genuine demand clears the datacenter thresholds — never to justify tuning difficulty, `n`, the work unit, or the floor to the current print.

---

### Q.22 Price as an output: metric taxonomy, manipulation model, and display (normative for btxprice)

> **Status:** governing for all btxprice presentation, implementing §0.7-(4). Price is an **output the market discovers** — on a thin market, a manipulable one — never an input to any protocol parameter or any headline metric.

**Q.22.1 Taxonomy — every displayed series carries exactly one tag.** Data flow is one-way: `chain → PHYSICAL → MODEL → display`; the observed price enters only the display layer.

| Tag | Meaning | Movable by moving the BTX print? |
|---|---|---|
| **[PHYSICAL]** | from chainwork, timestamps, consensus constants, hardware datasheets only | **No** — only by physically adding/removing Freivalds-verified compute |
| **[OBSERVED]** | a market output the network does not control and never consumes | Yes — that is the point; it is labeled as such |
| **[MODEL]** | a bracket/read-out combining PHYSICAL series with *external, non-BTX* market prices (GPU rental, Bitcoin) | Only via those external markets — not via the BTX print |

Assignment: `BTX_security_%`/`SEH`, `TOPS_net`/`N_eq`, raw `M_BTX` are **[PHYSICAL]**; `P_prod`, `P_prod_inf`, `P⁰`, `P*_g`, `P_btc`, `C_51` are **[MODEL]**; the exchange print `P_obs`, observed market cap, and reported volumes are **[OBSERVED]**.

**Q.22.2 The suppression burn-rate model.** Emission is fixed at 800 BTX/hr, so a dumper controlling share `s` of work dumps `s·800` BTX/hr and runs a metered loss

```
B = s · 800 · (P*_marginal − P_obs)⁺   [$/hr]   (+ wash-trading fees)
```

v3: `P*_marginal ≈ 0` (paid-off junk) ⇒ `B ≈ 0`, suppression self-financing. v4 (100-H100-eq, 5090-marginal): pinning `P_obs` below `P*_marginal` costs `B = s·800·(P*_marginal−P_obs)⁺` (computed on live inputs; no fixed value), forever, in real dollars (§S.4.3 negative-carry). **Fake supply** (wash/spoof) moves `P_obs` only — it mints no coin, adds no nonce, moves no chainwork, so every [PHYSICAL] series is untouched. That asymmetry *is* the security argument.

**Q.22.3 Gap decomposition.** `G = P_btc/P_obs = (P_btc/P_prod) × (P_prod/P_obs)`: the first factor is **structural** disequilibrium (constant in `N_eq`, parallel on a log axis — the honest distance between cost-to-produce and Bitcoin-grade security valuation; `P_btc/P_prod` is computed live from live inputs, no fixed ratio, §Q.20); the second is the **stress residual** = 1 in a rational regime, and > 1 only under capitulation (transient) or subsidized/manufactured supply (manipulation). A wide `P_btc/P_obs` is therefore *partly* manipulation, not purely honest disequilibrium; v4 compresses it **from below** (raising `P_prod`), never by chasing the print.

**Q.22.4 Diagnostics (all price-free on the evidence side; display annotations only).**

| # | Indicator | Manipulation-consistent reading |
|---|---|---|
| D1 | `P_obs < P*_marginal` for > k ASERT half-lives (k≈48 h) *while `TOPS_net` is flat/rising* | rational miners would have exited (shown in `TOPS_net`); someone is eating a metered loss or the flow is not real. Amber; below `P⁰`, red |
| D2 | reported daily sell volume ÷ (19,200 BTX/day + bounded float) ≫ low single digits | reported volume cannot be real coins — wash-consistent (Bitwise 2019; Cong et al. 2023) |
| D3 | `TOPS_net` rising while `P_obs` grinds down | real capital entering *against* the print — the print, not the network, is the anomaly |

**Q.22.5 Display rules (binding).** (1) Never "BTX is worth $X" — always "BTX trades at $X **(observed; may be suppressed)**; production-cost floor read-out $A; security-comparable $B." (2) Render `P_obs` as badged dots; when `P_obs < P_prod` or `< P⁰`, **show it below the floor** — never clamp or re-anchor the floor to it; the violation *is* the signal. (3) Chart D′: log $/BTX; `P_btc` dashed ("aspirational, not a floor"), `P_prod` band `[P*_marginal, P*_H100]` ("soft anchor"), `P⁰` dotted, `P_obs` badged dots; zones **green** `[P*_marginal, P_btc]` = fair-discovery range, **amber** `[P⁰, P*_marginal)` = below marginal cost / possible manipulation, **red** `< P⁰` = sub-viability; parallel bracket lines, no crossover. Beside it a **price-integrity panel** (D1–D3 with thresholds/state). (4) The standing line on every price view: *"No BTX price is an input to any consensus parameter (§0.7-(4)). These charts describe; the protocol does not read them."* (5) The prior "consumer-dominated low-`P_prod`-floor" wording is retired as an *equilibrium* description — it is the descriptive read-out at a suppressed print (the attack state), not the resting state.

**Q.22.6 No-feedback guard.** `getnetworkhashps` is a read-only RPC (`src/rpc/mining.cpp:271-315`); ASERT reads only heights/timestamps/constants (`src/pow.cpp:1829/2106/2455`); no consensus path consumes an exchange feed or btxprice. Recommended CI check: assert `src/pow.cpp`, `src/validation.cpp`, `src/kernel/chainparams.cpp` contain no price/HTTP dependency, and that btxprice's pipeline is one-directional.

---

## R. Post-quantum security — end-to-end audit

> **TOP-LINE VERDICT: the end-to-end post-quantum requirement is MET.** BTX is a **post-quantum-only chain from genesis.** Every non-OP_RETURN output must be a witness-v2 P2MR program (ML-DSA / SLH-DSA); legacy secp256k1 ECDSA, P2WPKH, and Schnorr/Taproot outputs **cannot be created** (consensus-rejected) and legacy signature verification is **additionally rejected** at the interpreter as defense-in-depth. Combined with the PQ-safe v4 PoW, information-theoretic Freivalds verification, SHA-256 at the 128-bit post-Grover tier, and the FIPS-204 / FIPS-205 signature schemes, BTX is end-to-end post-quantum. All primitives audited PQ-SAFE. (Verified against the code; see §R.2. An earlier draft of this audit wrongly reported legacy signatures as live — it searched for `nECDSADisableHeight`/`DISALLOW_ECDSA`-style gates and missed BTX's actual mechanism, `fEnforceP2MROnlyOutputs` + `SCRIPT_VERIFY_REJECT_LEGACY_SIGS`; corrected here.)

### R.1 Summary verdict table

| # | Primitive / role | Location | Quantum threat | PQ status |
|---|---|---|---|---|
| 1 | **PQ-only output rule** (non-OP_RETURN outputs must be witness-v2 P2MR) | `validation.cpp:9685-9717` (called `:9791`); `fEnforceP2MROnlyOutputs`+`fReducedDataLimits` = true `chainparams.cpp:161-162` | Blocks creation of any secp256k1 (ECDSA/Schnorr/Taproot) output | 🟢 **PQ-SAFE (enforced from genesis)** |
| 1 | **Legacy-sig rejection** (`SCRIPT_VERIFY_REJECT_LEGACY_SIGS`) | flag `interpreter.h:169`; set `validation.cpp:6811-6812`; enforced `interpreter.cpp:408-412` | Defense-in-depth vs Shor on secp256k1 (paths already unreachable) | 🟢 **PQ-SAFE** |
| 2 | **ML-DSA-44** (FIPS 204 / Dilithium) | `pqkey.h:26-28`, `libbitcoinpqc`, `interpreter.cpp:1173-1333` | Lattice (MLWE/MSIS); no known quantum poly-time algorithm | 🟢 **PQ-SAFE** |
| 2 | **SLH-DSA-SHAKE-128s** (FIPS 205 / SPHINCS+) | `pqkey.h:27`, `slh_dsa.h:12-15` | Hash-based; only Grover on SHAKE-256 | 🟢 **PQ-SAFE (most conservative)** |
| 3 | **SHA-256 seed derivation** (`DeterministicMatMulSeedV4`) | §H.4; `pow.cpp:53-100` | Grover preimage 2²⁵⁶→~2¹²⁸ | 🟢 **PQ-SAFE** |
| 3 | **Product-committed digest / sketch commit** `H(σ‖Ĉ)` | §A.3/§E.1; `transcript.cpp:485-509` | Grover preimage ~2¹²⁸; quantum collision ~2⁸⁵ (BHT) | 🟢 **PQ-SAFE** (R.4) |
| 3 | **Block header hash** `GetHash` (SHA256d) | §H.1; `block.cpp:11-14` | Grover mining: quadratic speedup on `digest ≤ target` | 🟢 **PQ-SAFE** (difficulty absorbs) |
| 4 | **MatMul work** (dense INT8 GEMM `C = A·B`) | §A, §B, §K | No relevant quantum speedup on emitting the classical n² product | 🟢 **PQ-SAFE** |
| 5 | **Freivalds verification** over `q = 2⁶¹−1` | §D.3 | None — information-theoretic (Schwartz–Zippel) | 🟢 **PQ-SAFE (unconditional)** |
| 6 | **Optional ZK (Plonky2, FRI/Goldilocks)** | §F | Grover on FRI hash / random oracle | 🟢 **PQ-plausible** (hash-based) |
| 7 | **SHA-256 Merkle / witness commitments** | Bitcoin-core inherited | Grover collision/preimage | 🟢 **PQ-SAFE** |
| 7 | **P2MR address / leaf hashing** (SHA-256, PQ key material) | `pqm.h:17-31` | Grover preimage ~2¹²⁸ | 🟢 **PQ-SAFE** |
| 7 | **Shielded pool** (lattice commitments, SLH-DSA/FIPS-205, ML-KEM) | `params.h:280-360` | Lattice-based; Grover on internal hashes | 🟢 **PQ-SAFE** (out of PoW scope) |
| — | **ML-DSA emergency disable** (`nMLDSADisableHeight`, defensive) | `params.h:323`; `interpreter.h:154` | Hedge if lattices ever break → falls back to SLH-DSA | 🟢 **defensive feature, not a hole** |

### R.2 How BTX enforces end-to-end PQ (verified in code)

BTX is **not** Bitcoin-with-PQ-bolted-on; it is a **PQ-only chain from genesis**, enforced at two layers:

**(1) Output creation — no non-PQ output can exist.** On mainnet, testnet, testnet4 and signet, `consensus.fReducedDataLimits = true` and `consensus.fEnforceP2MROnlyOutputs = true` (`chainparams.cpp:161-162, 534-535, 716-717, 928-929`; false only on regtest, `:1089-1090`). `CheckReducedDataOutputLimits` (`validation.cpp:9685-9717`, invoked from the block/tx validation path at `:9791`) iterates every output and, for any non-`OP_RETURN` output that is **not** a witness-v2 program with a 32-byte payload (`is_p2mr_output`, `:9689-9694`), returns `state.Invalid(BLOCK_CONSENSUS, "bad-txns-nonp2mr-output", "non-OP_RETURN outputs must be witness v2 P2MR")` (`:9713-9716`). Witness v2 + 32 bytes is precisely the P2MR (pay-to-MatRiCT-root) PQ output type (`pqm.h:17-31`) that commits ML-DSA / SLH-DSA key material. This **excludes every secp256k1 output type**: legacy P2PK/P2PKH (BASE), P2WPKH/P2WSH (witness v0), and Taproot (witness v1) are all non-v2 and therefore rejected. There is **no height gate** — the rule is a plain consensus boolean active from block 0, so no window ever existed in which a non-PQ output could be mined.

**(2) Spend verification — legacy signatures rejected outright (defense-in-depth).** `GetBlockScriptFlags` sets `SCRIPT_VERIFY_REJECT_LEGACY_SIGS` (`interpreter.h:169`, bit 25) whenever `fEnforceP2MROnlyOutputs` holds (`validation.cpp:6807-6813`). In `EvalChecksig` (`interpreter.cpp:400-412`), that flag causes any checksig under `SigVersion::BASE`, `WITNESS_V0`, or `TAPSCRIPT` — i.e. every secp256k1 ECDSA or Schnorr path — to return `SCRIPT_ERR_BAD_OPCODE` before verification. PQ signatures use the dedicated `OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA` opcodes under `SigVersion::P2MR` (`interpreter.cpp:1173-1333`), a separate route. The in-tree comment states the design intent verbatim: *"BTX is post-quantum only … legacy … are unreachable on a PQ-only chain (no non-P2MR outputs exist), and are rejected outright at consensus."* This layer is redundant with (1) by design — belt and suspenders.

**Why the earlier draft was wrong.** A name-based search for `nECDSADisableHeight` / `SCRIPT_VERIFY_DISALLOW_ECDSA` / `DISALLOW_SCHNORR` returns nothing, and the ECDSA/Schnorr verifier *functions* still exist in `interpreter.cpp` (inherited from Bitcoin Core), so a search that stopped there concluded legacy spending was live. It is not: the enforcement is by the differently-named `fEnforceP2MROnlyOutputs` + `SCRIPT_VERIFY_REJECT_LEGACY_SIGS`, and the verifier functions are dead code (no UTXO can reach them). The correct verdict is **end-to-end PQ: MET.**

### R.3 Detailed per-primitive analysis

**Signatures (PQ-SAFE).** ML-DSA-44 (FIPS 204, Module-LWE/SIS, NIST Cat-2) and SLH-DSA-SHAKE-128s (FIPS 205, hash-based, Cat-1; 32-byte pk, 7856-byte sig) are the NIST PQ standards, both Shor-immune. SLH-DSA is the conservative fallback if ML-DSA is ever disabled via the defensive `nMLDSADisableHeight` hedge (`params.h:323`) — an intentional safety valve (if module-lattice cryptanalysis ever advances, the chain drops to the hash-based scheme), not a weakness. No secp256k1 hybrid is used for on-chain verification. These are the *only* spendable signature schemes on the chain.

**v4 SHA-256 usage — Grover (PQ-SAFE).** Grover gives at most a quadratic speedup: SHA-256 preimage 2²⁵⁶→~2¹²⁸ (hard to parallelize, √(machines) only — NIST SP 800-208 / IR 8105). (a) 128-bit post-Grover is ample for seed unpredictability and Fiat–Shamir binding. (b) The `digest ≤ target` mining search gets the same quadratic edge as Bitcoin's SHA PoW — not chain-breaking: difficulty auto-adjusts (ASERT §I.4), Grover barely parallelizes, and the edge is a constant hashrate multiplier like any ASIC jump; in v4 the dominant per-nonce cost is the INT8 GEMM, not the header hash, so the lever matters even less. (c) **Recommendation: keep SHA-256/SHA256d — 128-bit post-Grover is the deliberate, sound design point.** Optional future hardening: move the *product-committed digest and Fiat–Shamir transcript hash* to SHA-512/256 (same 32-byte output, faster on 64-bit nodes, more internal-state margin) if a 256-bit-post-Grover commitment margin is ever desired. Not required.

**MatMul work (PQ-SAFE).** Emitting the full classical product `C = A·B` has no relevant quantum speedup: quantum GEMM/linear-algebra speedups act on structured/quantum-encoded inputs and produce quantum states/samples, not the explicit n² classical matrix a validator re-checks (readout is Ω(n²)); Freivalds over q pins the exact product (invariant I6), so an approximate/sampled result cannot pass. A quantum miner has no asymptotic per-nonce edge beyond the generic Grover-on-header lever, which difficulty absorbs.

**Freivalds & field (PQ-SAFE, unconditional).** Soundness over `q = 2⁶¹−1` is information-theoretic (Schwartz–Zippel), resting on **no** computational assumption → secure against any adversary, quantum or classical. The only cryptographic ingredient is the SHA-256 Fiat–Shamir challenge (covered above).

**Optional ZK Plonky2 (PQ-plausible).** FRI + Goldilocks, no pairings/trusted setup; soundness reduces to hash/random-oracle resistance. Plausibly PQ if the FRI/Poseidon hash targets ≥128-bit post-Grover. No DLP/pairing primitive involved.

**Merkle / addresses / shielded pool (PQ-SAFE).** SHA-256 Merkle & witness commitments (Grover-adjusted, acceptable); P2MR address derivation commits ML-DSA/SLH-DSA key material over SHA-256, no EC primitive; the shielded pool uses lattice commitments (MatRiCT/SMILE) with an SLH-DSA/FIPS-205 activation and a PQ-128 upgrade path — out of PoW scope, unmodified by v4, sound at the primitive level.

### R.4 Grover / hash-width recommendation (consolidated)

- **Mining/target (header SHA256d):** keep SHA-256; 128-bit post-Grover accepted, quadratic mining edge difficulty-absorbed and non-parallelizable. No change.
- **Commitment & Fiat–Shamir (seed, product digest, challenge):** keep SHA-256/SHA256d; optional drop-in to SHA-512/256 for extra margin. Not required.
- **If Plonky2 activated:** size FRI/Poseidon hash for ≥128-bit post-Grover.

The hash layer is PQ-SAFE at the 128-bit post-Grover tier — the correct, sufficient design point.

### R.5 Bottom line & standards

**BTX meets the end-to-end post-quantum requirement today**, on mainnet, at the current block height, enforced from genesis: only PQ (P2MR / ML-DSA / SLH-DSA) outputs can be created or spent, the v4 PoW and its verification are quantum-safe, and the hash layer is sound at the 128-bit post-Grover tier. The only recommended items are *optional* hardening (SHA-512/256 on the commitment digest; ≥128-bit-post-Grover FRI hash if Plonky2 is ever enabled) — none required. Keep the `nMLDSADisableHeight`→SLH-DSA fallback as the standing lattice-break contingency.

Standards: FIPS 203 (ML-KEM), **FIPS 204 (ML-DSA)**, **FIPS 205 (SLH-DSA)**, FIPS 180-4 (SHA-2), FIPS 202 (SHA-3/SHAKE), NIST SP 800-208 & IR 8105 (Grover rationale). The secp256k1 schemes (BIP340/341/342) are present only as inherited dead code and are consensus-rejected.

---

## S. ASIC/FPGA resistance, AI-native-compute necessity, and rogue-pool economics

### S.1 Reframing "ASIC resistance": the goal is AI-native-compute necessity

For v4 the classic "can anyone build fixed-function silicon that beats commodity hardware?" question dissolves, because the answer is yes — and that silicon is **mass-produced, commoditized, and the intended winner**. A dense, exact `s8×s8→s32` GEMM is *the* canonical workload of the AI era; its optimal circuit is a large tiled INT8 MAC array with high-bandwidth local memory — i.e. a **tensor core** (NVIDIA IMMA), a **TPU MXU**, an **MFMA unit** (AMD CDNA), or an **Apple GPU Neural Accelerator** (§O.1). A bespoke "BTX ASIC" would spend hundreds of millions re-deriving a TPU and then lose to vendors who ship that exact circuit at frontier nodes in volume. There is no secret better circuit — the AI industry has already spent ~$10¹¹ optimizing this precise primitive.

v4's hardware-security claim is therefore **not** "no ASIC can win." It is:

> **AI-native-compute necessity.** The only hardware that can win v4 blocks is hardware with a genuine, bit-exact, high-throughput dense INT8 tensor-matmul path — current AI accelerators (datacenter GPUs, TPUs, AI-capable consumer GPUs, M5-class Apple silicon). All **non-AI** hardware — SHA-256 ASICs, FPGAs, CPUs, memory-bandwidth cards (CMP-class), pre-tensor and FP-only GPUs — is structurally uncompetitive or excluded. "ASICs win" and "the design works as intended" are the same statement, because the relevant ASIC *is* AI-native compute.

### S.2 Closure: no non-AI device class can win

**S.2.1 FPGAs lose on throughput, $/TOPS, and TOPS/W — by construction of the workload.** FPGAs win on exotic bit widths, irregular dataflow, and ultra-low-latency small-batch inference — the polar opposite of v4 (one enormous dense latency-insensitive GEMM per nonce at full utilization). Even the AI-optimized flagship FPGAs:

| Device | Dense INT8 peak | vs H100 (1,979) | vs B200 (4,500) |
|---|---|---|---|
| Intel Stratix 10 NX (AI Tensor Blocks) | **143 TOPS** @ ~1 TOPS/W | 13.8× behind | 31× behind |
| AMD Versal AI Core VC1902 | **133 TOPS** | 14.9× | 34× |
| AMD VCK5000 card ($2,495) | **145 TOPS** | 13.6× | 31× |
| *ref: RTX 5090 (consumer GPU)* | 838 TOPS | 2.4× | 5.4× |
| *ref: TPU v5e / v6e* | 393 / ~1,836 TOPS | — | — |

Three independently fatal facts: (1) **throughput** — the best AI-FPGA ≈ 7% of an H100, 3% of a B200; a consumer 5090 beats every FPGA card ~5.8×; (2) **$/TOPS** — VCK5000 ≈ $17/TOPS vs 5090 ≈ $2.4/TOPS ($2,000/838) vs rentable H100 with zero capex; (3) **TOPS/W** — Stratix 10 NX ≈ 1 vs H100 ≈ 2.8 vs B200 ≈ 4.5, so the FPGA pays 3–4.5× the electricity per op on a PoW whose only recurring cost is energy per op. The deepest point: the *only* reason these FPGAs post triple-digit TOPS is that their vendors **hardened matmul units into the fabric** — the FPGA industry's own answer to dense INT8 GEMM was to stop being an FPGA. No reconfigurability dividend remains for v4 to leak. Sources: [Intel Stratix 10 NX white paper](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/a1153843-beyond-peak-performance-white-paper.pdf), [IEEE FCCM 2021](https://ieeexplore.ieee.org/document/9415606/), [AMD Versal AI Core](https://www.amd.com/en/products/adaptive-socs-and-fpgas/versal/ai-core-series.html), [AMD VCK5000](https://www.amd.com/en/products/adaptive-socs-and-fpgas/evaluation-boards/vck5000.html), [HPCwire](https://www.hpcwire.com/2022/03/08/amd-xilinx-takes-aim-at-nvidia-with-improved-vck5000-inferencing-card/), [Google TPU v6e](https://docs.cloud.google.com/tpu/docs/v6e).

**S.2.2 Component-by-component shortcut audit — no non-AI ASIC angle exists.**

| Component | Share of per-nonce cost | Fixed-function/ASIC edge? |
|---|---|---|
| **SHA-256 seed + sealing** | ~10⁻⁶ of the work (2 header hashes vs 1.7×10¹⁰ GEMM ops) | **None.** Contrast v3, where the ε-gate made 262,143/262,144 attempts *pure SHA* — so SHA silicon (CMP-class) effectively *was* the miner. v4 demotes SHA to seed/seal; a Bitcoin SHA ASIC mines v4 at rate ≈ 0. |
| **Operand expansion (XOF, O(n²))** | <1% | Negligible by Amdahl; GPUs generate operands on-die anyway. |
| **Dense GEMM** (exact s8×s8→s32, INT32 accumulate) | **>99%** | AI silicon's native op. No exotic width, no GF(2ⁿ) bit-twiddling, no mid-loop modular reduction (§B.4 keeps the whole K-dim in one INT32 accumulation). Any optimal circuit is a tensor core/MXU. |
| **Memory profile** | AI(n)=n/3≈1,365 ops/byte, compute-bound | Bandwidth ASICs gain nothing; the CMP-170HX profile (1.5 TB/s, ~no compute) is 158× behind H100 (§K.3). |
| **Determinism** | — | Property of two's-complement integer MMA on *any* conforming unit (§B.6) — IMMA, MFMA, M5 TensorOps, AVX-512 VNNI all match; excludes only FP-approximate paths, which no ASIC can smuggle past the digest (I6). |
| **Sub-cubic (Strassen) / sketch shortcut** | ≤~1.3× / factor b/2, available to all | Constant-factor, hardware-agnostic, difficulty-absorbed (§A.6, §N.3-ii); both still reduce to dense INT8 GEMMs. |

**Conclusion: the cheapest way on Earth to produce a bit-exact dense INT8 GEMM at scale is commodity AI tensor silicon.** A from-scratch non-AI ASIC has no component to attack. The only "ASIC" that helps is a big INT8 MAC array — a TPU — and building one means paying leading-node NRE (~$542M at 5nm, $0.5–1.5B at 3nm — [SemiEngineering](https://semiengineering.com/big-trouble-at-3nm/), [SemiEngineering](https://semiengineering.com/what-will-that-chip-cost/)) to arrive years later at a worse-than-B200 part whose difficulty target (§I.4) has already absorbed that generation. **Honest residual caveat:** a mining-only tensor chip could strip FP64/graphics/NVLink for a modest cost/watt edge — but that is again a TPU-class *AI inference ASIC*, i.e. AI-native compute with a different logo. It does not reopen participation to SHA farms, FPGAs, or junk cards; it is the disclosed centralization cost of §N.3-iv, by design.

### S.3 Hardening recommendations: maximize the AI-GPU-necessity property

1. **Keep SHA at seed/seal only — never reintroduce any pre-hash gate or hash-priced step** (any per-nonce hash filter recreates the v3 SHA lottery; enforce the §M.3 invariant that commit/hash ≪1% of tensor time).
2. **Keep the GEMM large, dense, full-rank, high-arithmetic-intensity** (n≥4096 keeps AI ≥ 2.3× above every ridge; full-rank i.i.d. operands keep sparse/low-rank tricks unusable; never add sparsity, fixed structure, small tiles, or repeated sub-blocks).
3. **Keep the precision exactly `s8×s8→s32`** — highest-leverage datacenter dtype, bit-exact/ZK-free, *and* the industry-standard quantized-inference precision, so consensus arithmetic tracks mainstream AI silicon for free. Never adopt bespoke widths (10-bit, GF(2ⁿ), mid-loop modular) — non-standard arithmetic is the one thing an FPGA does better than a tensor core.
4. **Shape the GEMM like real AI GEMMs** (n=4096 mirrors transformer d_model/FFN shapes; the §E.3 sketch GEMMs are literally skinny inference-style GEMMs), so the optimal miner is *literally* the optimal inference box and any mining ASIC is automatically a merchant AI part.
5. **Calibrate difficulty against the true optimal work unit** `n³·(2/b)` and measured honest dense cost (§E.3, §I.4), so constant-factor optimizations are absorbed as ordinary efficiency, not accumulated into a custom-silicon shortcut.
6. **Keep the determinism self-test + cross-vendor golden vectors mandatory** (§N.2, §N.3-v): eligibility ("has a genuine bit-exact INT8 tensor path") must be machine-checkable, not vendor-claimed (the M4 ANE "38 TOPS" marketing case shows why).
7. **Monitor for non-AI-hardware anomalies** (nonce-rate-vs-declared-hardware outliers) via the §N.3 dashboard.
8. **Accept and disclose the fixed point:** a datacenter AI GPU/TPU *is* the optimal "ASIC" for v4, permanently — hardening keeps that true (and non-AI silicon excluded), not prevents it.

### S.4 Rogue-pool economics: v4 vs the mine-and-dump model (btxpool.org case study)

**S.4.1 The parasitic model under v3.** A community report identifies `btxpool.org` — advertising "High-Yield BTX Mining Pool," PPLNS, hourly auto-payouts, 0% miner fee / ~10% dev fee, global Stratum — as running a **mine-and-dump arbitrage on low-quality "JEET hashrate."** Its public pages corroborate a hardware profile headed by **CMP 30HX/40HX/50HX** and end-of-life parts (RTX 2060 SUPER, V100), PPLNS over a 10,000-share window, hourly payout ≥ 0.1 BTX, a "temporarily reduced 5%" dev fee, and a global Stratum endpoint. Under v3 this is rational and corrosive: the ε-gate made the work a **SHA lottery** on which CMP-class/old cards sit near parity (§0.5 #13, "2 CMP ≈ 1 5080"); the hardware is paid-off and otherwise worthless (post-Ethash CMP cards have no resale market and no alternative workload), so marginal cost ≈ electricity only (~$0.0125/hr for a 250 W card at $0.05/kWh) — an effective **$0 floor** where *any* sale price is pure profit, so the rational policy is continuous 100% liquidation: structural, price-insensitive sell pressure.

**S.4.2 v4 collapses the hardware base.** Re-pricing the pool's advertised fleet by dense INT8 (§K.3):

| btxpool.org device | v3 standing | v4 standing |
|---|---|---|
| CMP 30HX (TU116) | competitive | **Excluded** — no tensor cores at all, no s8×s8→s32 path |
| CMP 170HX-class | competitive | **~158× behind H100, ~360× behind B200** — effectively excluded |
| Tesla V100 (Volta) | competitive | **Verify-only** — Volta tensor cores are FP16-only (non-deterministic, inadmissible); INT8 MMA arrived with Turing |
| CMP 40HX/50HX, RTX 2060 SUPER (Turing) | competitive | *If* IMMA exposed: ~100–230 TOPS → **~9–20× behind H100**; else excluded |
| pre-M5 Apple | competitive | **Excluded** |
| RTX 4090 / A100 sliver | competitive | Participates — as ordinary AI hardware at real cost (S.4.3) |

A fleet at ~parity per card under v3 drops to **1/9–1/360 of a modern accelerator per card, several classes excluded outright**. Since v4 pool revenue is strictly proportional to contributed *verified* compute (§O.2 — shares are Freivalds-checked matmul work, unfakeable and un-SHA-grindable), the pool's share, payout, and dev-fee take collapse by the same factor. The one asset the model depends on — cheap hardware that still does competitive work — no longer exists.

**S.4.3 A real marginal-cost floor replaces zero-cost dumping.** v4-capable hardware is, by S.1, **AI-rentable hardware** with a liquid hourly market (H100 on-demand ~$2–3.6/hr, specialist ~$2–2.4/hr, spot as low as ~$0.34/hr — [Spheron](https://www.spheron.network/blog/gpu-cloud-pricing-comparison-2026/), [Thunder Compute](https://www.thundercompute.com/blog/nvidia-h100-pricing), [GetDeploying](https://getdeploying.com/gpus/nvidia-h100), [IntuitionLabs](https://intuitionlabs.ai/articles/h100-rental-prices-cloud-comparison)). Every INT8 TOPS-hour pointed at BTX is one not sold to the AI market — a real opportunity cost for rented (cash) and owned (foregone revenue) fleets alike. At 90 s blocks and 20 BTX subsidy the network emits **800 BTX/hour**; with `N_eq` H100-equivalents (1 = 1,979 TOPS) at rate `r`/H100-eq-hour:

```
Floor($/BTX) ≈ N_eq · r / 800
```

*(This floor is identical — same formula, same $/BTX dimension — to the btxprice production-cost anchor `P_prod` of §Q.6/§Q.17–§Q.20; its per-GPU decomposition — the mine-vs-AI-rental break-even by device class, whose marginal-miner equilibrium this floor is — is §Q.21.)*

| `N_eq` | r=$0.34 (spot) | r=$2.50 | r=$3.61 (avg) |
|---|---|---|---|
| 100 | computed | computed | computed |
| 500 | computed | computed | computed |
| 2,000 | computed | computed | computed |
| 10,000 | computed | computed | computed |

(Each cell = `Floor($/BTX) = N_eq · r / 800`, computed live at the row's `N_eq` and the column's `r`; no cell value is a fixed/baked-in figure.)

**This is a soft, equilibrium anchor — a mechanism, not a hard price support (read with §0.7-(4)).** What is *structural and price-independent* is that a v4 nonce is real INT8 tensor work carrying a genuine AI-rental opportunity cost, so mining below that opportunity cost is irrational for any operator with an AI-market alternative (the same TOPS-hours convert to more dollars via rental). What is **not** guaranteed is a hard floor *under the market price*: the quantity above is the marginal miner's opportunity cost, and it **tracks price in both directions** via difficulty (ASERT) — as price rises, more and deeper hardware enters, `N_eq` rises, the floor rises; as price falls, marginal capacity redeploys to AI rental, `N_eq` falls, the floor falls. So the tabulated `$/BTX` values are **read-outs at a given `N_eq`, not a level the protocol pins** — consistent with §0.7-(4), the *number* moves with the market while the *mechanism* does not, and no price is ever fed back into a consensus parameter. Moreover, because emission is **fixed at 800 BTX/hour regardless of price**, this floor does not cap the *quantity* a determined dumper can sell; it raises the *marginal cost* of producing each coin, which is what kills the v3 zero-cost arbitrage. Contrast v3's ~$0 junk-hardware floor where dumping at any price was pure profit: v4 replaces price-insensitive, zero-cost structural selling with ordinary commodity-producer economics in which the marginal cost of a coin is a real, AI-market-indexed number. That is the honest claim — neither a guaranteed price support nor a cure for suppression by itself, but the removal of the zero-cost engine that made v3 dumping free. *(Rental note: the `r = $0.34` spot column is a **historical trough**; mid-2026 H100 spot is actually $2.46–2.91/hr with on-demand capacity reported sold out — [Thunder Compute](https://www.thundercompute.com/blog/ai-gpu-rental-market-trends). The trough is retained only as the adversary-optimistic bound.)*

**Negative-carry theorem (the floor read-out IS the suppression break-even).** For an operator sourcing fraction `f` of emission to dump at a suppressed print `P_s`, daily carry is `f · 19,200 · (P_s − c)` where `c = ρ_op·TOPS_net/800` is that operator's marginal cost per coin — **strictly negative whenever `P_s < c`, i.e. whenever the print is below the §Q.6 floor read-out.** So the floor formula is exactly the price at which suppression-by-mining flips from arbitrage to out-of-pocket burn. Combined with the **fixed-quantity lemma** (mined supply ≤ 800 BTX/hr = 19,200 BTX/day at any price/difficulty/fleet size — extra fleet only cannibalizes the attacker's own share via ASERT), gross mined-sell pressure is capped at `800·P_s $/hr` and every *additional* "supply" must be bought (value transfer to holders) or faked (§S.4.6). Cost-to-suppress, before vs after the fork (every `c`/coin and daily-carry cell below is computed live from `c = ρ_op·TOPS_net/800` and `f·19,200·(P_s−c)`; no cell is a fixed value):

| Regime | 𝒮's cheapest coin source | `c`/coin (N=100) | Daily carry to pin a suppressed print `P_s` at 50 % of emission | Self-financing? |
|---|---|---|---|---|
| **v3 (btxpool.org)** | paid-off CMP/junk, electricity only | ≈ **computed (near-zero)** | `9,600·(P_s−c)` — computed live | **Yes when `P_s>c≈0` — suppression is a business** |
| **v4, real spot present** | spot H100 @ $2.50 (real Jul-2026) | **computed (= P_prod)** | `9,600·(P_s−c)` — computed live | Depends on `P_s` vs `c`: negative (out-of-pocket) whenever `P_s<c` |
| **v4, adversary-optimistic** | trough spot @ $0.34 (historical) | **computed** | `9,600·(P_s−c)` — computed live | Marginal; needs a spot trough *and* `P_s>c` |
| **v4 + γ-gate** (if one existed — it does not, §L.4) | A100/H100 class only | **computed (γ× the H100 figure)** | `9,600·(P_s−c)` — computed live | Negative whenever `P_s<c`; cheap terminal state excised |

**v4 does not make suppression impossible — it makes it a cash-burning activity below a publicly computable threshold, and deletes the v3 state where suppression paid for itself.** The remaining soft spot (the network can be *pushed small*, after which the residual fleet's coins are cheap again) is the irreducible consequence of fixed emission + no capacity gate (§L.4); it is bounded by the residual class's tiny throughput (dominating even a 10-H100-eq network on Apple silicon needs ~150 M5 Max machines) and re-prices to the consumer band the instant the print clears consumer `P*`.

**S.4.4 Legit pooling survives; the parasitic variant does not (reconciles §O.2).** v4 does **not** kill pooling — it kills a specific pooling *business model*. Legit pools (§O.2) aggregate real INT8-capable devices (RTX 30/40/50, M5-family, A100/H100 fragments) with Freivalds-verified shares and proportional payouts; their members' hardware has alternative value and real operating cost, so output behaves like production at cost and incentives align with BTX's health. The parasitic pool's defining asset — hardware whose *only* residual use was BTX (zero opportunity cost → zero-floor dumping) — is exactly what v4 de-rates 10–360× or excludes; to stay relevant it must re-capitalize onto real AI hardware, inheriting the S.4.3 floor and becoming, economically, a legit pool. **Residual risk — spot-rental mine-and-dump during price spikes (quantified, §I.4.2):** bounded, not eliminated. A `k×` step-influx yields a **one-time ASERT windfall of ≈ 963 / 2,979 / 5,489 whole-network BTX at k = 2× / 5× / 10×** (attacker share `(k−1)/k`), harvested over ~4–5 h at full rental cost, symmetric on withdrawal; thereafter the steady-state spike margin is `P_spike − k·N_eq·r/800`, **self-extinguishing at exactly the post-influx floor read-out** (computed live; no fixed value). Worked (k=10, N=100): windfall ≈ 4,940 BTX; whenever the steady-state margin `P_spike − k·N_eq·r/800` goes negative, 𝒮 harvests the windfall and leaves; total dilution ≈ 5,489 BTX ≈ 0.03 % of a year's emission. This residual is real, bounded, and **cannot be eliminated without violating fixed emission or price-independence** (§0.7-(4)); at equilibrium the same mechanism is a *feature* (it recruits genuine AI capacity and arbitrages price toward the compute-cost floor from above). Monitor via §N.3 (nonce-rate spikes vs spot-GPU price troughs; difficulty trajectory vs the Epoch growth envelope).

**S.4.5 Net effect.** v4 converts BTX mining from a **zero-marginal-cost junk-hardware arbitrage** (v3: SHA lottery on paid-off cards → floorless sell pressure) into a **real-cost AI-compute activity** whose production cost — and rational sell floor — is indexed to the AI-compute market ($/TOPS-hour). Parasitic mine-and-dump pools lose both pillars at once (hardware stops doing competitive work; replacement hardware carries a real floor), while legitimate pooled participation by consumer and Apple-M5 AI hardware is preserved with consensus-grade share verification (§O.2). The structural sell pressure of the v3 era is replaced by commodity-producer economics anchored to the marginal price of AI compute.

**S.4.6 The price-robust floor ratio ρ, and the honest limits.** The one thing v4 guarantees at *every* price, including a suppressed one, is a **floor ratio**

```
ρ = ($/dTOPS·hr)_cheapest-eligible / ($/dTOPS·hr)_H100      (fraction of the H100-denominated floor that survives suppression)
```

v3: ρ ≈ 0 (CMP/junk had no alternative market → zero opportunity cost). v4 today: ρ = ($/dTOPS·hr of the marginal-eligible class) / ($/dTOPS·hr of H100) — e.g. ratio of the 5080's or 5090's rental $/POPS·hr (§Q.21.3, both KEEP-tier inputs) to the H100's, computed live — because the cheapest *eligible* producer (consumer INT8) carries a live AI-rental bid. ρ = 1 (datacenter-denominated floor at all prices) would require excluding consumer INT8, which is **impossible** (no capacity gate exists, §L.4) and **forbidden** (retail must stay poolable, §O.2). Below any rental bid the ordering is by **joules/nonce** — a physical, price-free ranking (B200 12.5 mJ < H100 19.9 < 5090 38.6 < 3090 69) in which datacenter and Apple tensor silicon win, bounding the deep-suppression drift. The suppression-burn worked example (method): to produce 80 % of blocks over a 100-H100-eq network 𝒮 rents ~1,756 5080-class cards (the cheapest $/TOPS fleet, at their polled rental $/hr), breaks even at `P*_g` for that fleet (computed live via `B = s·800·(P*−P_obs)⁺`; no fixed value), and burns real dollars per hour holding a suppressed print below that break-even — versus v3's ≈ free.

**Honest limits (do not overclaim — three separate price-free bounds, never conflate them).** The floor bounds *unit economics* (negative carry below `c`), ASERT bounds *timing* (§I.4.2 half-life), emission bounds *quantity* (800 BTX/hr). What the design **cannot** do: (1) **no hard price support** — a fixed-emission coin with no treasury cannot bid under its own price; if demand is zero, price is zero and 800 BTX/hr still mint on the residual `ρ⁰` fleet; the floor is where *rational supply* stops, not where price stops. (2) **The floor deflates under successful suppression** — sustained `P_s` below all `P*_g` drives honest exit, `TOPS_net` falls, `c` falls with it; the terminal state (absent a gate that cannot exist) is the Apple/idle electricity floor `P⁰`. The consumer-dominated, low-`P_prod`-or-below regime is thus self-consistent as an **attack state** (§0.7-(4)); the design's answer is to make *entering and holding* it cost real money (the negative-carry burn), not to forbid it. (3) **Wash trading / spoofed depth are invisible to consensus** — they move `P_obs` only, mint no coin, touch no chainwork; there is no protocol response and none should be attempted (an on-chain "price defense" would need a price oracle — the §0.7-(4) forbidden input). Refusing to read the price is *itself* the defense: it denies the manipulator the difficulty/floor as a second lever. Off-consensus responses are disclosure (§Q.20/§Q.22 caveats), monitoring (§N.3; difficulty-vs-Epoch-envelope), and the structural fact that fake supply manufactures no real coins, so it cannot bleed holders who do not sell.

---

## Appendix A — Glossary

| Term | Definition |
|---|---|
| **n** | Matrix dimension. v4 default 4096 (v3: 512). Per-nonce work: Θ(n³·2/b) under the default sketch payload; Θ(n³) under full-C (§E.3). |
| **p** | A small prime < 2⁸ used as the base field so elements fit an INT8 tensor-core operand. |
| **k** | Number of CRT primes (residue channels). The effective modulus is P = ∏pᵢ. |
| **P** | CRT-reconstructed modulus = ∏ pᵢ = 3,368,562,317 ≈ 2³¹·⁶⁵. A ring, not a field — Freivalds is never run over ℤ_P (§D.2); soundness is evaluated over the independent prime q = 2⁶¹−1 (§D.3). |
| **b** | Product-commitment/sketch tile size; n must be divisible by b. Network-wide **b = 8** (§G.2/§K.2a); sets sketch dimension m = n/b, payload 8m², the §E.3 work factor b/2, and the optimal-miner arithmetic intensity `AI_opt = 2n/b` (kept above every INT8 roofline ridge). |
| **E_max** | Maximum canonical field element value; bounds INT32 accumulation (n·E_max² < 2³¹). |
| **A, B, C** | Per-nonce input matrices A, B and their product C = A·B over the field. |
| **σ (sigma)** | Per-nonce challenge = H(header), binds seeds, Freivalds vector, and commitment. |
| **Product-committed digest** | SHA-256d over the per-block-compressed image of C; the value compared to target. |
| **Freivalds check** | O(n²) deterministic test C·r ≟ A·(B·r) (sketch form: xᵀĈy ≟ (Uᵀx)ᵀA(B(Vy))) for header-derived challenges, evaluated over q = 2⁶¹−1 (§D.3). |
| **Epsilon gate** | v3 pre-hash SHA filter (removed in v4). |
| **Low-rank noise** | v3 rank-r perturbation E=E_L·E_R, F=F_L·F_R (removed in v4). |
| **ML-DSA / SLH-DSA** | FIPS 204 / FIPS 205 post-quantum signatures; transaction-layer, untouched by v4. |
| **ASERT** | aserti3-2d exponential difficulty retargeting; reused unchanged. |
| **Roofline ridge point** | Arithmetic intensity at which a kernel transitions from memory-bound to compute-bound. v4 operates above it. |

## Appendix B — Consolidated references

**Source protocol & prior BTX design**
- Komargodski, Schen, Weinstein. *Proofs of Useful Work from Arbitrary Matrix Multiplication.* arXiv:2504.09971 / IACR ePrint 2025/685. https://arxiv.org/abs/2504.09971
- BTX v3 spec: `doc/btx-matmul-pow-spec.md`; analysis: `doc/btx-matmul-pow-spec-analysis.md`; Freivalds design: `doc/freivalds-algorithm-analysis.md`.

**Hardware throughput (tensor cores)**
- NVIDIA H100 datasheet. https://resources.nvidia.com/en-us-gpu/h100-datasheet-24306
- NVIDIA H200. https://www.nvidia.com/en-us/data-center/h200/
- NVIDIA B200 guide. https://www.spheron.network/blog/nvidia-b200-complete-guide/
- Blackwell vs Hopper (Exxact). https://www.exxactcorp.com/blog/hpc/comparing-nvidia-tensor-core-gpus
- RTX 5090. https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/rtx-5090/ ; specs: https://www.spheron.network/blog/nvidia-rtx-5090-specs/
- RTX 5090/5080 AI review (Puget). https://www.pugetsystems.com/labs/articles/nvidia-geforce-rtx-5090-amp-5080-ai-review/
- RTX Blackwell architecture whitepaper. https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf
- Apple M4 (Wikipedia). https://en.wikipedia.org/wiki/Apple_M4 ; M4 ANE analysis: https://maderix.substack.com/p/inside-the-m4-apple-neural-engine-615
- NVIDIA CMP 170HX teardown/review. https://niconiconi.neocities.org/tech-notes/nvidia-cmp-170hx-review/
- Apple M5 (newsroom). https://www.apple.com/newsroom/2025/10/apple-unleashes-m5-the-next-big-leap-in-ai-performance-for-apple-silicon/ ; Apple M5 (Wikipedia). https://en.wikipedia.org/wiki/Apple_M5 ; M5 coverage (Tom's Hardware). https://www.tomshardware.com/pc-components/cpus/apple-unveils-m5-chip-with-10-core-cpu-and-10-core-gpu-company-says-3nm-chip-offers-4x-peak-gpu-performance-over-m4-for-ai-45-percent-graphics-uplift
- Apple A19/M5 Neural Accelerator microbenchmarks (Zakharko). https://tzakharko.github.io/apple-neural-accelerators-benchmark/ ; Apple Metal 4 TensorOps (Tech Talk 111432). https://developer.apple.com/videos/play/tech-talks/111432/ ; MLX on M5 (Apple ML Research). https://machinelearning.apple.com/research/exploring-llms-mlx-m5

**Determinism of low-precision matmul**
- On the Structure of Floating-Point Noise in Batch-Invariant GPU MatMul. arXiv:2511.00025. https://arxiv.org/pdf/2511.00025
- Numerical Nondeterminism in LLM Inference. arXiv:2506.09501. https://arxiv.org/pdf/2506.09501
- Deterministic Inference across Tensor-Parallel Sizes. arXiv:2511.17826. https://arxiv.org/pdf/2511.17826

**Verifiable matrix multiplication**
- Freivalds' algorithm. https://en.wikipedia.org/wiki/Freivalds%27_algorithm
- Thaler. An Optimal Interactive Proof for Matrix Multiplication. https://people.cs.georgetown.edu/jthaler/OptimalMatMult.pdf ; Time-Optimal IPs, arXiv:1304.3812
- zkCNN. IACR ePrint 2021/673. https://eprint.iacr.org/2021/673.pdf
- Plonky2 deep dive. https://polygon.technology/blog/plonky2-a-deep-dive ; small fields: https://blog.icme.io/small-fields-for-zero-knowledge/
- Lasso/Jolt FAQ (a16z). https://a16zcrypto.com/posts/article/a-technical-faq-on-lasso-jolt-and-recent-advancements-in-snark-design/

**PoW hardware-leveling lineage (what v4 inverts)**
- Ethash / Dagger-Hashimoto. https://golden.com/wiki/Dagger_hashimoto
- ProgPoW EIP-1057. https://eips.ethereum.org/EIPS/eip-1057 ; ProgPoW: https://github.com/ifdefelse/ProgPOW
- RandomX. https://github.com/tevador/RandomX ; Trail of Bits review: https://blog.trailofbits.com/2019/07/02/state/

**Fast matrix multiplication (Strassen caveat)**
- Strassen algorithm. https://en.wikipedia.org/wiki/Strassen_algorithm ; Strassen on GPUs (ACM TOMS). https://dl.acm.org/doi/abs/10.1145/3372419

**Post-quantum signatures (unchanged subsystem)**
- NIST FIPS 203/204/205 issuance. https://www.federalregister.gov/documents/2024/08/14/2024-17956/
- ML-DSA (FIPS 204) overview. https://www.encryptionconsulting.com/education-center/ml-dsa-fips-204/
- NIST SP 800-208 (stateful hash-based sigs) & IR 8105 (post-quantum crypto / Grover rationale).

**Cross-generation hardware (§P)**
- RTX Blackwell whitepaper (5090/5080 dense INT8). https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf ; Ada whitepaper (4090). https://images.nvidia.com/aem-dam/Solutions/geforce/ada/nvidia-ada-gpu-architecture.pdf ; GA102 whitepaper v2.1 (3090). https://www.nvidia.com/content/PDF/nvidia-ampere-ga-102-gpu-architecture-whitepaper-v2.1.pdf
- A100 datasheet. https://www.nvidia.com/content/dam/en-zz/Solutions/Data-Center/a100/pdf/nvidia-a100-datasheet-nvidia-us-2188504-web.pdf ; B200 datasheet. https://www.primeline-solutions.com/media/categories/server/nach-gpu/nvidia-hgx-h200/nvidia-blackwell-b200-datasheet.pdf ; Hopper whitepaper. https://www.advancedclustering.com/wp-content/uploads/2022/03/gtc22-whitepaper-hopper.pdf
- Apple M5 / Pro / Max newsroom. https://www.apple.com/newsroom/2025/10/apple-unleashes-m5-the-next-big-leap-in-ai-performance-for-apple-silicon/ ; https://www.apple.com/newsroom/2026/03/apple-debuts-m5-pro-and-m5-max-to-supercharge-the-most-demanding-pro-workflows/ ; Apple silicon (Wikipedia). https://en.wikipedia.org/wiki/Apple_silicon ; A19/M5 Neural Accelerator microbenchmark. https://tzakharko.github.io/apple-neural-accelerators-benchmark/

**btxprice / compute accounting (§Q)**
- btxprice valuation model. https://btxprice.com/valuation-model ; btxprice.com. https://btxprice.com
- H100 rental (2026): https://intuitionlabs.ai/articles/h100-rental-prices-cloud-comparison · https://getdeploying.com/gpus/nvidia-h100 · https://www.thundercompute.com/blog/nvidia-h100-pricing · https://www.cloudzero.com/blog/h100-gpu-cost/ · https://www.spheron.network/blog/gpu-cloud-pricing-comparison-2026/

**FPGA/ASIC economics (§S)**
- Intel Stratix 10 NX ("Beyond Peak Performance"). https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/a1153843-beyond-peak-performance-white-paper.pdf ; IEEE FCCM 2021. https://ieeexplore.ieee.org/document/9415606/
- AMD Versal AI Core. https://www.amd.com/en/products/adaptive-socs-and-fpgas/versal/ai-core-series.html ; AMD VCK5000. https://www.amd.com/en/products/adaptive-socs-and-fpgas/evaluation-boards/vck5000.html ; HPCwire VCK5000. https://www.hpcwire.com/2022/03/08/amd-xilinx-takes-aim-at-nvidia-with-improved-vck5000-inferencing-card/
- Google Cloud TPU v6e. https://docs.cloud.google.com/tpu/docs/v6e ; NVIDIA Turing whitepaper. https://images.nvidia.com/aem-dam/en-zz/Solutions/design-visualization/technologies/turing-architecture/NVIDIA-Turing-Architecture-Whitepaper.pdf
- Chip design cost (NRE). https://semiengineering.com/big-trouble-at-3nm/ · https://semiengineering.com/what-will-that-chip-cost/

## Appendix C — Open calibration items (must be resolved before mainnet activation)

1. **Genesis/bootstrap difficulty** for the n=4096 INT8 work unit — requires benchmarking on reference H100/H200/5090 hardware.
2. **s8 operand sampling** — pin the seed→`[-125,125]` rejection-sampling PRF and test vectors (k = 1 baseline; no prime set needed unless the optional §B.3 CRT variant is ever enabled).
3. **Cross-vendor INT8 determinism test vectors** — generate a pinned reference (independent implementation) before writing consensus code, mirroring v3's TV1–TV6 discipline.
4. **n final value** — confirm n = 4096 (or ≤ 8192) meets the < 100 ms verification target and per-nonce cadence on reference hardware. Per §0.7/§D.5 the launch datacenter lever is INT8 tensor-core compute + energy, not a VRAM gate. **Capacity gate: RESOLVED-NEGATIVE (§L.4)** — no verification-preserving capacity/bandwidth/working-set gate exists (verifier-linearity collapse + selection-filtering + batch-streaming winner-recompute); this is closed, not a deferred launch item.
5. **Freivalds soundness field & round count** — confirm q = 2⁶¹−1 (or GF((2³¹−1)²)) with R = 3 (§D.3); do NOT use the composite CRT modulus (§D.2).
6. **Payload profile** — confirm the compressed-sketch default (§E.1) vs the full-C strict-binding alternative (§0.7); if full-C is chosen, land the §H.3 message/`MAX_SIZE` plumbing.
7. **DoS verify-budget retune** for O(n²) at the chosen n (§E.4, §I.5).
8. **Difficulty work-unit** — calibrate the one-time ASERT rescale (§I.4) against the sketch work unit n³·(2/b), not naïve n³ (§E.3).
9. **Committed-object definition — RESOLVED (k = 1).** The baseline is a single exact-integer s8 matmul: dense pseudorandom s8 operands `A, B ∈ [-125,125]`, exact INT32 product `C = A·B` (native `s8×s8→s32`), committed via the sketch and Freivalds-verified over `q = 2⁶¹−1` (§0.7 "Resolved", §D.3). The k-prime CRT scheme (§B.3/§B.5) is demoted to an optional, off-by-default compute-multiplier (each lane a separate exact-integer GEMM + per-lane q-Freivalds, ×k verify cost). Remaining sub-item: decide whether to keep the §B.3 CRT text as a documented optional variant (current choice) or delete it for a leaner spec.
10. **Sketch tile b = 8 — RESOLVED, with confirmation items (§K.2a/§L.2).** b was set 16 → 8 so the optimal-miner arithmetic intensity `AI_opt = 2n/b = 1,024` clears every INT8 roofline ridge. Confirm on real kernels: (a) bench the b=8 verify path (2 MiB payload SHA + R=3 Freivalds) on reference CPUs against the 300 ms budget; (b) empirically confirm `AI_opt ≥ ridge` on real H100/B200/4090 IMMA kernels (the L2-residency assumption for the m×n intermediates); if measured AI falls short (write-traffic spill), b = 4 (8.4 MiB payload) is the fallback with the §I.5 DoS retune.
11. **Pin the balanced-s8 `U, V` derivation** and its test vectors (normative dtype, §0.7/§E.1): `U·A`, `B·V` must be native IMMA GEMMs; the m×m stage exact 64-bit integer / mod-q.
12. **Operand-expansion XOF** — pin the seed→operand PRF (ChaCha8/12-class recommended); single-thread regeneration of the 2n² operand bytes must hold the 15–35 ms envelope (part of the §I.5 verify budget).
13. **ρ launch disclosure (monitoring, never a parameter)** — re-measure consumer/datacenter AI-rental centrals at activation and recompute the price-robust floor ratio ρ (§S.4.6) for the launch disclosure; refresh quarterly with timestamps.

---

## Appendix D — Optional k > 1 CRT compute-multiplier variant (complete specification)

This appendix fully specifies the optional, off-by-default construction that was resolved out of the baseline in §0.7 (formerly the open "Appendix C-9" item). The **normative v4 baseline is k = 1** — a single exact-integer s8 matmul (§0.7, §D.3). Everything here is a *documented alternative* that a future governance retarget may enable by setting `nMatMulV4PrimeCount = k > 1`; it is not active at launch. It is documented in full so the choice is a switch, not a redesign.

### D.1 Purpose and when it would be used

The baseline per-nonce work unit is one dense n×n INT8 GEMM (§A.6/§E.3). If a future network wants to **raise the per-nonce compute by an integer factor k without enlarging n** (e.g. to keep verification/payload at the n = 4096 point while demanding more work per nonce, or to widen the hardware gap by forcing k concurrent GEMMs and thus k× the on-device tensor pressure), the CRT variant multiplies compute by exactly k. It is strictly a *compute multiplier*: it changes neither soundness (supplied by the verification prime q, §D.3) nor determinism (each lane is exact-integer). Prefer raising n (within the §D.5 verification budget) or difficulty first; reach for k > 1 only when n is already at the verification ceiling and more per-nonce work is still wanted.

### D.2 Construction

Fix `k` distinct small primes `p_1 … p_k`, each `< 2⁸`, so a balanced residue mod `p_i` fits a signed INT8 operand. The reference set (also the `matmul::field::V4_PRIMES` constant, active only when k > 1):

```
p_1 = 251,  p_2 = 241,  p_3 = 239,  p_4 = 233
M   = ∏ p_i = 3,368,562,317 ≈ 2^31.65     (used only for the digest-alphabet framing, not for verification)
```

Per nonce, derive **k independent operand pairs** `(A⁽ⁱ⁾, B⁽ⁱ⁾)` from the header seeds (extend the §H.4 preimage with the lane index `i` as an extra domain byte), each a dense pseudorandom s8 matrix with entries in `[-125, 125]` (balanced residues; `p_1 = 251` bounds the range, so all lanes share the `[-125,125]` domain and the §B.4 overflow bound `|C⁽ⁱ⁾_jl| ≤ n·125² = 15,625·n < 2³⁰`). Compute the **k exact-integer lane products**:

```
C⁽ⁱ⁾ = A⁽ⁱ⁾ · B⁽ⁱ⁾      (native s8×s8→s32, exact INT32, no modular reduction) for i = 1..k
```

These are `k` independent, standard INT8 GEMMs with no data dependence — they parallelize perfectly across SMs or devices (this is the tensor-core analogue of v3's "split16" 4×-DGEMM idea; §B.3). The **committed object** is the concatenation of the k lane sketches (default payload) or the k full lane products (strict-binding payload):

```
digest = H( σ_v4 ‖ Ĉ⁽¹⁾ ‖ Ĉ⁽²⁾ ‖ … ‖ Ĉ⁽ᵏ⁾ ),   Ĉ⁽ⁱ⁾ = U · C⁽ⁱ⁾ · V   (per-lane sketch, §E.1)
```

There is **no CRT reconstruction to Z_M** anywhere in mining or verification — each lane stands alone as an exact-integer product. (The primes are merely a convenient, distinct way to derive k lane operand sets; any k independent s8 operand derivations would serve identically. The `M` value survives only as the notional digest alphabet.)

### D.3 Verification (per-lane Freivalds over q)

Verification runs the §D.3 exact-integer / `q = 2⁶¹−1` Freivalds **once per lane**: for each lane `i` and each of `R` rounds, derive `r` from `H(matmul_digest ‖ round ‖ i)` and check

```
C⁽ⁱ⁾ · r  ≡  A⁽ⁱ⁾ · (B⁽ⁱ⁾ · r)   (mod q)
```

regenerating `A⁽ⁱ⁾, B⁽ⁱ⁾` from the seeds on the fly (O(n²) each). Each lane inherits the baseline per-round soundness `≤ 1/q` (full-C) or `≤ 2/q` (sketch); a corrupted lane is caught by that lane's rounds with the same 2⁻¹⁸³/2⁻¹⁸⁰ margin at R = 3. **There is no composite-modulus check and no `Z_M` reconstruction** — the §D.2 trap is avoided because verification never leaves the per-lane exact-integer domain. This is the crucial correctness point that makes the variant sound.

### D.4 Costs (everything scales ×k)

| Quantity | Baseline (k = 1) | CRT variant (k lanes) |
|---|---|---|
| Per-nonce compute | 2n³ ops (full) / ~2n²m (sketch) | **k ×** baseline |
| Payload | 2 MiB sketch (b=8, n=4096) | **k ×** (e.g. k=4 → 8 MiB — still within the §D.5 few-MiB budget and existing 16 MB message limit) |
| Verification | R rounds, ~0.14–0.28 s (§I.5) | **k ×** rounds → ~k × time (k=4 → ~0.6–1.1 s — at the §D.5 ceiling; do not combine k=4 with n>4096) |
| Operand regen on verify | 2n² PRF | **k ×** (2kn²) |
| Determinism | exact per §B.6 | identical, per lane |

The device *ratios* of §K.3 are unchanged (every device does k× more of the same INT8 GEMM), so the datacenter lever and pooled economics are unaffected — only the absolute work unit and the verification cost move by k. The binding constraint is the §D.5 verification budget: `k · (n/512)² · R` per-round cost must stay under the ~1 s single-thread ceiling, which caps `k·n²` and is why k > 1 is incompatible with n at its own maximum.

### D.5 Consensus wiring (delta from the baseline)

- `nMatMulV4PrimeCount = k` (§G.2). k = 1 disables the variant (baseline). k > 1 enables it; `V4_PRIMES` must list ≥ k distinct primes < 2⁸; `static_assert` that k ≤ `V4_PRIME_COUNT`.
- Seed derivation (§H.4): append the lane index `i ∈ [0,k)` to the `DeterministicMatMulSeedV4` preimage so the k operand pairs are independent.
- Payload (§H.2): `matrix_c_data` carries the k concatenated lane sketches (or full lane products); size = k × the baseline. Range-check every word.
- Verification (§I.2): the `CheckMatMulProofOfWork_V4ProductCommitted` cascade loops the per-lane q-Freivalds over i = 1..k; all lanes must pass. DoS budgets (§I.5) scale the per-verification cost by k (retune `nMatMulV4GlobalVerifyBudgetPerMin` accordingly).
- Difficulty (§I.4/§M.4): the work unit becomes `k ×` the baseline sketch unit; calibrate the fork rescale against it.

### D.6 Recommendation

**Leave k = 1.** The baseline single exact-integer matmul already achieves every stated objective — SHA demoted to seeding/sealing, matmul as the sole per-nonce cost, INT8 tensor-core datacenter lever, cheap O(n²) Freivalds verification. The CRT variant buys only a per-nonce compute multiple at a proportional verification-cost multiple, which difficulty adjustment achieves for free without touching verification cost. It is specified here so that, should a future need arise (e.g. a deliberate work-unit enlargement that must avoid growing n or the payload dimension), enabling it is a parameter change with a fully-documented, sound verification path — not a re-architecture.
