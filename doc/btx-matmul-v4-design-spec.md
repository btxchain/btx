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
| 1 | Consumer 5090 is the most efficient miner, at parity with H100/H200 | Invert via INT8 tensor-core dense matmul at large n + memory-capacity gate; datacenter INT8 FLOPS + HBM win | §K, §L, §M |
| 2 | "Increase the compute level while washing out the retail guys" | Matmul is the sole per-nonce cost; difficulty tracks tensor-FLOPS; n scaled to exceed consumer VRAM | §A, §K, §M |
| 3 | SHA-256 share is enormous; matrix share shrinks as difficulty rises | **Remove the pre-hash epsilon gate**; SHA limited to seed + sealing; one dense matmul per nonce | §A, §C, §I |
| 4 | "Hashing takes up way more of the mining effort than GPU compute" | Same as #3 — matmul runs on every nonce; SHA cost becomes negligible per attempt | §A, §C |
| 5 | Scale matrix size n = 512 → 4096+, deterministic INT8 | n = 4096 default (scalable); INT8/CRT field on tensor cores; exact INT32 accumulation | §A, §B, §M |
| 6 | ZK layer "mandatory"; limit SHA to seed/sealing; matmul dominant; Plonky2; large-n re-verification infeasible | SHA limited to seed/sealing; matmul dominant; **Freivalds O(n²) makes re-verification feasible so ZK is optional, not mandatory**; Plonky2 analysed as optional module | §A, §D, §F |
| 7 | Retain ML-DSA / SLH-DSA for quantum resistance | Untouched — orthogonal subsystem | §0.4, §J |
| 8 | "If we can't efficiently do Freivalds it is a problem" | Deterministic Freivalds over an independent 61-bit prime on the exact-integer product (§D.3 — never over the composite CRT modulus, §D.2); R = 3 rounds for ≤ 2⁻¹⁸⁰; ≈ 0.1 s verify at n = 4096 | §D |
| 9 | Target datacenters (H100/H200); let them win more blocks | INT8 tensor-FLOPS + HBM-capacity design gives datacenter the best cost-per-block | §K, §M |
| 10 | Must scale compute; worst case is compute going down via memory-hardness | Compute-bound above the roofline ridge; memory used as *capacity gate*, never *bandwidth bottleneck* | §L |
| 11 | May need to abandon SHA-256 (consumer excels at it) | SHA-256 demoted to seed derivation + block sealing; it is no longer the mining bottleneck | §A, §C |
| 12 | Don't break the chain / past blocks | Height-gated hard fork; legacy blocks validated under v3 rules | §0.4, §G, §J |
| 13 | CMP cards / old hardware / cheap electricity dumping price (2 CMP ≈ 1 5080) | CMP-class cards lack low-precision tensor GEMM (CMP-170HX FP32 = 0.39 TFLOPS) and are excluded by the INT8-tensor + VRAM-gate design | §K, §N |
| 14 | Advisor: make it memory-bound to limit low-VRAM GPUs | Adopted **only as a capacity gate**, not as bandwidth-hardness; design stays compute-bound (resolves the tension in #10) | §L, §M |
| 15 | Change consensus immediately; give requirements | This document; clean hard-fork swap with a complete implementation checklist | §G–§J |
| 16 | Consumer/Apple users must still pool massively and earn rewards, not be shut out | v4 *orders* by INT8 throughput, never hard-excludes; share-based pooling over cheap Freivalds-verified shares pays proportional-to-compute (PPLNS/PPS); Apple M5 re-enters with a genuine INT8 path | §O.1, §O.2 |

---

## 0.6 Document structure

- **§A–§C** — Core algorithm, INT8/CRT arithmetic, anti-amortisation invariants *(the work function)*
- **§D–§F** — Freivalds verification, data availability & node tiers, optional ZK *(the check)*
- **§G–§J** — Consensus params, header/serialization, validation/mining/difficulty wiring, file-by-file hard-fork checklist *(the integration)*
- **§K–§N** — Hardware economics, compute-vs-memory reconciliation, parameter calibration, migration & risk register *(the economics)*
- **§O** — Evolving consumer matmul hardware (Apple M5) & inclusive pooling *(who can still participate)*
- **Appendices** — Test vectors & test matrix, glossary, references

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
| **Sketch (default)** — ship `Ĉ = U·C·V ∈ 𝔽_q^{m×m}`, `m=n/b`, dense σ-derived `U,V`; digest `H(σ‖Ĉ)`; sketch-Freivalds `xᵀĈy ≟ (Uᵀx)ᵀA(B(Vy))` (§E) | **~512 KiB** (b=16) | **~0.1 s** | dense INT8 `n×n×2m` GEMM ≈ `n³·(2/b)` per nonce (§E.3) | **fits existing 16 MB/24 MB limits — no §H.3 protocol-limit changes needed** |
| Full-C (strict-binding alternative) | 64 MiB | ~0.3 s | strict `Θ(n³)` (Freivalds pins all n² entries) | requires the §H.3 message/`MAX_SIZE` plumbing |

Both profiles verify in O(n²) via the `q = 2⁶¹−1` Freivalds of (2) and use the product-committed digest form of v3's `ComputeProductCommittedDigest` (`src/matmul/transcript.cpp:485`). Where §A/§H describe a mandatory 64 MiB full-`C` payload, treat that as the *alternative* profile; the **default is the sketch**, which also removes the need to raise `MAX_PROTOCOL_MESSAGE_LENGTH`/`MAX_SIZE`.

**Honest work-binding disclosure (§E.3):** under the sketch, the optimal miner computes `Ĉ = (U·A)(B·V)` directly at ≈ `n³·(2/b)` MACs (a factor `b/2` = 8× below full `n³` at b=16) — it need not form all of `C`. This does **not** weaken security (no invalid block passes; §E.3) and does **not** reintroduce SHA or any non-tensor shortcut: the work remains a **dense INT8 tensor-core GEMM** of the same hardware profile, so the datacenter advantage (§K) and the "compute, not hashing, is the work" fix are fully intact. It only means the per-nonce *work unit* is `n³·(2/b)`, not `n³`; **difficulty calibration (§I.4) and the §M work-unit/economics MUST use the `n³·(2/b)` figure.** Strict `n³` binding is available by choosing the full-C profile or the optional ZK module (§F.4d); it is not required to meet any stated objective.

**Resolved (was Appendix C-9) — the compute is a single exact-integer INT8 matmul, k = 1.** The normative baseline multiplies **one** pair of dense pseudorandom **s8 operand matrices** `A, B` (entries seed-derived in `[-125, 125]`) into the **exact integer product** `C = A·B` — which is precisely what an `s8×s8→s32` tensor-core GEMM produces natively, with `|C_ij| ≤ 15,625·n < 2³⁰` for every header `n ≤ 65,535` (§B.4), so `C` is an exact INT32 matrix with no modular reduction. Freivalds then runs over the independent prime `q = 2⁶¹−1` on that exact integer product (2). This is the only construction that keeps verification at the cheap R = 3 / 2⁻¹⁸³ point: the k-prime CRT scheme of §B.3 leaves the product defined only mod `M`, for which no single exact integer exists to check over `q`, and per-plane checking would need ~17 small-field rounds per lane (blowing the §D.5 budget). **The CRT/multi-prime construction (§B.3, §B.5) is therefore demoted to a non-normative, optional _compute-multiplier variant_:** each extra prime is one more independent s8 GEMM whose own exact-integer lane product is committed and Freivalds-verified over `q` separately, multiplying both per-nonce work and verification cost by `k`. It is off by default (k = 1). This supersedes every `k = 4` / `nMatMulV4PrimeCount = 4` reference in §B.3, §G.2, §M.2, §M.4, and the "CRT-reconstruct to Z_M" step in §D.3.

### Normative launch parameters (supersede any divergent example in §A–§N)

| Symbol | Value | Notes |
|---|---|---|
| `n` (dimension) | **4096** all production nets; **≤ 8192** only after the §H.3 serialization work (full-C profile) or trivially under the sketch | §D.5: n = 4096 baseline meets the <100 ms target; n = 8192 ≈ 1 s conservative (ceiling); **n ≥ 16384 is EXCLUDED** — fails the single-thread verify budget regardless of miner capability. |
| `k` (compute lanes) | **1** (baseline) | Single exact-integer s8 matmul; s8 operands in `[-125,125]` give exact INT32 accumulation for n ≤ 137,438 (§B.4). k > 1 (the §B.3 CRT variant) is an optional compute-multiplier at ×k verify cost, off by default. |
| `q` (verification prime) | **2⁶¹ − 1** (or `GF((2³¹−1)²)`) | Independent of the compute field; gives 1/q per-round soundness (§D.3). |
| `b` (commit/sketch tile) | **16** (n ≤ 8192), 32 at larger n | Sets sketch dimension m = n/b and payload m²·8 bytes (§E.1). |
| `R` (Freivalds rounds) | **3** (2 on regtest) | Error ≤ 2⁻¹⁸³ over q. |
| Payload (default) | **~512 KiB** sketch at n=4096, b=16 | Within existing limits; no protocol-message-size fork needed. |
| Verify budget | **< 100 ms target, < 1 s hard ceiling**, single-thread | Binds n from above (§D.5). If the memory-gate (§M) wants more hardware footprint, it must come from required-resident working set / batching — NOT from raising n. |

### On the memory-capacity gate (§L/§M)

Per (1) and §D.5, `n` is capped by the verification budget, so a *single-matmul* VRAM gate (which needs n ≈ 49k–74k, far past the verify ceiling) is out. Any capacity-gate construction that makes block validity depend on more than the winning nonce's product must first be shown to preserve O(n²) verification; none is in the launch consensus. At launch the datacenter advantage rests entirely on the **INT8 tensor-core compute lever** (§K: ~5× Hopper, ~11× Blackwell over RTX 5090; CMP-class and M4 excluded by lack of low-precision tensor GEMM), which is fully compatible with cheap sketch verification. A verification-preserving capacity gate is filed as future hardening (Appendix C).

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
| Dimension, tile | n=4096, b=16, N=256, m=256 |
| Channels | k=4, {251,241,239,233}, M=3,368,562,317 |
| Operand storage | 8 residue matrices × n² B = **128 MiB**/nonce (s8 balanced, residue-planar) |
| MAC count | full product k·n³ = 4·2^36 ≈ 2.75×10¹¹ INT8 MACs (~5.5×10¹¹ ops)/nonce; optimal sketch miner ≈ k·2n²m ≈ 3.4×10¹⁰ MACs (§E.3) — sub-ms at INT8 tensor-core peak either way |
| Accumulator peak | 4096·125² = 6.4×10⁷ < 2^31−1 (balanced residues, §B.4); headroom ×33.6; no mid-K reduction |
| Payload | sketch Ĉ: 8·m² = **512 KiB** (default, §E.1); full-C alternative: n² int32 = 64 MiB |
| Commit overhead | ≪ 1% of GEMM MACs |

---

## C. Anti-amortization and hardness invariants

v4's posture: **every accepted digest certifies one full dense matmul, and no cheaper computation produces an acceptable digest.**

- **I1 — Nonce-fresh operands.** `seed_A/seed_B` commit to `(hashPrevBlock, height, nVersion, hashMerkleRoot, nTime, nBits, nNonce64, matmul_dim, parent_mtp, which)` (A.2). No operand/product/partial shared across nonces; extends the v3 nonce-fold fix.
- **I2 — Full-rank dense operands.** i.i.d. uniform per channel; no rank parameter, no `noise::Generate`, no structured component.
- **I3 — No reusable additive split.** v4's product has no term independent of `nNonce64`; the clean-products cache has nothing to hold.
- **I4 — (non-normative, see §0.7).** Schedule-pinning via an intermediate transcript is *not used* in v4; work-forcing comes from I1–I3 + Freivalds on the final product, keeping verification O(n²). Retained here only to document why v3's linear-compression replay has no v4 analogue: there is no cacheable additive term to compress.
- **I5 — No pre-hash lottery.** `ε=0`; every nonce runs the dense GEMM; the cheapest nonce costs Θ(k·n²·m) (sketch profile; Θ(k·n³) full-C, §E.3), not one SHA-256d.
- **I6 — Bit-exact arithmetic.** Acceptance requires exact digest reproduction (B.6); approximate/low-precision "estimate then patch" cannot substitute.

Shortcut-to-invariant map:

| v3 shortcut | v3 cost effect | v4 invariant that closes it |
|---|---|---|
| Pre-hash epsilon gate | matmul on 2⁻¹⁸ of nonces; PoW → SHA lottery (`src/pow.cpp:2688-2697`) | **I5** |
| Low-rank noise amortization | O(n²r) via cached AB + factorized corrections, ~64× (`src/matmul/noise.cpp:144-157`; `transcript.cpp:313-399`) | **I2 + I3** |
| Cross-nonce A,B reuse (pre-125,000) | per-tip operands amortized, ~12.8× (`src/pow.cpp:58-62`) | **I1** |
| Linear transcript-compression replay | `(uᵀA)(Bv)` factorization, O(b²)/step (`transcript.cpp:362-392`) | **I2+I3** (no cacheable term) + digest on final C only |
| Strassen / sub-cubic | ~(7/8)^levels multiply savings in principle | non-remunerative: Freivalds demands the correct dense C; s8-range + constant-factor barriers (A.6) |
| Reduced-precision approximation | fast approximate product | **I6** — digest equality demands bit-exact C |
| Sketch evaluation shortcut `(U·A)(B·V)` (v4-specific) | factor b/2 = 8 below full n³ (§E.3) | acknowledged, not closed: same dense INT8 tensor-GEMM profile, priced into difficulty (§0.7-(3), §I.4); strict n³ binding needs full-C or ZK (§F.4d) |

Together I1, I2, I3, I5, I6 make the marginal cost of a nonce equal the average cost — a dense INT8 tensor-core GEMM of `k·n³·(2/b)` MACs under the default sketch payload (`k·n³` under full-C; §E.3) — with all identified v3 amortization channels structurally absent rather than parameter-disabled, and with verification held at O(n²).

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

**v4 ships only the compressed per-block commitment**: the sketch **Ĉ = U·C·V ∈ 𝔽_q^{m×m}**, m = n/b, where U (m×n) and V (n×m) are dense σ-derived pseudorandom matrices (the v4 generalization of `DeriveCompressionVector`/`CompressBlock`, `src/matmul/transcript.cpp:185-230`), words canonical mod q = 2⁶¹−1 (8 bytes). The header digest is `matmul_digest = H(σ ‖ Ĉ)`, recomputed by every verifier in O(m²). Recommended and normative network-wide: **b = 16 for n ≤ 8192 (512 KiB / 2 MiB), b = 32 at larger n** (`nMatMulV4TranscriptBlockSize = 16`, §G.2) — always within the few-MiB budget, versus the out-of-bounds 64 MiB–4 GiB of full C. The choice balances the two b-sensitive quantities: the payload 8·(n/b)² shrinks with b, while the §E.3 work-shortcut factor b/2 (and the coarseness of the commitment) grows with it. At n = 4096, b = 16 gives a 512 KiB payload — well inside the existing 16 MB message limit — with a modest 8× shortcut; b = 64 would cut the payload to 32 KiB but widen the shortcut to 32× and shrink the commitment to m = 64; b = 8 would tighten the shortcut to 4× at a 2 MiB payload. 512 KiB with an 8× shortcut is the chosen balance.

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

Any linear commitment of C admits an algebraic evaluation shortcut: Ĉ = (U·A)·(B·V) can be computed in ≈ 2n²m + nm² MACs (U·A and B·V at n²m each, their m×n by n×m product at nm²) instead of the honest n³ + n²m + nm², a factor ≈ n/(2m) = b/2 (8× at b = 16; 7.8× counting the lower-order terms). Stated plainly:

- The **de-facto per-nonce work unit** under this payload is a dense INT8 n×n×2m GEMM (2n²m ≈ 8.6×10⁹ MACs per CRT lane at n = 4096, b = 16) — same tensor-core, same bandwidth profile as the full product, 1/8 the volume. Difficulty calibration and the memory-gate sizing in §M MUST assume this optimal algorithm, not the naïve n³ figure.
- v3 does not have this gap only because it ships full C and Freivalds pins all n² entries. Restoring *strict* n³ binding requires full-C payload (out of DA bounds above) or a proof of full evaluation — the optional ZK module of §F.4(d).
- Verification soundness is unaffected: no invalid block passes; the gap concerns only how much work a *valid* block proves. The work remains a dense INT8 tensor-core GEMM, so the datacenter lever (§K) and the "compute not hashing" fix are intact.

### E.4 Node tiers and DoS budgets

| Tier | Per-block cost | Storage |
|---|---|---|
| Mining | ≈ 2n²m INT8-MACs per lane per nonce (GPU tensor cores; §E.3) + digest hash | working set per §M |
| Consensus-validating | full §E.2 check: ≈ 0.1–0.2 s CPU (n = 4096) | payload to prune depth 10 000 (`src/consensus/params.h:151`): 10⁴ × 512 KiB ≈ **5 GiB rolling** |
| Economic (exchange/merchant) | full check over recent window only (`nMatMulValidationWindow = 1000`, `:145`), assumevalid beneath | ≈ 500 MiB rolling |
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
| Extra payload | 512 KiB sketch | ≈ 43 KB proof |
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
| `nMatMulV4TranscriptBlockSize` | uint32 | 16 | 16 | 16 | 16 | 16 | 16 | `b`; product-commit/sketch tile, m = n/b (§0.7, §E.1). |
| `nMatMulV4FreivaldsRounds` | uint32 | 3 | 3 | 3 | 3 | 3 | 2 | `R`; Freivalds rounds over q = 2⁶¹−1 (§0.7-(2), §D.3). |
| `nMatMulV4DigestScheme` | uint32 | 1 | 1 | 1 | 1 | 1 | 1 | Digest scheme (1 = SHA256d over the σ_v4-derived dense sketch Ĉ = U·C·V of exact-INT32 C, §E.1). |
| `nMatMulV4AsertRescaleNum` | uint32 | 1 | calibrated‡ | ‡ | ‡ | 1 | 1 | One-time ASERT rescale num at fork (I.4). |
| `nMatMulV4AsertRescaleDen` | uint32 | 1 | calibrated‡ | ‡ | ‡ | 1 | 1 | Rescale den. |
| `nMatMulV4GlobalVerifyBudgetPerMin` | uint32 | 16 | 16 | 16 | 16 | 32 | 1024 | Global expensive-verify budget above fork (I.5). |
| `nMatMulV4PeerVerifyBudgetPerMin` | uint32 | 4 | 4 | 4 | 4 | 8 | 1024 | Per-peer budget. |
| `nMatMulV4MaxPendingVerifications` | uint32 | 4 | 4 | 4 | 4 | 8 | 16 | Pending cap (4 × 512 KiB = 2 MiB bound at n=4096 sketch; 256 MiB under full-C). |

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

> **Profile note (§0.7-(3)):** H.2–H.3 specify the **full-C (strict-binding) profile**. Under the **default sketch profile** the payload is `Ĉ ∈ 𝔽_q^{m×m}` (8·m² bytes = 512 KiB at n = 4096, b = 16; §E.1), which fits every existing size limit — none of the H.3 size-limit changes are then required.

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
- Under the full-C profile the 64 MiB payload makes full-block relay the dominant bandwidth cost; the default 512 KiB sketch keeps relay tx-dominated. DoS budgets (I.5) and the pending cap are sized against the shipped profile.

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

### I.5 DoS budget retuning

Baseline: v3's measured bench is 569.4 µs **per round** at n=512 (`MatMulFreivaldsN512R2`, §D.4); per-round cost scales `(n/512)²`.

| Component (n=4096, R=3, k=1, sketch payload) | Cost |
|---|---|
| Freivalds/round (base extrapolation) | 569.4 µs × 64 ≈ **36.4 ms** |
| Freivalds total (R=3; ×2 conservative for 61-bit lanes) | ≈ **109–219 ms** |
| Digest over 512 KiB sketch (SHA256d) | < 1 ms (full-C 64 MiB: 45–130 ms) |
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

**Editor's load-bearing findings:** (1) v3 payload validators cap dim at 2048 (`pow.cpp:137`, `params.h:143`), *below* v4's 4096 — height-selected bounds are mandatory. (2) Under the full-C profile the 64 MiB C payload at n=4096 exceeds `nMaxBlockSerializedSize` (24 MB) and `MAX_PROTOCOL_MESSAGE_LENGTH` (16 MB), and n=8192 exceeds the `MAX_SIZE` element cap — H.3/J#7-8 are fork deliverables **only if** full-C is chosen; the default 512 KiB sketch requires none of them (§0.7-(3)).

---

## K. Hardware economics & the datacenter lever

### K.1 Tensor throughput landscape (dense, deterministic-relevant dtypes)

All figures are **dense** peak throughput; 2:4 structured-sparse peaks (marked \*) are shown for completeness but are irrelevant to v4, since PoW matrices are full-rank dense by construction.

| Device | FP64 | BF16/FP16 | FP8 | INT8 (s8×s8→s32) | Memory | Bandwidth |
|---|---|---|---|---|---|---|
| NVIDIA H100 SXM5 | ~60–67 TFLOPS | ~990 TFLOPS (1,979\*) | ~1,979 TFLOPS (3,958\*) | **~1,979 TOPS** (3,958\*) | 80 GB HBM3 | 3.35 TB/s |
| NVIDIA H200 | as H100 (same die) | as H100 | as H100 | **~1,979 TOPS** | 141 GB HBM3e | 4.8 TB/s |
| NVIDIA B200 | ~40 TFLOPS (cut vs Hopper) | 2,250 TFLOPS (4,500\*) | 4,500 TFLOPS (9,000\*) | **4,500 TOPS** (9,000\*) | 192 GB HBM3e | ~8 TB/s |
| GeForce RTX 5090 | — | 209.5 TFLOPS | ~400 TFLOPS | **~400 TOPS** (est.; 3,352 "AI TOPS" is sparse marketing) | 32 GB GDDR7 | 1.79 TB/s |
| GeForce RTX 5080 | — | 112.6 TFLOPS | ~225 TFLOPS | **~225 TOPS** (est.) | 16 GB GDDR7 | 0.96 TB/s |
| Apple M4 Max | — | 36.9 TFLOPS FP16 (GPU); ANE "38 TOPS INT8" dequantizes to FP16, true ~19 TFLOPS | n/a | **~19–37 TOPS effective** (no real INT8 speedup) | up to 128 GB unified | 546 GB/s |
| Apple M5 (10-core GPU, est.) | — | ~16–18 TFLOPS FP16 (GPU Neural Accelerators; no native BF16) | n/a | **~25–35 TOPS** (s8×s8→s32, est.) | up to 32 GB unified | 153 GB/s |
| Apple M5 Max (40-core GPU, est.) | — | ~70 TFLOPS FP16 (GPU Neural Accelerators) | n/a | **~110–140 TOPS** (s8×s8→s32, est.) | up to 128 GB unified | 460–614 GB/s |
| NVIDIA CMP 170HX (GA100, ex-Ethash) | — | ~42 TFLOPS FP16 | n/a | **~12.5 TIOPS** (integer ALU; no usable low-precision tensor GEMM) | 8 GB HBM2e | 1.5 TB/s |

Sources: [H100 datasheet](https://resources.nvidia.com/en-us-gpu/h100-datasheet-24306), [H200](https://www.nvidia.com/en-us/data-center/h200/), [B200](https://www.spheron.network/blog/nvidia-b200-complete-guide/), [Exxact](https://www.exxactcorp.com/blog/hpc/comparing-nvidia-tensor-core-gpus), [RTX 5090](https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/rtx-5090/), [5090 specs](https://www.spheron.network/blog/nvidia-rtx-5090-specs/), [Puget 5090/5080](https://www.pugetsystems.com/labs/articles/nvidia-geforce-rtx-5090-amp-5080-ai-review/), [Apple M4](https://en.wikipedia.org/wiki/Apple_M4), [M4 ANE](https://maderix.substack.com/p/inside-the-m4-apple-neural-engine-615), [CMP 170HX](https://niconiconi.neocities.org/tech-notes/nvidia-cmp-170hx-review/).

Two structural facts drive the design: (1) **the precision ladder is the lever** — at FP32/FP64 the datacenter-vs-consumer gap is small (Blackwell even cuts FP64), but at low precision it opens to 5–11× (BF16 B200/5090 ≈ 10.7×, H100/5090 ≈ 4.7×; FP8/INT8 B200/5090 ≈ 11×, H100/5090 ≈ 5×), and GeForce historically halves reduced-precision throughput with FP32 accumulate, widening the effective deficit; (2) **non-tensor devices fall off a cliff** — CMP 170HX has no usable low-precision tensor GEMM (~12.5 TIOPS ALU), and the Apple M4-generation ANE INT8 gives no real speedup — but the Apple M5 generation adds genuine in-GPU-core INT8→INT32 matmul units (§O.1), so M5-class silicon re-enters at its throughput tier rather than being excluded.

### K.2 The roofline argument

A dense n×n GEMM does 2n³ ops on Θ(n²) data, so `AI(n) = 2n³/6n² = n/3` ops/byte. At n=4096, AI ≈ 1,365 — 2.3–6× above every device's ridge point (H100 ≈ 591, B200 ≈ 563, RTX 5090 ≈ 223). Large-n dense GEMM is pinned against the **peak-FLOPS ceiling**, so per-nonce throughput ∝ the device's dense low-precision tensor throughput and nothing else. The device with the most INT8 TOPS wins, linearly. This inverts the v3 regime (n=512 cache-resident, SHA-lottery, integer ALUs — where Apple/CPU/CMP competed within small constant factors).

### K.3 Per-nonce INT8 advantage, quantified

Per nonce (n=4096, k=1): 2n³ ≈ 1.374·10¹¹ INT8 ops.

| Device | Dense INT8 (TOPS) | Time/nonce (peak) | Slowdown vs H100 | vs B200 |
|---|---|---|---|---|
| B200 | 4,500 | 30.5 µs | 0.44× | 1× |
| H100 / H200 | 1,979 | 69.4 µs | 1× | 2.3× |
| RTX 5090 | ~400 | 344 µs | **~4.9×** | **~11×** |
| RTX 5080 | ~225 | 611 µs | **~8.8×** | **~20×** |
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
| Memory-**capacity**-gated (working set must be resident; per-byte traffic negligible) | Binary admission test: below-threshold devices can't participate competitively; above-threshold compete purely on tensor FLOPS. | **Adopted (subject to §0.7 verification constraint)** |

**Rule: throughput = INT8 tensor FLOPS (compute-bound); admission = VRAM capacity (memory-gated); bandwidth is never binding.**

### L.2 Roofline / ridge-point reasoning

Attainable = `min(peak_FLOPS, AI·peak_bandwidth)`, ridge `AI* = peak_FLOPS/peak_bandwidth`; `AI(n) = n/3`:

| Device | Ridge AI\* | AI at n=4096 (1,365) | AI at n=16384 (5,461) |
|---|---|---|---|
| H100 | 591 | 2.3× above | 9.2× above |
| B200 | 563 | 2.4× | 9.7× |
| RTX 5090 | 223 | 6.1× | 24× |
| RTX 5080 | 234 | 5.8× | 23× |

Every n ≥ 4096 is comfortably compute-bound on every device, headroom growing linearly in n. Because consumer cards have lower ridge points, going bandwidth-bound would *help* them (and resurrect CMP); staying above the ridge keeps ranking strictly ordered by tensor TOPS. Minimum-traffic is the standard tiled-GEMM result (stage b_t×b_t tiles through shared memory, reuse each byte O(b_t)×, stream C once — cuBLASLt IMMA already does this).

### L.3 Capacity as a hard gate, not a treadmill

A capacity gate works only if the resident set is (a) provably necessary — recomputation must cost tensor FLOPS, so shedding memory costs proportional throughput — and (b) sized `32 GB (5090) < W < 80 GB (H100)`. Per-byte traffic to it stays O(n²) per O(n³) compute, so the gate consumes capacity without consuming the roofline. **Per §0.7, any capacity-gate construction must first be shown to preserve O(n²) verification; the launch consensus therefore relies on the INT8 compute lever (§K), with a verifiable capacity gate filed as future hardening.** As hardware improves, n/W are retargetable upward — compute scales up, never down.

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

*(Times shown are for the full n³ product; the optimal sketch miner runs at ×(2/b) = 1/8 of them, §E.3. Payload figures in the last column are full-C; the default sketch payload is 8·(n/b)² B — 512 KiB at n = 4096, b = 16, §E.1.)*

Per-nonce footprint alone does not gate 32 GB consumer VRAM until n ≈ 74,000 — where verification/payload are far past budget. **The single-matmul VRAM gate is therefore incompatible with cheap verification** (§0.7). Two consequences:

- **Launch (normative): n = 4096, single-C verification.** Compute-bound (AI ≈ 1,365, ≥ 2.3× every ridge), per-nonce ~0.1 ms on H100 → thousands of nonces per 90 s block, Freivalds verify ~0.15–0.3 s, payload 512 KiB sketch (64 MiB full-C alternative). The datacenter advantage is the ~5×/~11× INT8 compute lever (§K.3) plus the resident/thermal/scale-out edges of datacenter parts. n may rise to **8192** once the serialization limits (§H.3) are lifted, trading verification headroom for a larger work unit.
- **Future hardening (optional, non-launch): capacity gate.** A resident-C-window (hold m recent products, digest chained with random back-references so a dropped C must be recomputed) would gate 32 GB VRAM at moderate n. It is **excluded from the launch consensus** because it makes block validity depend on more than the winning nonce's C and must first be shown to preserve O(n²) verification (§0.7). Recorded in Appendix C.

**Recommendation: n = 4096, k = 1 (single exact-integer s8 matmul, §0.7), b = 16, sketch payload, Freivalds verification over q = 2⁶¹−1.** n=8192 is a governance-raisable option after the §H.3 plumbing lands; larger n, the optional k > 1 compute-multiplier (§B.3/§M.2), and the capacity gate are all deferred pending a verification-preserving construction / verification-budget headroom.

### M.2 k — compute lanes (baseline k = 1)

The normative baseline is **k = 1**: a single exact-integer s8 matmul (§0.7). Freivalds soundness is supplied entirely by the independent verification prime `q` (§D.3), so k plays no role in security. The optional §B.3 CRT variant sets k > 1 purely to multiply per-nonce compute: each extra lane is one more independent `s8×s8→s32` GEMM (+2n³ ops) with its own exact-INT32 lane product committed and Freivalds-verified over `q` — so both per-nonce work **and per-block verification cost** scale ×k (device *ratios* in §K.3 are unchanged, but the ×k verify cost eats the §D.5 budget, which is why k > 1 is off by default). Leave k = 1 unless a future retarget deliberately wants a larger work unit and can afford the verification headroom; prefer raising n (within §D.5) or difficulty first.

### M.3 b — commit tile size

C is committed via the dense sketch Ĉ = U·C·V, m = n/b (§E.1). b trades three quantities: (i) payload 8·m² = 8·(n/b)² bytes shrinks with b; (ii) the §E.3 work-shortcut factor b/2 grows with b; (iii) commitment granularity m² coarsens with b. Hash/commit cost must stay ≪ 1% of tensor time so the digest never becomes a v3-style SHA side-channel — satisfied at every candidate b, since the sketch is a by-product of the §E.3 optimal evaluation. **b = 16 network-wide at n = 4096** (§G.2): payload 512 KiB, shortcut 8×, m = 256; see §E.1 for the rejected b = 8 / b = 64 corners.

### M.4 Block time and work-unit sizing

Retain **90 s**. With the k = 1 baseline, the per-nonce work unit is the §E.3 sketch-optimal cost `W = 4n²m + 2nm² ≈ 2n³·(2/b)` ops (**not** naïve 2n³ — §0.7-(3), §I.4); the difficulty target on the product-committed digest tracks **aggregate network dense-INT8 TOPS**. Sketch-basis nonce rate `≈ ε·P_int8/W`: at n=4096, b=16 (m=256), ε=0.65, H100 ≈ 7×10⁴ nonces/s → ~6×10⁶/block (excellent variance). *(The §K.3 and §O per-device "nonces/s" columns are quoted on the conservative full-matmul reference basis 2n³ — ~8× lower — for illustration; the sketch shortcut scales every device's rate by the same ~8×, so device ratios and the datacenter/pooling economics are basis-invariant.)* Difficulty cadence/clamps carry over from v3, with the one-time fork rescale of §I.4. As successors raise P_int8, difficulty rises transparently; governance retargets n only when VRAM boundaries shift, not to chase FLOPS.

---

## N. Migration, mining ops & risk register

### N.1 Strategic pivot — stated explicitly

BTX's existing spec/site optimize for commodity fairness: viability "on any machine from the last decade" (`doc/btx-matmul-pow-spec.md`), commodity GPU/TPU alignment as the ASIC story (`doc/btx-matmul-pow-spec-analysis.md`), first-class Apple/Metal/CPU paths (`src/pow.cpp`). **v4 intentionally reverses this priority:** the marginal mining reward accrues to the device with the most dense low-precision tensor throughput — current-generation datacenter accelerators — and consumer (16–32 GB), Apple, CPU, and repurposed-mining hardware become structurally less competitive (§K.3). This is an objective change, not a side effect; all public docs/site/mining guides must be rewritten before activation, or shipping v4 under v3's fairness messaging is a credibility failure. Note that ordering is **not** exclusion: share-based pooling (§O.2) preserves proportional-to-compute rewards for consumer and Apple devices with a conforming INT8 path (Apple M5-class and later, §O.1), so "less competitive per device" does not mean "shut out."

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
| vi | **Verification/DA cost at large n** (Freivalds O(n²) but verifier regenerates 2n² operand bytes + downloads C). | Medium | Medium–High | Hard invariant (§0.7): full-node verify < ~0.3 s CPU, payload 512 KiB sketch (64 MiB full-C) at n=4096; caps n growth (raise k before n; n≤8192 only after §H.3); stream PRF regeneration (O(n) RAM on verifiers). |

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

## Appendix A — Glossary

| Term | Definition |
|---|---|
| **n** | Matrix dimension. v4 default 4096 (v3: 512). Per-nonce work: Θ(n³·2/b) under the default sketch payload; Θ(n³) under full-C (§E.3). |
| **p** | A small prime < 2⁸ used as the base field so elements fit an INT8 tensor-core operand. |
| **k** | Number of CRT primes (residue channels). The effective modulus is P = ∏pᵢ. |
| **P** | CRT-reconstructed modulus = ∏ pᵢ = 3,368,562,317 ≈ 2³¹·⁶⁵. A ring, not a field — Freivalds is never run over ℤ_P (§D.2); soundness is evaluated over the independent prime q = 2⁶¹−1 (§D.3). |
| **b** | Product-commitment/sketch tile size; n must be divisible by b. Network-wide b = 16 (§G.2); sets sketch dimension m = n/b and the §E.3 work factor b/2. |
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

## Appendix C — Open calibration items (must be resolved before mainnet activation)

1. **Genesis/bootstrap difficulty** for the n=4096 INT8 work unit — requires benchmarking on reference H100/H200/5090 hardware.
2. **s8 operand sampling** — pin the seed→`[-125,125]` rejection-sampling PRF and test vectors (k = 1 baseline; no prime set needed unless the optional §B.3 CRT variant is ever enabled).
3. **Cross-vendor INT8 determinism test vectors** — generate a pinned reference (independent implementation) before writing consensus code, mirroring v3's TV1–TV6 discipline.
4. **n final value** — confirm n = 4096 (or ≤ 8192) meets the < 100 ms verification target and per-nonce cadence on reference hardware. Per §0.7/§D.5 the launch datacenter lever is INT8 tensor-core compute, not a VRAM gate; any future verification-preserving memory-capacity gate (§L.3) is a separate, deferred item, not a launch dependency.
5. **Freivalds soundness field & round count** — confirm q = 2⁶¹−1 (or GF((2³¹−1)²)) with R = 3 (§D.3); do NOT use the composite CRT modulus (§D.2).
6. **Payload profile** — confirm the compressed-sketch default (§E.1) vs the full-C strict-binding alternative (§0.7); if full-C is chosen, land the §H.3 message/`MAX_SIZE` plumbing.
7. **DoS verify-budget retune** for O(n²) at the chosen n (§E.4, §I.5).
8. **Difficulty work-unit** — calibrate the one-time ASERT rescale (§I.4) against the sketch work unit n³·(2/b), not naïve n³ (§E.3).
9. **Committed-object definition — RESOLVED (k = 1).** The baseline is a single exact-integer s8 matmul: dense pseudorandom s8 operands `A, B ∈ [-125,125]`, exact INT32 product `C = A·B` (native `s8×s8→s32`), committed via the sketch and Freivalds-verified over `q = 2⁶¹−1` (§0.7 "Resolved", §D.3). The k-prime CRT scheme (§B.3/§B.5) is demoted to an optional, off-by-default compute-multiplier (each lane a separate exact-integer GEMM + per-lane q-Freivalds, ×k verify cost). Remaining sub-item: decide whether to keep the §B.3 CRT text as a documented optional variant (current choice) or delete it for a leaner spec.
