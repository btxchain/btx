# BTX SMILE Implementation Specification

Status: reset-chain launch architecture implemented and verified on the
audited single-round CT surface (`anon_set <= 32`, `rec_levels == 1`).

As of `2026-03-21`, BTX ships `DIRECT_SMILE` as the default direct
wallet-spend backend for the reset chain, with MatRiCT retained only as
failover tooling. The implementation in tree is the shipped launch protocol,
not a transitional prototype branch.

Current measured direct-spend footprints on that launch surface are:

- `1x2 v2_send`: `60,110` bytes, `10.20 s` build,
  `304.26 ms` verify
- `2x2 v2_send`: `70,272` bytes, `7.29 s` build, `481.09 ms` verify
- `2x4 v2_send`: `101,918` bytes, `5.09 s` build, `538.55 ms` verify

The compact SMILE sizes discussed below remain the paper target rather than the
current measured BTX launch-surface runtime. For the current architecture and
production assessment, see
[doc/btx-shielded-production-status-2026-03-20.md](btx-shielded-production-status-2026-03-20.md).
For the genesis-reset activation checklist for `DIRECT_SMILE`, see
[doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md](btx-smile-v2-genesis-readiness-tracker-2026-03-20.md).
For the settlement-side soft-fork upgrade boundary now merged on `main`, see
[doc/btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md](btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md).

## 1. Overview

This document specifies the implementation of the **SMILE** (Set Membership from Ideal Lattices) confidential transaction proof system for BTX, based on:

- **SMILE**: Lyubashevsky, Nguyen, Seiler. "SMILE: Set Membership from Ideal Lattices with Applications to Ring Signatures and Confidential Transactions." CRYPTO 2021 (eprint 2021/564).
- **MatRiCT+**: Esgin, Steinfeld, Zhao. "MatRiCT+: More Efficient Post-Quantum Private Blockchain Payments." IEEE S&P 2022 (eprint 2021/545).
- **MatRiCT**: Esgin, Steinfeld, Liu, Liu. "MatRiCT: Efficient, Scalable and Post-Quantum Blockchain Confidential Transactions Protocol." ACM CCS 2019 (eprint 2019/1287).

### 1.1 Goals

1. **Proof size**: 2-in-2-out CT proof ≤ 30 KB at anonymity set size N=2^15 (matching SMILE paper Figure 3).
2. **Zero-knowledge**: Hides sender identity (which UTXO is spent) and transaction amounts.
3. **Post-quantum security**: Based on Module-LWE and Module-SIS hardness (≥128-bit classical security).
4. **Practical performance**: On the audited reset-chain launch surface
   (`N <= 32`, wallet default ring size `8`), keep direct-send verification
   sub-second and continue the post-launch proof-size / prover-time reduction
   work needed to move the current tens-of-seconds prover path downward.

### 1.2 Current Status vs Target

| Component | Current (Groth-Kohlweiss) | Target (SMILE) |
|---|---|---|
| Membership proof (N=2^15) | ~112 KB | ≤ 20 KB |
| Range proof | ~23 KB | ≤ 10 KB |
| 2-in-2-out CT total (N=2^15) | ~252 KB | ≤ 30 KB |
| Ring parameters | n=256, q=8380417, MODULE_RANK=4 | d=128, q=2^32, l=32 |

---

## 2. SMILE Paper Construction (Detailed)

### 2.1 Ring Parameters

The SMILE construction fundamentally depends on specific ring arithmetic:

```
Ring:        R_q = Z_q[X] / (X^d + 1)
Parameters:  d = 128, q ≈ 2^32 (chosen so q ≡ 1 mod 2l)
             l = 32 (number of NTT slots / CRT factors)
             Each factor: degree d/l = 4, i.e. M_q = Z_q[X]/(X^4 - ζ^(2j+1))
```

**Critical**: `X^d + 1` must split into exactly `l = 32` irreducible factors of degree `d/l = 4` modulo q. This gives 32 "NTT slots" in the module `M_q`.

**Why this matters**: The recursive set membership proof decomposes an index vector `v ∈ {0,1}^n` (where n = l^m = 32^m) into m smaller vectors `v_1, ..., v_m ∈ {0,1}^l = {0,1}^32`. Each recursion level reduces the anonymity set by factor l=32, requiring only m = ⌈log_32(N)⌉ levels. For N=2^15: m = ⌈15/5⌉ = 3 levels.

### 2.2 BDLOP Commitment Scheme

The SMILE paper uses the BDLOP commitment scheme (Baum, Damgård, Lyubashevsky, Oechsner, Peikert):

```
Public parameters:
  B_0 ∈ R_q^(α+β+n) × (α+β+n)    (binding matrix)
  b_1, ..., b_n ∈ R_q^(α+β+n)      (message encoding vectors)

Commit(m_1, ..., m_n; r):
  r ← χ^(α+β+n)                     (short randomness, ternary ±1)
  t_0 = B_0 · r mod q                (binding part, α+β polynomials)
  t_i = ⟨b_i, r⟩ + m_i mod q        (message part, 1 polynomial each)

Commitment = (t_0, t_1, ..., t_n)
```

Where α = β = 10 are the M-SIS and M-LWE module ranks respectively, chosen for root Hermite factor δ ≈ 1.004.

**Key property**: A SINGLE randomness vector `r` is shared across ALL message polynomials. This is what makes SMILE proofs constant-size — you commit to v_1, ..., v_m, w_1, ..., w_k all under one `r`, and the masked opening `z = y + c·r` is a single vector regardless of how many messages are committed.

### 2.3 NTT and Inner Product Operations

For polynomials in R_q, the NTT decomposes them into l=32 slots in M_q:

```
NTT(p) = (p̂_0, ..., p̂_31) ∈ M_q^32
where p̂_j = p mod (X^4 - ζ^(2j+1))
```

The "inner product" operation on NTT vectors:
```
⟨v, w⟩ = Σ_{j=0}^{l-1} v_j · w_j mod (X^4 - ζ^(2j+1))
```

**Important**: This is NOT a true inner product (not linear in general), BUT it is linear when one operand has only scalar (constant) coefficients, i.e., when v ∈ Z_q^l. This is precisely the case for the binary selector vectors v_i ∈ {0,1}^l.

**Lemma 2.2** (used throughout): For p ∈ R_q:
```
(1/l) · Σ_{i=0}^{l-1} NTT(p)_i = p_0 + p_1·X + ... + p_{d/l-1}·X^{d/l-1}
```
i.e., the sum of NTT slots equals the first d/l coefficients of p.

### 2.4 Recursive Set Membership Proof

This is the core SMILE innovation. Given:
- Public set S = {p_1, ..., p_n} ⊂ M_q^{kl}, where n = l^m
- Matrix P ∈ M_q^{kl × n} with columns p_i
- Secret: index ℓ and opening s such that A·s = p_ℓ

The prover decomposes the index vector:
```
v = v_1 ⊗ v_2 ⊗ ... ⊗ v_m
where v_i ∈ {0,1}^l, ‖v_i‖_1 = 1 (one-hot)
```

And proves P·(v_1 ⊗ ... ⊗ v_m) = w.

#### Recursion (Figure 8 in paper):

For j = 1, 2, ..., m-1:
1. Verifier sends challenge α_j ∈ M_q^l (or M_q^{kl} for j=1)
2. Prover computes:
   - P_{j+1} = matrix derived from P_j and α_j (Equation 21)
   - x_{j+1} = P_{j+1} · (v_{j+1} ⊗ ... ⊗ v_m)
   - y_j = v_j ⊙ x_{j+1} - x_j ⊙ α_j  (component-wise)
3. Prover commits to x_{j+1}

The key relation: if P_j · (v_j ⊗ ... ⊗ v_m) = x_j, then y_j = NTT^{-1}(ŷ_j) has its first d/l coefficients all zero.

At level m: prove P_m · v_m = x_m (simple linear relation).

#### Linear proof and binary constraints:

All linear relations (P_m · v_m = x_m and ⟨1, v_i⟩ = 1) are combined into one matrix equation (Equation 23):

```
[0  0  ... P_m] [v_1]   [x_m ]
[B  0  ... 0  ] [v_2] = [e_1 ]
[0  B  ... 0  ] [... ]   [e_1 ]
[.  .  .   .  ] [v_m ]   [... ]
[0  0  ... B  ] [ 1  ]   [e_1 ]
```

Binary constraints v_i ⊙ (v_i - 1) = 0 are proven using the algebraic technique from Equation 30.

#### Garbage polynomial technique:

All y_j polynomials must have zero first d/l coefficients. A random polynomial g with zero first d/l coefficients is committed, and h = g + y_1 + ... + y_m is revealed. The verifier checks h has zero first d/l coefficients. Soundness: if any y_j has non-zero first coefficients, this propagates through the random challenge.

A garbage commitment t_{k+2m+1} absorbs the quadratic terms from both the y_j check and the binary constraints.

### 2.5 Amortization (Appendix D)

For multiple inputs (m inputs each with their own selector vector), the recursion generalizes:

```
Σ_{i=1}^{r} P^i_1 · v^i = w
```

At each recursion level, all r inputs' intermediate values x_{i,j+1} can be stacked into a single equation of the same form, reducing by factor l at each level. This means **all m inputs share the same BDLOP commitment and z vector**.

### 2.6 CT Protocol (Appendix E, Figure 12)

The full CT protocol for m inputs, n outputs:

**Public**: For each input i: U^{in}_i (public key ring), T^{in}_i (coin ring), serial numbers n^{in}_i.

**Private**: For each input i: secret key s^{in}_i, coin key r^{in}_i, selector v_i. For each output: amount a^{out}_i.

**Protocol stages**:

1. **STAGE1** (Figure 14):
   - Mint output coins: t^{out}_{i,0} = B_0 · r^{out}_i, t^{out}_{i,1} = ⟨b_1, r^{out}_i⟩ + a^{out}_i
   - Sample masking vector y
   - Compute carry polynomial e = (X-4)^{-1} · (Σ a^{in}_i - Σ a^{out}_i) for balance proof
   - Create auxiliary BDLOP commitment t' to: garbage terms, all amounts, w components, selector decompositions v_{i,j}
   - Total commitment slots: 7 + m + n + α + 1 + m(2r-1) message polynomials under ONE randomness r'

2. **OOOM recursion** (Figure 15):
   - Set membership for each input using combined matrices P_{1,i} = β_i · U^{in}_i + γ_i · T^{in}_{i,0}
   - Recursive rounds with challenges α_j

3. **GARBAGE** (Figure 16):
   - Compute response z = y' + c·r' where y' includes amortized masking
   - Build combined garbage polynomial g from: carry constraint, amount digit constraints (base-4), selector binary constraints
   - Build combined h polynomial from: framework proof terms, serial number/balance proof terms
   - Commit to garbage decomposition: t'_5, t'_6, t'_7

4. **VERIFY** (Figure 17):
   - Check ‖z‖ < B (norm bound)
   - Check B'_0 · z = w_0 + c · t'_0 (commitment opening)
   - Check h_{2,0} = h_{2,1} = h_{2,2} = h_{2,3} = 0 (first d/l coefficients)
   - Recompute all f_i, g, h from z and commitments
   - Final check: g_0 = g + (h - h_2·c²)·c² + f_5 + f_6·c + f_7·c²

### 2.7 Proof Size Formula

From Section E.1 of the paper:

**Auxiliary commitment t'**:
```
(log(q) - D) · α  +  (7 + m + n + α + 1 + m(2r-1)) · log(q) bits
```
where D is the Dilithium compression parameter (drop low-order bits of t'_0).

**Masked opening z**:
```
Length: α + 7 + m + n + α + 1 + m(2r-1) polynomials
Bandwidth: entropy-coded discrete Gaussian (≈ σ·√(2πe) bits per coefficient)
```

**Polynomial h_2**: d · log(q) bits (but first d/l coefficients are zero).

**Challenges**: derived from Fiat-Shamir seeds (32 bytes each, not counted in proof).

### 2.8 Concrete Sizes from SMILE Paper (Figure 3)

| (m inputs, n outputs) | N=2^5 | N=2^10 | N=2^15 | N=2^20 | N=2^25 |
|---|---|---|---|---|---|
| (1, 2) | 21.14 KB | 23.25 KB | 25.30 KB | 27.30 KB | 29.27 KB |
| (2, 2) | 24.35 KB | 26.49 KB | 28.69 KB | 30.80 KB | 32.87 KB |
| (10, 2) | 41.75 KB | 44.65 KB | 47.47 KB | 50.18 KB | 52.82 KB |
| (100, 2) | 314.64 KB | 323.98 KB | 332.97 KB | 341.62 KB | 350.04 KB |

Ring signature sizes (Figure 11):
| n users | m | k | ℓ | α | β | Proof size |
|---|---|---|---|---|---|---|
| 2^5 | 1 | 5 | 4 | 13 | 10 | 15.96 KB |
| 2^10 | 2 | 5 | 4 | 13 | 10 | 17.27 KB |
| 2^15 | 3 | 5 | 4 | 13 | 10 | 18.73 KB |
| 2^20 | 4 | 5 | 4 | 13 | 10 | 20.15 KB |
| 2^25 | 5 | 5 | 4 | 13 | 10 | 21.53 KB |

---

## 3. Parameter Decisions for BTX

### 3.1 Ring Parameters: MUST CHANGE

The current BTX implementation uses Dilithium parameters (n=256, q=8380417). These are **incompatible** with the SMILE construction because:

1. **NTT slot structure**: With n=256 and q=8380417 (Dilithium), X^256+1 splits into 256 linear factors (degree-1 slots). SMILE needs degree-4 slots (l=32 slots of degree d/l=4).
2. **Tensor decomposition**: SMILE's recursion needs l=32 so that N=32^m. With degree-1 slots, we'd need l=256 and m=1 for N=256 (far too small).
3. **Inner product linearity**: The ⟨·,·⟩ operation on M_q slots is only linear when one operand is scalar. With degree-1 slots this is trivially true, but the slot size is too small for the proof structure.

**Required parameters for BTX SMILE**:

```cpp
// Ring R_q = Z_q[X] / (X^128 + 1)
static constexpr size_t POLY_DEGREE = 128;           // d = 128

// Prime q ≈ 2^32, chosen so X^128+1 splits into 32 degree-4 factors
// q ≡ 1 (mod 64) to ensure 64th roots of unity exist
// Candidate: q = 4611686018427387761 (from reference impl) — NO, too large
// Paper uses q ≈ 2^32. Concrete: q must satisfy q ≡ 1 (mod 2l) = 1 (mod 64)
// Candidate: q = 4294955521 = 2^32 - 11775 (≡ 1 mod 64, prime, NTT-friendly)
static constexpr int64_t Q = 4294955521;              // ≈ 2^32

// NTT parameters
static constexpr size_t NUM_NTT_SLOTS = 32;           // l = 32
static constexpr size_t SLOT_DEGREE = 4;              // d/l = 4
// Each slot: M_q = Z_q[X] / (X^4 - ζ^(2j+1))

// Module ranks for M-SIS/M-LWE security
static constexpr size_t MSIS_RANK = 10;               // α = 10
static constexpr size_t MLWE_RANK = 10;               // β = 10

// Commitment key dimension
// BDLOP commitment: (α+β+n) columns, where n = number of message slots
static constexpr size_t BDLOP_RAND_DIM_BASE = 20;     // α + β = 20

// Secret distribution: ternary {-1, 0, 1} with P(0) = 6/16, P(±1) = 5/16
static constexpr size_t SECRET_ETA = 1;

// Signature/proof key dimensions
static constexpr size_t KEY_ROWS = 5;                  // k = 5
static constexpr size_t KEY_COLS = 4;                  // ℓ = 4

// Anonymity set parameters
static constexpr size_t ANON_EXP = 15;
static constexpr size_t ANON_SET_SIZE = 1 << ANON_EXP; // 32768
// m = ceil(log_32(32768)) = ceil(15/5) = 3 recursion levels
static constexpr size_t RECURSION_LEVELS = 3;
```

### 3.2 Rejection Sampling

SMILE uses the bimodal Gaussian technique from [Lyubashevsky et al. 2021]:

```
Standard deviation:  σ = 0.675 · T   (where T = ‖c·s‖ bound)
Repetition rate:     M = √(3/2) ≈ 1.22
Expected attempts:   2M ≈ 2.45
```

This is a ~10x reduction in σ compared to the standard technique (σ = 11·T), directly reducing z vector sizes. The trade-off: leaks one bit (sign of ⟨z, c·s⟩), which is acceptable for one-time commitments (coins spent once).

### 3.3 Commitment Compression (Dilithium technique)

The top part t_0 of the BDLOP commitment is compressed:
- Drop D low-order bits (paper targets 2^D ≈ 12σ)
- Reduces t_0 from α · d · log(q) bits to α · d · (log(q) - D) bits
- The remainder serves as masking for the M-LWE error (Bai-Galbraith technique)

### 3.4 Gaussian Entropy Coding

The z vectors are discrete Gaussians. Instead of storing each coefficient in ⌈log(12σ)⌉ bits, use Huffman/entropy coding:
- Per-coefficient entropy: ≈ log₂(σ√(2πe)) bits
- Savings: ~15-20% vs fixed-width encoding

---

## 4. Data Structures

### 4.1 Polynomial

```cpp
// Polynomial in R_q = Z_q[X]/(X^128+1)
struct SmilePoly {
    std::array<int64_t, 128> coeffs;  // d=128 coefficients mod q

    // NTT representation: 32 slots, each degree-4
    struct NttSlot {
        std::array<int64_t, 4> coeffs;  // in Z_q[X]/(X^4 - root)
    };
    std::array<NttSlot, 32> ToNTT() const;
    static SmilePoly FromNTT(const std::array<NttSlot, 32>& slots);

    // Arithmetic
    SmilePoly operator+(const SmilePoly& other) const;
    SmilePoly operator*(const SmilePoly& other) const;  // via NTT
    SmilePoly operator*(int64_t scalar) const;
};

// Vector of polynomials
using SmilePolyVec = std::vector<SmilePoly>;
```

### 4.2 BDLOP Commitment

```cpp
struct BDLOPCommitmentKey {
    // B_0 ∈ R_q^{(α+β+n_msg) × (α+β+n_msg)}
    // Generated pseudorandomly from seed
    uint256 seed;
    size_t n_msg;  // number of message slots

    // b_1, ..., b_{n_msg} ∈ R_q^{α+β+n_msg}
    // Also generated from seed

    // Expand the full matrices on demand
    SmilePolyVec ExpandB0Row(size_t row) const;
    SmilePoly ExpandBi(size_t i, size_t col) const;
};

struct BDLOPCommitment {
    SmilePolyVec t0;     // α+β polynomials (binding part)
    // After compression: high-order bits only
    std::vector<SmilePoly> t_msg;  // n_msg polynomials (message parts)
};

struct BDLOPOpening {
    SmilePolyVec r;      // randomness vector, (α+β+n_msg) polynomials
};
```

### 4.3 Membership Proof (SMILE Recursive)

```cpp
struct SmileMembershipProof {
    // BDLOP commitment t (combines ALL committed values under one r):
    //   t_1, ..., t_m:        commitments to v_1, ..., v_m (selector decomposition)
    //   t_{m+1}, ..., t_{m+k}: commitments to w_1, ..., w_k (target value NTT)
    //   t_{m+k+1}, ..., t_{2m+k-1}: commitments to x_2, ..., x_m (intermediate recursion values)
    //   t_{k+2m}:              commitment to g (garbage polynomial with zero first d/l coeffs)
    //   t_{k+2m+1}:           commitment to ψ (combined binary + framework garbage)
    //   t_{k+2m+2}:           commitment to b (bimodal sign, ∈ {-1,1}^l)
    BDLOPCommitment commitment;  // All in ONE commitment

    // Polynomial h = g + y_1 + ... + y_m (first d/l=4 coefficients must be zero)
    SmilePoly h;

    // Masked openings
    SmilePolyVec z;     // z = y + c·r (main randomness masking)
    SmilePolyVec z0;    // z_0 = y_0 + b·c_0·s (secret key masking, bimodal)

    // Garbage polynomial ω (verifier-computable check value)
    SmilePoly omega;

    // Fiat-Shamir challenge seeds
    uint256 challenge_seed_c0;   // for c_0 (first challenge)
    uint256 challenge_seed_c;    // for c (final challenge)
    // All intermediate challenges (α_j, β_j, ρ_j) derived deterministically
};
```

### 4.4 CT Proof

```cpp
struct SmileCTProof {
    // Output coins (minted in protocol)
    std::vector<BDLOPCommitment> output_coins;  // n outputs

    // Auxiliary commitment t' (ONE big BDLOP commitment):
    //   t'_1: garbage (zero commitment for serial number proof)
    //   t'_2: garbage (⟨b'_1, y⟩ for amortized opening)
    //   t'_3: carry garbage polynomial o
    //   t'_4: carry polynomial e
    //   t'_5, t'_6, t'_7: garbage decomposition for quadratic check
    //   t'_{8..7+m}: recommitted input amounts a^{in}_i
    //   t'_{8+m..7+m+n}: recommitted output amounts a^{out}_i
    //   t'_{8+m+n..7+m+n+α}: w components
    //   t'_{8+m+n+α}: w'' commitment
    //   t'_{8+m+n+α+1..}: selector decompositions v_{i,j}
    BDLOPCommitment aux_commitment;

    // Masked opening
    SmilePolyVec z;     // z = y' + c·r' (amortized)

    // Serial numbers (revealed)
    std::vector<SmilePoly> serial_numbers;  // m serial numbers

    // Framework proof polynomial h_2 (first d/l coefficients = 0)
    SmilePoly h2;

    // Garbage value g_0 (public)
    SmilePoly g0;

    // Fiat-Shamir seeds (intermediate challenges are derived)
    uint256 fs_seed;

    // Estimated size for 2-in-2-out at N=2^15: ~29 KB
};
```

---

## 5. Algorithms

### 5.1 NTT for d=128, l=32

```
Input:  p ∈ R_q (128 coefficients)
Output: (p̂_0, ..., p̂_31) where p̂_j ∈ M_q = Z_q[X]/(X^4 - ζ^(2j+1))

Algorithm:
  1. Find ζ = primitive 64th root of unity mod q
  2. For j = 0, ..., 31:
     p̂_j = p mod (X^4 - ζ^(2j+1))
     = (p_0 + p_4·r + p_8·r² + ...) + (p_1 + p_5·r + ...)·X + ...
     where r = ζ^(2j+1) is the slot root

Inverse NTT: standard CRT reconstruction
```

### 5.2 Prove Membership (SMILE Recursive)

```
ProveMembership(ck, anon_set, index, opening, rng):
  n = |anon_set|, m = ceil(log_l(n)), l = 32

  1. Decompose index into v_1, ..., v_m ∈ {0,1}^l
     index = v_{1,j_1} + l·v_{2,j_2} + ... + l^{m-1}·v_{m,j_m}

  2. Compute w_0 = A·y_0 (masking for key proof), y_0 ~ D_σ₀

  3. Sample garbage polynomial g with g_0 = ... = g_3 = 0

  4. Create BDLOP commitment to (v_1, ..., v_m, w_0, g) under single r

  5. Fiat-Shamir: derive c_0 (challenge for key proof)
     z_0 = y_0 + b·c_0·s (bimodal Gaussian)
     Reject if Rej(z_0, b·c_0·s, σ₀) fails → restart

  6. Build P_1 from public keys scaled by c_0 (Equation 31)
     x_1 = NTT(w_0 - A·z_0)

  7. For j = 1, ..., m-1:
     Derive challenge α_j via Fiat-Shamir
     Compute P_{j+1} from P_j and α_j (Equation 21)
     x_{j+1} = P_{j+1} · (v_{j+1} ⊗ ... ⊗ v_m)
     y_j = v_j ⊙ x_{j+1} - x_j ⊙ α_j
     Commit to x_{j+1}: t_{m+k+j} = ⟨b_{m+k+j}, r⟩ + NTT^{-1}(x_{j+1})

  8. Derive challenge α_m, compute y_m (Equation 24)

  9. h = g + y_1 + ... + y_m  (reveal this)

  10. Derive random ρ_0, ..., ρ_m
      Compute ψ = ρ_0·ψ_sm + ψ_bin (combined garbage, Equation 30)
      Commit to ψ: t_{k+2m+1} = ⟨b_{k+2m+1}, r⟩ + ψ
      Compute ω = ⟨b_{k+2m+1}, y⟩ + ω_bin + ρ_0·ω_sm

  11. Derive challenge c via Fiat-Shamir
      z = y + c·r
      Reject if Rej(z, c·r, σ) fails → restart

  12. Output proof = (commitment, h, z, z_0, ω, seeds)
```

### 5.3 Verify Membership

```
VerifyMembership(ck, anon_set, proof):
  1. Check ‖z_0‖₂ < σ₀·√(2ℓd) and ‖z‖₂ < σ·√(2(α+β+k+2m+1)d)

  2. Check B_0·z = w + c·t_0  (commitment opening)

  3. Compute t'_{m+i} = t_{m+i} - A·z_0 for i ∈ [k]  (adjust for key proof)

  4. For all j ∈ [k+2m+1]: f_j = ⟨b_j, z⟩ - c·t_j

  5. Rebuild P_1 from public keys, derive all challenges deterministically

  6. Compute F_j, ψ_sm, ω_sm, ψ_bin, ω_bin as in verification (Figure 9)

  7. Check: (Σ F_j - c·f_{k+2m} - c²·h) + Σ ρ_i·(f_i² + c·f_i) + f_{k+2m+1} = ω

  8. Check: h_0 = h_1 = h_2 = h_3 = 0  (first d/l=4 coefficients)
```

### 5.4 CT Prove/Verify

The CT proof combines:
- m membership proofs (amortized, sharing one z vector)
- Balance proof (amount recommitments + carry check)
- Serial number proof (correctness of revealed serial numbers)
- Range proofs (amounts encoded in base-4 via NTT slots, carry polynomial constraint)

All under a SINGLE BDLOP commitment and SINGLE masked opening z.

---

## 6. Proof Size Budget (2-in-2-out, N=2^15)

Using SMILE paper parameters (α=β=10, d=128, l=32, q≈2^32, k=5, ℓ=4, m=3):

```
Auxiliary commitment t':
  t'_0 (compressed): α · d · (log(q) - D) ≈ 10 · 128 · 20 = 25,600 bits = 3,200 bytes
  Message polynomials: (7 + m + n + α + 1 + m(2r-1)) · d · log(q)
    = (7 + 2 + 2 + 10 + 1 + 2·(2·3 - 1)) · 128 · 32
    = (22 + 10) · 4,096 = 32 · 4,096 = 131,072 bits = 16,384 bytes
  Total t': ≈ 19,584 bytes

Masked opening z:
  Length: 32 polynomials × 128 coefficients = 4,096 coefficients
  Gaussian with σ ≈ 675 → per-coeff entropy ≈ log₂(675·√(2πe)) ≈ 11.6 bits
  Total: 4,096 · 11.6 ≈ 47,514 bits ≈ 5,939 bytes

z_0 (key proof, bimodal):
  Length: ℓ = 4 polynomials × 128 coefficients = 512 coefficients
  σ₀ ≈ small (bimodal) → per-coeff ≈ 8 bits
  Total: 512 · 8 = 4,096 bits = 512 bytes

h_2 polynomial:
  128 coefficients × 32 bits = 4,096 bits = 512 bytes

Serial numbers: 2 × 128 × 32 = 8,192 bits = 1,024 bytes

Challenge seeds: ~128 bytes

Overhead (g_0, etc.): ~512 bytes

ESTIMATED TOTAL: ≈ 28-30 KB ✓  (matches paper's 28.69 KB for 2-in-2-out N=2^15)
```

---

## 7. Test Specifications

### 7.1 Unit Tests: Ring Arithmetic (d=128, q≈2^32)

```
TEST: NTT forward/inverse roundtrip
  For random p ∈ R_q: INTT(NTT(p)) == p

TEST: NTT multiplication correctness
  For random p, q ∈ R_q: NTT(p·q) == NTT(p) ⊙ NTT(q)

TEST: NTT slot structure
  X^128+1 should factor into exactly 32 degree-4 irreducible polynomials mod q
  Verify: for each root ζ^(2j+1), X^4 - ζ^(2j+1) is irreducible mod q

TEST: Slot inner product linearity for scalars
  For v ∈ Z_q^32, w ∈ M_q^32: ⟨c·v, w⟩ == c·⟨v, w⟩ for scalar c

TEST: Lemma 2.2 verification
  For random p: (1/l)·Σ NTT(p)_j should equal first d/l=4 coefficients of p
```

### 7.2 Unit Tests: BDLOP Commitment

```
TEST: Commitment correctness
  Commit(m; r) produces valid (t_0, t_1, ..., t_n)
  Verify: B_0·r == t_0, ⟨b_i, r⟩ + m_i == t_i

TEST: Hiding property
  Two commitments to different messages with different randomness
  should be computationally indistinguishable (statistical test)

TEST: Binding property
  Cannot find (r, m) ≠ (r', m') with same commitment
  (test that finding such would require solving M-SIS)

TEST: Weak opening
  Given z = y + c·r, verify: B_0·z == w + c·t_0
  and ⟨b_i, z⟩ - c·t_i == ⟨b_i, y⟩ - c·m_i

TEST: Multi-message commitment
  Commit to (m_1, ..., m_n) under single r
  Verify all message slots independently
```

### 7.3 Unit Tests: Recursive Set Membership

```
TEST: Tensor decomposition
  For index ℓ ∈ [0, l^m), with l=32, m=3:
  v = v_1 ⊗ v_2 ⊗ v_3 should have exactly one 1 at position ℓ

TEST: Matrix P_{j+1} construction
  Given P_j and challenge α_j, verify P_{j+1} matches Equation 21

TEST: Intermediate value x_{j+1} correctness
  x_{j+1} = P_{j+1} · (v_{j+1} ⊗ ... ⊗ v_m) should satisfy the recursion

TEST: y_j polynomial first-coefficient check
  If P_j · (v_j ⊗ ... ⊗ v_m) == x_j, then NTT^{-1}(y_j) has first 4 coefficients = 0

TEST: Framework proof (garbage polynomial)
  h = g + y_1 + ... + y_m should have first 4 coefficients = 0

TEST: Binary constraint proof
  Σ ρ_i · (f_i² + c·f_i) should have correct quadratic structure

TEST: Small anonymity set (N=32, m=1)
  Full prove/verify cycle, verify proof size ≈ 16 KB

TEST: Medium anonymity set (N=1024, m=2)
  Full prove/verify cycle, verify proof size ≈ 17 KB

TEST: Target anonymity set (N=32768, m=3)
  Full prove/verify cycle, verify proof size ≤ 19 KB

TEST: Wrong index → verification fails
  Prove with index ℓ, but tamper with v_1 → verify should reject

TEST: Wrong key → verification fails
  Prove with wrong secret key s → z_0 norm too large or equation fails
```

### 7.4 Unit Tests: CT Proof

```
TEST: Balance proof correctness
  2-in-2-out with amounts: in=(100, 200), out=(150, 150)
  Prove and verify. Balance holds.

TEST: Balance proof rejection (inflation)
  in=(100, 200), out=(150, 200) → should fail (net +50)

TEST: Amount range proof
  Each amount encoded in base-4 via NTT slots
  Verify digit constraint: each slot ∈ {0,1,2,3}

TEST: Serial number correctness
  sn_i = ⟨b_1, s_i⟩ should be correctly revealed and verified

TEST: Amortized membership
  2 inputs from same anonymity set, single z vector
  Verify both memberships hold

TEST: Full CT proof size (2-in-2-out, N=32)
  Measure serialized size, should be ≈ 24 KB

TEST: Full CT proof size (2-in-2-out, N=32768)
  Measure serialized size, should be ≤ 30 KB
  THIS IS THE KEY TARGET

TEST: Zero-knowledge property
  Two proofs with different (sender, amount) but same public data
  Should be computationally indistinguishable (statistical test)

TEST: Double-spend detection
  Same input in two different transactions → same serial number revealed

TEST: Maximum transaction (16-in-16-out)
  Verify proof generation succeeds and size is reasonable
```

### 7.5 Integration Tests

```
TEST: Serialization roundtrip
  Serialize proof to bytes → deserialize → re-verify

TEST: Cross-validation with reference implementation
  If feasible, generate proof with reference impl → verify with BTX impl

TEST: Fiat-Shamir transcript consistency
  Same inputs → same challenge → same proof (deterministic with fixed rng)

TEST: Rejection sampling distribution
  Over many proofs, z vector distribution should be statistically close to
  D^{ℓd}_σ (chi-squared test)

TEST: Performance benchmark
  Prove 2-in-2-out in < 3 seconds
  Verify 2-in-2-out in < 250 ms
```

---

## 8. Implementation Plan

### Phase 1: Ring Arithmetic Foundation
1. New polynomial type `SmilePoly` with d=128 coefficients mod q≈2^32
2. NTT for 32 degree-4 slots (NOT the current 256 degree-1 Dilithium NTT)
3. Slot arithmetic: multiplication, inner product in M_q = Z_q[X]/(X^4 - root)
4. Unit tests for all ring operations

### Phase 2: BDLOP Commitment
1. Commitment key generation (B_0, b_i from seed)
2. Commit/open operations
3. Dilithium-style compression of t_0
4. Unit tests for correctness, hiding

### Phase 3: Recursive Set Membership
1. Tensor decomposition of index
2. Matrix recursion (P_j → P_{j+1})
3. Framework proof (garbage polynomial g, h computation)
4. Binary constraint proof
5. Fiat-Shamir transcript
6. Rejection sampling (bimodal Gaussian)
7. Prove/verify with small N first, then scale to N=32768

### Phase 4: CT Protocol
1. Auxiliary commitment structure (7 + m + n + α + 1 + m(2r-1) slots)
2. Amortized membership for multiple inputs
3. Balance proof (amount recommitment + carry polynomial)
4. Serial number proof
5. Full prove/verify
6. Size measurement and optimization

### Phase 5: Integration
1. Serialization/deserialization
2. Consensus validation hooks
3. Wallet RPC integration
4. Performance optimization (parallelism, precomputation)

---

## 9. Key Differences from Current Implementation

| Aspect | Current | SMILE Target |
|---|---|---|
| Ring degree | n=256 | d=128 |
| Modulus | q=8380417 (23 bits) | q≈2^32 (32 bits) |
| NTT slots | 256 degree-1 | 32 degree-4 |
| Commitment | Module-LWE (k=4 rows, l=6 cols) | BDLOP (α=β=10, single r) |
| Membership proof | Groth-Kohlweiss per-digit | Recursive tensor decomposition |
| Recursion base | 2 (binary, 15 levels) | 32 (l=32, 3 levels) |
| Rejection sampling | Standard (σ = 11T) | Bimodal (σ = 0.675T) |
| Proof structure | Separate proofs per component | Single BDLOP + single z |
| Amortization | None (each input separate) | All inputs share one z |

### 9.1 What Can Be Reused

- Hash functions (SHA-256 for Fiat-Shamir)
- Random number generation infrastructure
- Serialization framework (adapted for new types)
- Test framework
- Transaction structure / UTXO model
- Wallet integration layer

### 9.2 What Must Be Rewritten

- **Polynomial arithmetic**: Entirely new (d=128, q≈2^32, degree-4 NTT)
- **Commitment scheme**: BDLOP replaces current Module-LWE commitments
- **Membership proof**: Recursive tensor replaces Groth-Kohlweiss
- **Range proof**: Integrated into CT proof via NTT-slot base-4 encoding
- **CT proof**: Complete rewrite following SMILE Figure 12

---

## 10. Open Questions

1. **Exact prime q**: Need to find a specific q ≈ 2^32 where X^128+1 splits into exactly 32 degree-4 factors. The reference implementation uses q = 4611686018427365377 (63-bit), which is much larger than the paper claims. Need to verify the paper's claim of q ≈ 2^32.

2. **Compatibility with existing UTXO**: The change from n=256 to d=128 polynomials changes the commitment format. Need a migration plan for existing shielded UTXOs (if any exist on testnet).

3. **Hardware acceleration**: The degree-4 slot arithmetic is different from standard NTT used in Dilithium. May need custom SIMD implementations.

4. **Carry polynomial for balance**: The paper's carry polynomial technique (Equation in STAGE1, line 08) uses (X-4)^{-1} which requires 4 to be invertible mod the slot polynomials. Need to verify this for chosen q.

5. **Reference implementation discrepancy**: The GitHub reference (Valeh2012/voting-from-lattices) uses much larger parameters than the paper claims. Need to determine which parameters are correct for 128-bit security.

---

## Appendix A: SMILE Reference Implementation Key Functions

From github.com/Valeh2012/voting-from-lattices/smile/:

```c
// smile.h
typedef struct {
    uint8_t hash[32];       // Fiat-Shamir hash
    polyvecl z1;            // masked opening (ℓ polynomials)
    commrnd z2;             // commitment randomness response
    comm t;                 // auxiliary commitment
    poly h;                 // framework proof polynomial
} smile_proof;

// comm.h
typedef struct {
    polyvec_com t0;         // binding part
    poly_com tm;            // message part
} comm;

typedef struct {
    polyvec_com s;          // randomness vector
    poly_com e;             // error polynomial
    poly_com em;            // message error
} commrnd;

// Core functions
int smile_prove(smile_proof *proof, ...);
int smile_proof_verify(smile_proof *proof, ...);
void commit(comm *c, commrnd *r, poly *msg, commkey *ck);
```

## Appendix B: Concrete Prime Selection

For d=128, l=32, we need q such that:
- q is prime
- q ≡ 1 (mod 2l) = 1 (mod 64)
- q ≈ 2^32
- X^128+1 splits into 32 irreducible degree-4 factors mod q
- The maximum probability p of challenge coefficients satisfies q^{-d/l} · p^{d/l} < 2^{-128}

Candidate search: q = 2^32 - k for small k, where q ≡ 1 (mod 64) and q prime.

The condition q ≡ 1 (mod 64) ensures Z_q contains a primitive 64th root of unity ζ, and then X^128+1 = Π_{j∈Z_32} (X^4 - ζ^{2j+1}) (mod q).

**Verification needed**: Compute ζ = g^{(q-1)/64} for a generator g of Z_q^*, then verify each X^4 - ζ^{2j+1} is irreducible mod q. If instead X^4 - ζ^{2j+1} factors further, we get l > 32 slots (which could still work but changes parameters).
