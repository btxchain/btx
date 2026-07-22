// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_H
#define BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_H

#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_fri_ext3.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

// ============================================================================
// ENC_RC — AIR constraint-quotient construction (O(Q) verification of the
// per-row update rules that matmul_v4_rc_gkr_air.{h,cpp} currently checks by
// scanning EVERY row).
//
// CONSTRUCTION (standard AIR / ALI quotienting over the trace subgroup H):
//  1. Each per-row rule is a polynomial constraint C_i(X) over the trace
//     column polynomials P_1..P_W (each deg < N = |H|) that VANISHES on H
//     exactly when the trace satisfies the rule on every row. Three shapes:
//       kEverywhere : C_i(X) = R_i(P(X), P(ω_H X))                — all rows
//       kTransition : C_i(X) = (X − h_last) · R_i(P(X), P(ω_H X)) — rows 0..N−2
//       kFirstRow   : C_i(X) = (Z_H(X)/(X − 1))      · R_i(P(X))  — row 0 only
//       kLastRow    : C_i(X) = (Z_H(X)/(X − h_last)) · R_i(P(X))  — row N−1
//     with h_last = ω_H^{N−1} and Z_H(X)/(X − h) = Σ_j h^{N−1−j} X^j a
//     POLYNOMIAL (h ∈ H). deg C_i ≤ d_i(N−1) + extra, extra = 0 / 1 / N−1.
//  2. Fiat–Shamir batching: λ from the transcript AFTER all trace column
//     roots are absorbed; C(X) = Σ_i λ^i C_i(X). If any C_i is nonzero on H,
//     C fails to vanish on H except for ≤ (n_constraints−1)/|F| of the λ
//     (Schwartz–Zippel on the λ-polynomial).
//  3. Quotient: Q(X) = C(X) / Z_H(X), Z_H(X) = X^N − 1. Division is EXACT
//     iff C vanishes on all of H (iff every rule holds on every row). The
//     prover commits Q with the declared coefficient bound
//     len(Q) = max_i deg C_i − N + 1, enforced by the batched-FRI
//     degree-shift RLC (an over-degree quotient cannot be committed under
//     the declared length, and a wrong declared length is rejected
//     structurally by the verifier).
//  4. COSET EVALUATION: every committed column (trace + quotient) is
//     committed in the basis P̂(X) := P(g·X) with g = 7 (a generator of
//     F_p^×, the standard Goldilocks coset shift), i.e. coefficient j is
//     multiplied by g^j. The batched FRI therefore evaluates/open at points
//     y = g·x for x in the size-(16·n_coeffs) LDE subgroup D. Since
//     ord(g) = p−1 has odd factors while |D| is a power of two,
//     (g·x)^N = 1 is impossible for any x ∈ D, so Z_H(y) ≠ 0 at EVERY
//     opened point — the identity below never degenerates.
//  5. Per-point check: the trace columns and Q ride ONE batched FRI
//     instance (FriBatchCommit / Fri3BatchCommit — Q = 128 FS query
//     points, dual-OOD DEEP, per-column degree bounds). At each query
//     index the verifier takes the opened column values, the supplemental
//     "next-row" openings (same columns at LDE index + n_lde/N, i.e. at
//     ω_H·y — Merkle-verified against the SAME column roots), evaluates
//         C(y) = Σ_i λ^i · sel_i(y) · R_i(cur, next)
//     and accepts iff  C(y) == Q(y) · Z_H(y).  This replaces the full-row
//     scan by O(Q) work.
//
// SOUNDNESS SHAPE (honest statement). The identity is checked at the 128
// in-domain FS query points (classical ALI), with column proximity + the
// per-column degree bounds supplied by the batched FRI (2^-76.8 post-grind
// query term; see kRCFriBatchSoundnessStatement). If the committed words are
// within unique decoding of polynomials P_i, Q and C ≠ Q·Z_H as polynomials,
// the two sides agree on ≤ deg/|D| of the domain, so 128 independent FS
// points reject w.h.p.; λ adds the (n_constraints−1)/|F| SZ term. A
// DEEP-style out-of-domain lift of THIS identity (open every column also at
// ω_H·z and check C(z) = Q(z)·Z_H(z) at the FS z ∉ D) is the production
// hardening step and needs a batched-FRI extension that opens shifted OOD
// points; it is deliberately NOT faked here. COMPUTATIONAL — not ε=0.
// Arbiter OFF; nMatMulRCHeight stays INT32_MAX.
//
// ============================================================================
// WHAT ARITHMETIZES CLEANLY — AND WHAT DOES NOT (per-rule honesty).
//
//  • Dequant / operand-expansion output rule (C-E10 / mxexpand dequant):
//      out(X) − mu(X)·(1 + e0(X))·(1 + 3·e1(X)) = 0 on H, plus booleanity
//      of e0, e1 and first-row public binding of (e0, e1) to the scale.
//      Degree 3 → deg C ≤ 3(N−1). CLEAN.
//  • Extract-sampler rule (C-E2..E9 core): nibble-bit booleanity and
//      recomposition (deg 2/1), mixed = kappa ⊕ h per bit (deg 2), the
//      degree-4 E2M1 acceptance selector acc = AcceptPoly(mixed bits),
//      liveness (32 − pos)·inv_live = 1 gated by the activity selector
//      (deg 3), position transition pos' = pos + acc (transition, deg 1),
//      boundary pos(0) = 0 and pos+acc = 32 at the end, and the golden-mix
//      integer identity u·G = q·2^32 + v (deg 1, exact over F_p since
//      u·G < p). Max degree 4 → deg C ≤ 4(N−1). CLEAN. (The 16-bit-limb
//      range obligations remain LogUp/T_R16 membership rows — membership,
//      not identities — exactly as in the row-scan AIR.)
//  • LogUp membership rule: per-row fractional witnesses
//      φ·(α − w) = 1,  ψ·(α − t) = m   (deg 2, fail-closed: a pole α = w
//      makes the row unsatisfiable), running sum S' = S + φ − ψ
//      (transition), S(0) = 0 and S + φ − ψ = 0 at the last row (this IS
//      Σφ = Σψ). The table column t is PREPROCESSED: the verifier
//      regenerates its canonical values from consensus constants and
//      checks the committed column root against them — the Theorem-5.1
//      "table := witness" clone is rejected by the root equality even
//      though its fractional sums balance. CLEAN.
//  • Tile-tree hashing rule (SHA-256d Merkle tree, §6.3) — DOES NOT reduce
//      to a low-degree constraint over the byte-stream columns. SHA-256 is
//      high-degree over F_p as a function of packed words; it becomes
//      low-degree (≤ 4) ONLY after full bit-decomposition: per compression
//      ≈ 48·32 schedule bits + 64·6·32 round bits + carries ≈ 1.5–2.6k
//      committed cells, ×2 for SHA256d, per tree node (leaves + n−1 inner
//      nodes). Honest options: (a) lay the EmitTileConstraints SHA gadget
//      rows onto this quotient's trace with per-family selector columns —
//      ~2^11 columns × (compressions) rows of commitment cost, the
//      identities themselves are already degree ≤ 4 and would slot into
//      this module unchanged; or (b) keep CheckTileTreeInCircuit as a
//      separate carried check (the current row-scan path) outside the
//      O(Q)-verification claim. This module implements NEITHER as a fake
//      low-degree constraint; the hash rule is out of scope of the
//      quotient argument until (a) is built.
// ============================================================================

namespace matmul::v4::rc::air_quotient {

// ---------------------------------------------------------------------------
// Field trait: the module is generic over the extension field used for
// commitments and challenges (Fp2 today, Fp3 later). All trace/constraint
// algebra goes through this trait.
// ---------------------------------------------------------------------------
template <typename F>
struct AirField;

template <>
struct AirField<gkr_field::Fp2> {
    using Field = gkr_field::Fp2;
    static Field Zero() { return Field::Zero(); }
    static Field One() { return Field::One(); }
    static Field Add(const Field& a, const Field& b) { return gkr_field::Add(a, b); }
    static Field Sub(const Field& a, const Field& b) { return gkr_field::Sub(a, b); }
    static Field Mul(const Field& a, const Field& b) { return gkr_field::Mul(a, b); }
    static Field Neg(const Field& a) { return gkr_field::Neg(a); }
    static Field Inv(const Field& a) { return gkr_field::Inv(a); }
    static bool Eq(const Field& a, const Field& b) { return gkr_field::Eq(a, b); }
    static bool IsZero(const Field& a) { return gkr_field::IsZero(a); }
    static Field FromBase(gkr_field::Fp a) { return Field::FromFp(a); }
    static Field FromU64(uint64_t v) { return Field::FromFp(gkr_field::FromU64(v)); }
    static Field FromSigned(int64_t v) { return Field::FromFp(gkr_field::FromSigned(v)); }
    /** 32 FS bytes -> field challenge (16 bytes of entropy consumed). */
    static Field FromChallenge(const unsigned char* b32)
    {
        return gkr_field::FromChallengeBytes2(b32);
    }
};

template <>
struct AirField<gkr_field::Fp3> {
    using Field = gkr_field::Fp3;
    static Field Zero() { return Field::Zero(); }
    static Field One() { return Field::One(); }
    static Field Add(const Field& a, const Field& b) { return gkr_field::Add(a, b); }
    static Field Sub(const Field& a, const Field& b) { return gkr_field::Sub(a, b); }
    static Field Mul(const Field& a, const Field& b) { return gkr_field::Mul(a, b); }
    static Field Neg(const Field& a) { return gkr_field::Neg(a); }
    static Field Inv(const Field& a) { return gkr_field::Inv(a); }
    static bool Eq(const Field& a, const Field& b) { return gkr_field::Eq(a, b); }
    static bool IsZero(const Field& a) { return gkr_field::IsZero(a); }
    static Field FromBase(gkr_field::Fp a) { return Field::FromFp(a); }
    static Field FromU64(uint64_t v) { return Field::FromFp(gkr_field::FromU64(v)); }
    static Field FromSigned(int64_t v) { return Field::FromFp(gkr_field::FromSigned(v)); }
    /** 32 FS bytes -> field challenge (24 bytes of entropy consumed). */
    static Field FromChallenge(const unsigned char* b32)
    {
        return gkr_field::FromChallengeBytes3(b32);
    }
};

// ---------------------------------------------------------------------------
// FRI backend trait: maps the field to its batched proximity module. Both
// substrates already exist (matmul_v4_rc_fri.h over Fp2, matmul_v4_rc_fri_ext3.h
// over Fp3) with byte-compatible shapes; the module never reimplements FRI.
// ---------------------------------------------------------------------------
template <typename F>
struct AirFriBackend;

template <>
struct AirFriBackend<gkr_field::Fp2> {
    using BatchProof = FriBatchProof;
    using BatchCommitResult = FriBatchCommitResult;
    using MerklePath = FriMerklePath;
    static BatchCommitResult BatchCommit(const std::vector<std::vector<gkr_field::Fp2>>& cols,
                                         const uint256& fs_seed)
    {
        return FriBatchCommit(cols, fs_seed);
    }
    static bool BatchVerify(const BatchProof& p, const uint256& fs_seed, std::string* why)
    {
        return FriBatchVerify(p, fs_seed, why);
    }
    static uint256 ColumnRoot(const std::vector<gkr_field::Fp2>& col, uint32_t n_coeffs)
    {
        return FriBatchColumnRoot(col, n_coeffs);
    }
    static uint256 LeafHash(const gkr_field::Fp2& v, uint32_t index)
    {
        return FriLeafHash(v, index);
    }
    static uint256 NodeHash(const uint256& l, const uint256& r) { return FriNodeHash(l, r); }
    static bool VerifyPath(const MerklePath& p, const uint256& root, uint32_t n_leaves)
    {
        return FriVerifyPath(p, root, n_leaves);
    }
    static uint32_t NumQueries() { return kRCFriBatchNumQueries; }
};

template <>
struct AirFriBackend<gkr_field::Fp3> {
    using BatchProof = Fri3BatchProof;
    using BatchCommitResult = Fri3BatchCommitResult;
    using MerklePath = Fri3MerklePath;
    static BatchCommitResult BatchCommit(const std::vector<std::vector<gkr_field::Fp3>>& cols,
                                         const uint256& fs_seed)
    {
        return Fri3BatchCommit(cols, fs_seed);
    }
    static bool BatchVerify(const BatchProof& p, const uint256& fs_seed, std::string* why)
    {
        return Fri3BatchVerify(p, fs_seed, why);
    }
    static uint256 ColumnRoot(const std::vector<gkr_field::Fp3>& col, uint32_t n_coeffs)
    {
        return Fri3BatchColumnRoot(col, n_coeffs);
    }
    static uint256 LeafHash(const gkr_field::Fp3& v, uint32_t index)
    {
        return Fri3LeafHash(v, index);
    }
    static uint256 NodeHash(const uint256& l, const uint256& r) { return Fri3NodeHash(l, r); }
    static bool VerifyPath(const MerklePath& p, const uint256& root, uint32_t n_leaves)
    {
        return Fri3VerifyPath(p, root, n_leaves);
    }
    static uint32_t NumQueries() { return kRCFriBatchNumQueries; }
};

// ---------------------------------------------------------------------------
// Constraint system description.
// ---------------------------------------------------------------------------

/** Coset shift generator g = 7 (a generator of F_p^×; ord(g) = p−1 has odd
 *  factors, so g·x never lands in any power-of-two subgroup — Z_H(g·x) ≠ 0
 *  at every FRI evaluation point). */
inline constexpr gkr_field::Fp kAirCosetShift = 7;

enum class AirKind : uint8_t {
    kEverywhere = 0,  // vanish on every row
    kTransition,      // vanish on rows 0..N−2 (auto-multiplied by (X − h_last))
    kFirstRow,        // vanish on row 0 (auto-multiplied by Z_H/(X − 1))
    kLastRow,         // vanish on row N−1 (auto-multiplied by Z_H/(X − h_last))
};

/**
 * One per-row rule R_i(cur, next). `alg_degree` is the total multiplicative
 * degree of R_i in the column values (the module's declared degree bound —
 * it feeds the quotient-length computation, so understating it makes the
 * proof unverifiable, not unsound).
 */
template <typename F>
struct AirConstraint {
    const char* name{""};
    AirKind kind{AirKind::kEverywhere};
    uint32_t alg_degree{1};
    std::function<F(const std::vector<F>& cur, const std::vector<F>& next)> eval;
};

template <typename F>
struct AirConstraintSystem {
    uint32_t n_rows{0};     // N = |H|, power of two ≥ 2
    uint32_t n_columns{0};  // trace columns (quotient is committed additionally)
    std::vector<AirConstraint<F>> constraints;
    /** Preprocessed (public) columns: (column index, canonical values over H).
     *  The verifier regenerates the committed root from these values and
     *  rejects any deviation — table sides of lookups go here. */
    std::vector<std::pair<uint32_t, std::vector<F>>> preprocessed;
    /** Pin preprocessed columns through the batch's dual-OOD DEEP evals
     *  instead of regenerating the full LDE Merkle root: the verifier
     *  computes P(g·z1), P(g·z2) natively from the canonical values
     *  (barycentric over H — O(N) FIELD ops with shared denominators) and
     *  requires equality with evals_z1/evals_z2, which the batched FRI
     *  DEEP-binds to the committed codeword. A committed column that differs
     *  from the canonical polynomial (both deg < N) agrees at an FS OOD
     *  point w.p. ≤ (N−1)/|F|; the dual points square it. Used by the
     *  episode-scale instantiation where per-shard LDE+Merkle regeneration
     *  of every public column would dominate the O(Q) verifier. */
    bool preprocessed_pin_ood{false};

    [[nodiscard]] uint64_t ComposedDegreeBound(const AirConstraint<F>& c) const
    {
        const uint64_t d = static_cast<uint64_t>(c.alg_degree) * (n_rows - 1);
        switch (c.kind) {
        case AirKind::kEverywhere: return d;
        case AirKind::kTransition: return d + 1;
        default: return d + (n_rows - 1);
        }
    }
    [[nodiscard]] uint64_t MaxComposedDegreeBound() const
    {
        uint64_t m = 0;
        for (const auto& c : constraints) {
            const uint64_t b = ComposedDegreeBound(c);
            if (b > m) m = b;
        }
        return m;
    }
    /** Declared quotient coefficient count: deg Q ≤ deg C − N ⇒ len. */
    [[nodiscard]] uint32_t QuotientLen() const
    {
        const uint64_t dmax = MaxComposedDegreeBound();
        return dmax < n_rows ? 1u : static_cast<uint32_t>(dmax - n_rows + 1);
    }
};

// ---------------------------------------------------------------------------
// Proof / prover-result containers.
// ---------------------------------------------------------------------------

template <typename F>
struct AirQuotientProof {
    typename AirFriBackend<F>::BatchProof batch;  // trace columns + quotient (last)
    /** Supplemental per-query openings of every TRACE column at LDE index
     *  (query_index + n_lde/N) mod n_lde — the "next row" value P(ω_H·y),
     *  Merkle-verified against the SAME column roots as the batch proof. */
    std::vector<std::vector<typename AirFriBackend<F>::MerklePath>> next_openings;
};

struct AirProveOptions {
    /** Commit even when the remainder is nonzero (adversarial/self-test use). */
    bool force_commit_on_inexact{false};
    /** If nonzero, commit the quotient padded to this length instead of the
     *  declared QuotientLen() (adversarial/self-test use — the verifier's
     *  structural degree-bound check must reject the result). */
    uint32_t quotient_len_override{0};
};

template <typename F>
struct AirQuotientProveResult {
    bool ok{false};
    bool division_exact{false};
    std::string note;
    /** Remainder of C(X) mod Z_H(X) (N coefficients; all zero iff exact). */
    std::vector<F> remainder;
    AirQuotientProof<F> proof;
};

// ---------------------------------------------------------------------------
// Core API (templates instantiated in the .cpp for Fp2 and Fp3).
// ---------------------------------------------------------------------------

/**
 * Prover: interpolate the columns over H, derive the FS batching λ from the
 * (coset-shifted) trace column roots, build C(X) = Σ λ^i C_i(X) on an
 * extended subgroup, divide by Z_H(X) = X^N − 1 (exact iff every rule holds
 * on every row), coset-shift, commit trace + quotient in ONE batched FRI
 * instance, and attach next-row openings for the Q=128 query sites.
 */
template <typename F>
[[nodiscard]] AirQuotientProveResult<F> AirQuotientProve(
    const AirConstraintSystem<F>& cs, const std::vector<std::vector<F>>& columns,
    const uint256& fs_seed, const AirProveOptions& opt = {});

/**
 * Verifier: structural degree-bound checks (per-column committed lengths must
 * equal the declared bounds — this is what rejects an over-degree quotient),
 * batched-FRI verification, preprocessed-column root regeneration, FS λ
 * re-derivation, and the per-point identity C(y) = Q(y)·Z_H(y) at each of
 * the Q=128 query sites (Z_H(y) ≠ 0 by the coset shift). O(Q) work — no
 * full-row scan.
 */
template <typename F>
[[nodiscard]] bool AirQuotientVerify(const AirConstraintSystem<F>& cs,
                                     const AirQuotientProof<F>& proof, const uint256& fs_seed,
                                     std::string* why = nullptr);

/** FS challenge over fs_seed ‖ label ‖ roots ‖ extra (SHA256d, domain-tagged). */
[[nodiscard]] uint256 AirChallengeDigest(const uint256& fs_seed, const char* label,
                                         const std::vector<uint256>& roots,
                                         const std::vector<uint32_t>& extra);

/** Degree-4 E2M1 acceptance selector over the nibble bits (field-generic
 *  mirror of gkr_air::AirAcceptNibblePoly; cross-checked in tests). */
template <typename F>
[[nodiscard]] F AirAcceptPoly(const F& b0, const F& b1, const F& b2, const F& b3);

/** Root of `values` read as evaluations over H (|values| = N, power of two),
 *  committed in the coset-shifted coefficient basis at `n_coeffs` —
 *  byte-identical to the root AirQuotientProve's batched FRI produces for the
 *  same column (used for the two-epoch FS discipline of instantiations that
 *  draw challenges from committed epoch-1 columns). */
template <typename F>
[[nodiscard]] uint256 AirCommittedValuesRoot(const std::vector<F>& values, uint32_t n_coeffs);

// ---------------------------------------------------------------------------
// Concrete instantiation: the Extract-sampler + dequant + LogUp rules of one
// tile (matmul_v4_rc_gkr_air TileWitness) as an AIR over N = 2^k rows.
// Column layout (all length N):
//   base columns 0..31 (feed the γ/α FS derivation):
//     act, kappa, kb0..3, h, hb0..3, mixed, mb0..3, acc, mu, pos, inv_live,
//     u_mix, gold_q, gold_v, v_low28, vb0..3, e0, e1, mu_out, out
//   LogUp columns 32..36 (built AFTER γ, α are fixed):
//     phi, t_fp (PREPROCESSED — canonical T_M fingerprints), m, psi, S
// Candidate rows are the real TileWitness cands; padding rows carry the
// neutral assignment (mixed = 1, a rejected E2M1 code, acc = 0, pos = 32,
// act = 0) which satisfies every rule. The 16-bit-limb range obligations of
// the row-scan AIR remain LogUp membership rows (documented in the header
// block above) — they ride the same φ/ψ machinery and are not identities.
// SCOPE: this instantiation covers the sampler core (C-E2..E6, C-E9), the
// dequant output rule (C-E10) and the T_M LogUp. The C-E1 keystream binding
// and the C-E7/E8 int64-embedding rows are degree ≤ 2 identities over
// additional bit columns (64 bits of y_lo/y_hi plus the ChaCha byte column)
// and slot into the same machinery unchanged; they are additional columns,
// not a different construction.
// ---------------------------------------------------------------------------

enum RcSamplerCol : uint32_t {
    kColAct = 0,
    kColKappa,
    kColKb0, kColKb1, kColKb2, kColKb3,
    kColH,
    kColHb0, kColHb1, kColHb2, kColHb3,
    kColMixed,
    kColMb0, kColMb1, kColMb2, kColMb3,
    kColAcc,
    kColMu,
    kColPos,
    kColInvLive,
    kColUMix,
    kColGoldQ,
    kColGoldV,
    kColVLow28,
    kColVb0, kColVb1, kColVb2, kColVb3,
    kColE0,
    kColE1,
    kColMuOut,
    kColOut,
    kColPad0,          // reserved zero column (keeps the base-column count round)
    kRcSamplerBaseCols,          // = 32
    kColPhi = kRcSamplerBaseCols,
    kColTfp,
    kColM,
    kColPsi,
    kColS,
    kRcSamplerNumCols            // = 37
};

/** The constraint set for row count `n_rows`, LogUp challenges (γ, α), the
 *  public scale bits of `scale_e`, and the consensus T_M table. Includes the
 *  preprocessed t_fp column (a pure function of γ and T_M). */
template <typename F>
[[nodiscard]] AirConstraintSystem<F> BuildRcSamplerConstraintSystem(
    uint32_t n_rows, const F& gamma, const F& alpha, uint8_t scale_e,
    const gkr_air::TableTM& tm);

template <typename F>
struct RcSamplerBuild {
    bool ok{false};
    std::string note;
    uint32_t n_rows{0};
    F gamma{};
    F alpha{};
    std::vector<std::vector<F>> columns;  // kRcSamplerNumCols columns of n_rows
    AirConstraintSystem<F> cs;
};

/**
 * Build the full AIR instance from a real TileWitness: base columns from the
 * candidate rows, then γ/α by FS over the committed base-column roots (the
 * two-epoch discipline — FriBatchColumnRoot is byte-identical to the roots
 * the later FriBatchCommit produces), then the LogUp columns and the
 * constraint system.
 */
template <typename F>
[[nodiscard]] RcSamplerBuild<F> BuildRcSamplerInstance(const gkr_air::TileWitness& w,
                                                       const gkr_air::TableTM& tm,
                                                       const uint256& fs_seed);

/**
 * Verifier-side convenience: re-derive γ/α from the proof's base-column
 * roots, rebuild the constraint system with the PUBLIC scale_e, and run
 * AirQuotientVerify (which also pins the preprocessed t_fp column root).
 */
template <typename F>
[[nodiscard]] bool RcSamplerAirVerify(const AirQuotientProof<F>& proof, const uint256& fs_seed,
                                      uint8_t scale_e, const gkr_air::TableTM& tm,
                                      std::string* why = nullptr);

} // namespace matmul::v4::rc::air_quotient

#endif // BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_H
