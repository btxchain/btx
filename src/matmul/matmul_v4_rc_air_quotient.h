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
//
// BACKEND POLICY PARAMETER: AirQuotientProof / AirQuotientProve /
// AirQuotientVerify (and AirCommittedValuesRoot) additionally take an
// explicit `Backend` policy DEFAULTED to AirFriBackend<F>, because field
// type alone cannot distinguish two proximity modules over the SAME field:
// Fp3 has both the SHA256d-Merkle Fri3Batch* module below (per-column
// trees — the episode/base path) and the algebraic-hash ROW-WISE
// Fri3AlgBatch* module (matmul_v4_rc_fri_ext3_alg.h — the recursion path).
// Every existing caller keeps writing AirQuotientProof<Fp3> /
// AirQuotientProve<Fp3>(...) and gets AirFriBackend<Fp3> via the default —
// source- and behavior-identical. The recursion instantiates
// AirQuotientProve<Fp3, AirFriBackendAlg<Fp3>> (policy defined in
// matmul_v4_rc_air_quotient_alg.h, which this header deliberately does NOT
// include).
//
// A policy declares `static constexpr bool kRowWiseLayout = true` iff its
// batch commits ONE row tree over all columns (one authentication path per
// query carrying the whole row) instead of one tree per column. The two
// AirFriBackend specializations below carry no such member and therefore
// read as per-column. The row-wise layout changes what the proof can carry
// (no per-column roots) — see AirQuotientProof for the shape differences.
// ---------------------------------------------------------------------------
template <typename F>
struct AirFriBackend;

/** true iff `Backend` declares the row-wise commitment layout (see above). */
template <typename Backend>
inline constexpr bool AirBackendIsRowWise = requires { requires Backend::kRowWiseLayout; };

/** Opt-in for row-wise backends whose BatchCommit intentionally returns no
 * dense column_lde and instead supplies selected openings on a second pass. */
template <typename Backend>
inline constexpr bool AirBackendStreamsRowOpenings = false;

/** true iff a per-column backend emits query openings without retaining the
 * complete dense column-LDE matrix returned by BatchCommit. */
template <typename Backend>
inline constexpr bool AirBackendStreamsColumnOpenings =
    requires { requires Backend::kStreamsColumnOpenings; };

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

/**
 * Same SHA256d-Merkle Fri3BatchProof format as AirFriBackend<Fp3>, with
 * two-pass per-column LDE/tree recomputation and no retained W x LDE matrix.
 * Supplemental next-row paths are retained during pass two.
 */
struct AirFriBackendFp3StreamingColumns
    : public AirFriBackend<gkr_field::Fp3> {
    static constexpr bool kStreamsColumnOpenings = true;

    static BatchCommitResult BatchCommit(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        const uint256& fs_seed)
    {
        return Fri3BatchCommitStreamingColumns(cols, fs_seed);
    }

    static BatchCommitResult BatchCommitWithStep(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        const uint256& fs_seed,
        uint32_t supplemental_index_step)
    {
        return Fri3BatchCommitStreamingColumnsWithStep(
            cols, fs_seed, supplemental_index_step);
    }

    static bool OpenColumns(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        uint32_t n_coeffs,
        const std::vector<uint32_t>& indices,
        const std::vector<uint256>& expected_roots,
        std::vector<std::vector<MerklePath>>& out,
        std::string* why)
    {
        return Fri3BatchOpenColumnsStreaming(
            cols, n_coeffs, indices, expected_roots, out, why);
    }
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
 * Exact row-vector root pin for the Split-RAP MultiRow-V2 backend.
 *
 * A row-wise commitment has no independently meaningful per-column root.
 * Therefore a caller that needs proof-owned preprocessing must pin the
 * complete ordered R0 or Rdep row group, including its exact column list.
 * The Split-RAP verifier compares this root to the committed group root; that
 * root is already absorbed by both the AIR batching challenge and final FRI
 * seed.  This is deliberately separate from `preprocessed_roots`, whose
 * entries are per-column roots and remain unsupported for row-wise proofs.
 */
enum class AirPreprocessedRowGroupRole : uint8_t {
    kR0 = 0,
    kRdep = 1,
};

struct AirPreprocessedRowGroupRoot {
    uint16_t version{1};
    AirPreprocessedRowGroupRole role{
        AirPreprocessedRowGroupRole::kR0};
    std::vector<uint32_t> ordered_columns;
    uint256 root{};

    bool operator==(const AirPreprocessedRowGroupRoot&) const = default;
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
    /** Preprocessed columns satisfied by ROOT EQUALITY against a SUPPLIED
     *  root (column index → expected committed root) instead of canonical
     *  values: the verifier requires batch.columns[idx].root == root — an
     *  O(1) compare, stronger than the OOD pin (exact commitment equality,
     *  not two-point agreement). The supplied root's own provenance (e.g. a
     *  Merkle slice opening against an episode-level preprocessed commitment
     *  P_root, Stage A of the sublinear-aggregation program) is the CALLER's
     *  obligation — this module only binds the shard's committed column to
     *  it. A column may appear in both lists (values pin AND root equality)
     *  when the caller needs the values bound to proof-public inputs too. */
    std::vector<std::pair<uint32_t, uint256>> preprocessed_roots;
    /**
     * Split-RAP-only root equality for complete ordered row groups.  Legacy
     * per-column and row-wise verifiers ignore no entries: unsupported use is
     * rejected fail-closed.
     */
    std::vector<AirPreprocessedRowGroupRoot>
        preprocessed_row_group_roots;

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

/**
 * Proof container, parameterized on the proximity Backend policy (defaulted
 * to AirFriBackend<F>, so all existing AirQuotientProof<F> spellings keep
 * their exact type and layout).
 *
 * PER-COLUMN backends (the default AirFriBackend<F>):
 *   next_openings[qi] has W entries — for each trace column a MerklePath
 *   opening the "next row" value P(ω_H·y) at LDE index
 *   (query_index + n_lde/N) mod n_lde against that column's OWN root from
 *   the batch proof. trace_commit is unused (zero).
 *
 * ROW-WISE backends (kRowWiseLayout, e.g. AirFriBackendAlg<Fp3>):
 *   next_openings[qi] has exactly 2 entries:
 *     [0] the next-row opening: index = (query_index + n_lde/N) mod n_lde,
 *         values = ALL W+1 column values of that row (the full row is needed
 *         to recompute the row leaf), siblings against batch.row_commit.
 *     [1] the trace-binding opening: index = query_index, values EMPTY (the
 *         leaf is recomputed from the batch query's own opened trace values
 *         [0..W)), siblings against the trace-only row root R_T below.
 *   trace_commit = packed R_T, the row root over the W coset-shifted TRACE
 *   columns only. The quotient column depends on the FS batching challenge
 *   λ, so it cannot ride the tree that seeds λ; R_T is the λ-seeding trace
 *   commitment, and the per-query [1] openings bind it to agree with the
 *   batch's committed trace at every FS query site (same α = 17/32 query
 *   soundness as the FRI itself — the standard trace/composition binding).
 */
template <typename F, typename Backend = AirFriBackend<F>>
struct AirQuotientProof {
    typename Backend::BatchProof batch;  // trace columns + quotient (last)
    /** Supplemental per-query openings — see the layout note above. */
    std::vector<std::vector<typename Backend::MerklePath>> next_openings;
    /** ROW-WISE backends only: the packed trace-only row root R_T that seeds
     *  the constraint-batching challenge λ. Zero/unused for per-column
     *  backends (their λ is seeded by the batch's per-column trace roots). */
    uint256 trace_commit{};
};

struct AirProveOptions {
    /** Commit even when the remainder is nonzero (adversarial/self-test use). */
    bool force_commit_on_inexact{false};
    /** If nonzero, commit the quotient padded to this length instead of the
     *  declared QuotientLen() (adversarial/self-test use — the verifier's
     *  structural degree-bound check must reject the result). */
    uint32_t quotient_len_override{0};
    /**
     * Optional per-column trace roots already computed by an earlier
     * commit-then-challenge phase. The vector is either empty or exactly
     * `cs.n_columns` long; a null entry is recomputed normally.
     *
     * These are checked hints, not trusted inputs: the batched FRI commit
     * still recomputes every column root and AirQuotientProve rejects any
     * mismatch before returning a proof. Per-column backends only.
     */
    std::vector<uint256> checked_trace_root_hints;
};

struct AirQuotientRowTileAudit {
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t composition_rows{0};
    uint32_t tile_rows{0};
    uint32_t tiles_visited{0};
    bool callback_schedule_executed{false};
    bool composition_values_identical{false};
    bool quotient_coefficients_identical{false};
    bool valid{false};
    std::string note;
};

enum class AirExternalStoreBackend : uint8_t {
    kMemory = 0,
    kAnonymousTempFile = 1,
};

class AirFp3ExternalColumnStore {
public:
    AirFp3ExternalColumnStore(
        AirExternalStoreBackend backend,
        uint32_t columns,
        uint32_t rows);
    ~AirFp3ExternalColumnStore();

    AirFp3ExternalColumnStore(
        const AirFp3ExternalColumnStore&) = delete;
    AirFp3ExternalColumnStore& operator=(
        const AirFp3ExternalColumnStore&) = delete;

    [[nodiscard]] bool IsOpen() const;
    [[nodiscard]] bool Write(
        uint32_t column,
        uint32_t offset,
        const std::vector<gkr_field::Fp3>& values,
        std::string* why = nullptr);
    [[nodiscard]] bool Read(
        uint32_t column,
        uint32_t offset,
        uint32_t count,
        std::vector<gkr_field::Fp3>& out,
        std::string* why = nullptr);
    [[nodiscard]] uint64_t PeakLiveCells() const;
    [[nodiscard]] uint64_t ResidentCells() const;

private:
    AirExternalStoreBackend backend_;
    uint32_t columns_;
    uint32_t rows_;
    std::vector<std::vector<gkr_field::Fp3>> memory_;
    void* file_{nullptr};
    uint64_t peak_live_cells_{0};
};

struct AirQuotientSpillAudit {
    AirQuotientRowTileAudit quotient;
    AirExternalStoreBackend backend{
        AirExternalStoreBackend::kMemory};
    uint64_t store_peak_live_cells{0};
    uint64_t store_resident_cells{0};
    bool all_lde_columns_spilled{false};
    bool all_tiles_reloaded{false};
    bool byte_canonical_roundtrip{false};
    bool valid{false};
    std::string note;
};

/**
 * Bounded Fp3 audit for the quotient row-tile seam.  The callback schedule
 * evaluates the same composition rows, in fixed-size contiguous tiles, and
 * compares both the composition evaluations and interpolated coefficients to
 * the dense schedule.  It does not commit a production proof.
 */
[[nodiscard]] AirQuotientRowTileAudit
AuditAirQuotientRowTilesFp3(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const uint256& fs_seed,
    uint32_t tile_rows);

[[nodiscard]] AirQuotientSpillAudit
AuditAirQuotientSpillFp3(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const uint256& fs_seed,
    uint32_t tile_rows,
    AirExternalStoreBackend backend);

template <typename F, typename Backend = AirFriBackend<F>>
struct AirQuotientProveResult {
    bool ok{false};
    bool division_exact{false};
    std::string note;
    /** Remainder of C(X) mod Z_H(X) (N coefficients; all zero iff exact). */
    std::vector<F> remainder;
    AirQuotientProof<F, Backend> proof;
};

// ---------------------------------------------------------------------------
// COMPOSITION-SITE MEMORY GUARD.
//
// WHY THIS EXISTS (second materialization site).  Streaming the batch commit
// bounded the (W+1) x n_lde column LDE, but the prover has a SECOND O(W x M)
// materialization that streaming the commit does not touch: the composition
// matrix, i.e. every trace column evaluated on the size-M extended subgroup.
// At the MEASURED real-role arity-4 parent shape (W = 384,984, N = 256,
// M = 2,048, Fp3 = 24 B) that matrix alone is
//     384,984 x 2,048 x 24 B = 18,922,733,568 B = 17.6 GiB,
// which is what OOM-killed a 24 GiB-capped real-width self-prove after 6 h.
// Neither kRCFri3AlgBatchMaxColumns (a COLUMN cap) nor
// Fri3AlgCommitFitsMemoryBudget (a COMMIT-site guard) sees this site at all.
//
// HOW IT IS BOUNDED.  The composition loop reads exactly two rows of that
// matrix per output point: row j and row jn = (j + M/N) mod M.  Those two row
// indices are always congruent mod stepM = M/N, i.e. they lie in the SAME
// coset of the order-N subgroup H_N inside the order-M subgroup.  So the
// matrix can be built and consumed ONE COSET AT A TIME: a W x N slab instead
// of W x M, a factor of stepM = M/N (8 at the real shape).  See
// AirQuotientCompositionPeakBytes.
//
// MEASURED RESULT (real-role arity-4 four-slot aggregate-root self-prove,
// parent_cols = 384,984, 16 prover threads, systemd scope MemoryMax=20G,
// MemorySwapMax=0):  the prove COMPLETED — prove_ok=true, verify_ok=true,
// root_produced=true, test exit 0.  getrusage max RSS 17,457,560 KiB
// = 16.65 GiB; cgroup memory.peak 17,891,889,152 B = 16.66 GiB.  The same
// workload was previously OOM-killed at a 24 GiB cap after 6 h 11 m.
// AirQuotientProve total 4,003.9 s, of which the composition phase is 36.5 s
// (0.9%): trace_ntt+roots 1,695.4 s, composition(M rows) 36.5 s,
// lde+leafcommit+fri 1,599.1 s, supplemental_openings 672.8 s.
// The peak is no longer here — it is the FRI/supplemental phase.
//
// This is a FOOTPRINT decision only.  Field arithmetic here is exact modular
// arithmetic and gkr_field::Add/Sub/Mul all return canonical residues in
// [0, p), so two mathematically equal evaluation schedules produce
// bit-identical values by construction — not by luck and not approximately.
// ---------------------------------------------------------------------------

/**
 * Fail-closed peak-residency ceiling for the composition site, in bytes.
 * Env override: BTX_AIRQ_COMPOSITION_PEAK_BYTES.
 *
 * Liveness guard, not a soundness gate: it never weakens a check, it converts
 * an unsurvivable allocation into a clean, diagnosable ok=false BEFORE any of
 * the big vectors are allocated.
 */
inline constexpr uint64_t kRCAirQuotientCompositionPeakByteCeiling =
    uint64_t{32} << 30; // 32 GiB

/**
 * Projected peak prover-held bytes at the composition site for this shape.
 *
 *   coefficient matrix   columns x n_rows x elem_bytes   (held across cosets)
 *   evaluation slab      columns x (coset_blocked ? n_rows : composition_rows)
 *                                 x elem_bytes
 *   composition vector   composition_rows x elem_bytes
 *   per-thread frames    2 x columns x elem_bytes x threads  (cur/nxt)
 *
 * Pure function of shape — no transcript, no soundness parameter.
 */
[[nodiscard]] uint64_t AirQuotientCompositionPeakBytes(uint64_t columns,
                                                       uint32_t n_rows,
                                                       uint32_t composition_rows,
                                                       uint64_t elem_bytes,
                                                       bool coset_blocked,
                                                       uint32_t threads);

/**
 * Fail-closed admission check for the composition site.  Returns false (and
 * fills `why` / `projected`) when the projected peak exceeds the ceiling.
 */
[[nodiscard]] bool AirQuotientCompositionFitsMemoryBudget(uint64_t columns,
                                                          uint32_t n_rows,
                                                          uint32_t composition_rows,
                                                          uint64_t elem_bytes,
                                                          bool coset_blocked,
                                                          uint32_t threads,
                                                          uint64_t* projected,
                                                          std::string* why);

// ---------------------------------------------------------------------------
// Core API (templates instantiated in the .cpp for Fp2 and Fp3).
// ---------------------------------------------------------------------------

/**
 * Prover: interpolate the columns over H, derive the FS batching λ from the
 * (coset-shifted) trace column roots, build C(X) = Σ λ^i C_i(X) on an
 * extended subgroup, divide by Z_H(X) = X^N − 1 (exact iff every rule holds
 * on every row), coset-shift, commit trace + quotient in ONE batched FRI
 * instance, and attach next-row openings for the Q query sites (Q from the
 * Backend policy; 128 on the SHA paths, 148 on the alg recursion path).
 */
template <typename F, typename Backend = AirFriBackend<F>>
[[nodiscard]] AirQuotientProveResult<F, Backend> AirQuotientProve(
    const AirConstraintSystem<F>& cs, const std::vector<std::vector<F>>& columns,
    const uint256& fs_seed, const AirProveOptions& opt = {});

/**
 * Verifier: structural degree-bound checks (per-column committed lengths must
 * equal the declared bounds — this is what rejects an over-degree quotient),
 * batched-FRI verification, preprocessed-column root regeneration, FS λ
 * re-derivation, and the per-point identity C(y) = Q(y)·Z_H(y) at each of
 * the Q query sites (Z_H(y) ≠ 0 by the coset shift). O(Q) work — no
 * full-row scan.
 *
 * ROW-WISE backends: the value-pinned preprocessed-column modes require
 * preprocessed_pin_ood (there are no per-column roots to regenerate), and
 * the preprocessed_roots root-equality mode is unsupported (same reason);
 * both are rejected with an explicit message rather than mis-verified.
 *
 * `verify_threads`: the Q per-query checks (Merkle re-hash + quotient
 * identity) are mutually independent, so they may be split across threads
 * with NO change to the accepted/rejected verdict — same field arithmetic,
 * same Merkle roots, same equality tests, just reordered. Default 1 keeps
 * every existing caller byte-for-byte sequential (the parameter is new and
 * additive). >1 only takes effect for ROW-WISE backends built with OpenMP;
 * other backends and non-OpenMP builds silently ignore it and stay
 * sequential — never a correctness fork, only a wall-clock one. When
 * multiple queries fail, `why` receives an arbitrary one of their messages
 * rather than deterministically the first (diagnostic text only; the
 * accept/reject boolean is unaffected).
 */
template <typename F, typename Backend = AirFriBackend<F>>
[[nodiscard]] bool AirQuotientVerify(const AirConstraintSystem<F>& cs,
                                     const AirQuotientProof<F, Backend>& proof,
                                     const uint256& fs_seed, std::string* why = nullptr,
                                     uint32_t verify_threads = 1);

/** FS challenge over fs_seed ‖ label ‖ roots ‖ extra (SHA256d, domain-tagged). */
[[nodiscard]] uint256 AirChallengeDigest(const uint256& fs_seed, const char* label,
                                         const std::vector<uint256>& roots,
                                         const std::vector<uint32_t>& extra);

// ===========================================================================
// PR-89: POSEIDON2 ROUTE for the AIR challenge digest.  NOT ACTIVATED.
//
// WHY.  The measured g4 producer-endpoint floor is 58.6 s, of which 41.1 s is
// one Split-RAP prove over the parent's in-AIR replay of airq_lambda and
// 16.2 s is building that replay's constraint system.  Both costs are set by
// the SHA256d vertical chip, which charges lane_rows = 1024 per compression
// and schedules next_pow2(compressions) instances: airq_lambda's 113-byte
// preimage is 3 compressions, so 1024 * next_pow2(3) = 4096 rows is the FLOOR
// for ANY SHA256d replay of it.  It is not tunable from this file.  The
// in-AIR Poseidon2 chip (matmul_v4_rc_stage3_poseidon_air.{h,cpp}) charges
// ONE row per permutation, so the same logical preimage costs a handful of
// rows instead of 4096.
//
// WHAT IS AND IS NOT CHANGED HERE.  AirChallengeDigest itself is UNTOUCHED and
// is still the default on every caller.  It is a SHARED helper: ten distinct
// labels route through it ("airq_lambda", "airq_gamma", "airq_alpha",
// "airq_split_rap_*", "airq_two_epoch_r1", "ep_pre_leaf", "ep_shard",
// "ep_air_root_seed", "stage3_chunk_rlc_coeff_v1"), and it is drawn INSIDE
// AirQuotientProve/AirQuotientVerify, which are templated over the backend and
// therefore serve the FROZEN SHA lanes (kRCFri3BatchProofVersion = 5,
// kRCFriBatchProofVersion = 5) as well as the algebraic one.  Replacing its
// body unconditionally would silently re-transcript those frozen lanes AND
// break stage3_recursive_parent_air's SHA companion, which REQUIREs its in-CS
// SHA output to equal this function's native return.  So the Poseidon2 form is
// added as a SEPARATE, SEPARATELY VERSIONED route and nothing selects it yet.
// ===========================================================================

/** Domain tag of the Poseidon2 route.  Distinct string from the SHA256d
 *  route's "BTX_RC_AIRQ_V1", and absorbed length-prefixed, so no preimage can
 *  be shared between the two routes. */
inline constexpr char kAirChallengeP2DomainTag[] = "BTX_RC_AIRQ_P2_V1";

/** Codec/proof version of the Poseidon2 route.  This is a NEW number on a NEW
 *  lane; kRCFri3BatchProofVersion = 5 and kRCFriBatchProofVersion = 5 are
 *  frozen SHA paths and are NOT touched. */
inline constexpr uint32_t kAirChallengeP2RouteVersion = 8;

/** Route activation. False: no producer or verifier selects the Poseidon2
 *  challenge, and every shipped proof still derives airq_lambda by SHA256d.
 *
 *  WHEN TRUE: row-wise (algebraic / recursion) AirQuotientProve/Verify select
 *  AirChallengeDigestP2 via AirChallengeDigestForBackend; per-column SHA
 *  backends keep AirChallengeDigest so frozen SHA lanes stay byte-identical.
 *  Flip only with measured evidence that the four-slot parent decoder and the
 *  g4 producer companion also consume the P2 route (see recursive_parent_air).
 */
inline constexpr bool kAirChallengeP2Activated = true;

/** true iff this Backend should draw AIR challenges on the Poseidon2 route.
 *  Row-wise algebraic backends only; SHA per-column backends never. */
template <typename Backend>
inline constexpr bool AirBackendUsesP2Challenge =
    kAirChallengeP2Activated && AirBackendIsRowWise<Backend>;

/**
 * Select SHA256d or Poseidon2 digest for the same logical preimage.
 * `use_p2` is the sole route bit; callers must not pass true for frozen SHA
 * lanes (use AirBackendUsesP2Challenge / AirChallengeDigestForBackend).
 */
[[nodiscard]] uint256 AirChallengeDigestSelected(
    bool use_p2, const uint256& fs_seed, const char* label,
    const std::vector<uint256>& roots, const std::vector<uint32_t>& extra);

/** Backend-gated digest: Poseidon2 iff AirBackendUsesP2Challenge<Backend>. */
template <typename Backend>
[[nodiscard]] uint256 AirChallengeDigestForBackend(
    const uint256& fs_seed, const char* label, const std::vector<uint256>& roots,
    const std::vector<uint32_t>& extra)
{
    return AirChallengeDigestSelected(AirBackendUsesP2Challenge<Backend>, fs_seed,
                                      label, roots, extra);
}

/**
 * INJECTIVE Fp-lane encoding of the AirChallengeDigest preimage
 * (tag ‖ version ‖ seed ‖ label ‖ roots ‖ extra).  Exposed rather than kept
 * private for two reasons: an in-AIR replay must absorb EXACTLY these lanes,
 * and the injectivity property is testable directly on the lane vector.
 *
 * Every variable-length section is length-prefixed, so the concatenation is
 * prefix-free and no two distinct preimages produce the same lane list.
 *
 * THE GOLDILOCKS ALIASING CLASS, and why this encoding is 32-bit-lane based.
 * gkr_field::FromU64(x) is x mod p with p = 2^64 - 2^32 + 1.  For every
 * x < 2^32 - 1 the value x + p is a DIFFERENT u64 that maps to the SAME field
 * element.  A uint256 absorbed as four u64 limbs is therefore NOT injective:
 * each limb has ~2^32 aliasing partners, so two DIFFERENT trace-commitment
 * roots can yield an IDENTICAL lane vector and hence an IDENTICAL challenge.
 * Splitting every u64 into two 32-bit halves keeps each absorbed lane strictly
 * below 2^32 < p, where reduction mod p is the identity, so the map is
 * injective by construction.  Driven by an explicit x + p witness in
 * matmul_v4_rc_air_quotient_tests.cpp.
 */
[[nodiscard]] std::vector<gkr_field::Fp> AirChallengeP2Lanes(
    const uint256& fs_seed, const char* label, const std::vector<uint256>& roots,
    const std::vector<uint32_t>& extra);

/**
 * Poseidon2 form of AirChallengeDigest over the same logical preimage, hashed
 * with alg_hash::SpongeHashFp — the primitive that is ALREADY this backend's
 * Merkle hash, so no new hash and no new soundness assumption is introduced.
 * The four output lanes are packed little-endian into the returned uint256;
 * each is a canonical Goldilocks element (< p), so the packing is injective.
 */
[[nodiscard]] uint256 AirChallengeDigestP2(const uint256& fs_seed, const char* label,
                                           const std::vector<uint256>& roots,
                                           const std::vector<uint32_t>& extra);

/** Permutation count AirChallengeDigestP2 costs for a given preimage shape —
 *  i.e. the ROW count of an in-AIR Poseidon2 replay, at 1 row/permutation.
 *  Computed from the same 10*-padding rule SpongeHashFp applies. */
[[nodiscard]] uint32_t AirChallengeP2Permutations(size_t n_lanes);

/** Degree-4 E2M1 acceptance selector over the nibble bits (field-generic
 *  mirror of gkr_air::AirAcceptNibblePoly; cross-checked in tests). */
template <typename F>
[[nodiscard]] F AirAcceptPoly(const F& b0, const F& b1, const F& b2, const F& b3);

/** Root of `values` read as evaluations over H (|values| = N, power of two),
 *  committed in the coset-shifted coefficient basis at `n_coeffs` —
 *  byte-identical to the root AirQuotientProve's batched FRI produces for the
 *  same column (used for the two-epoch FS discipline of instantiations that
 *  draw challenges from committed epoch-1 columns). For ROW-WISE backends
 *  this is the Backend's ColumnRoot semantic — the packed root of a
 *  SINGLE-column row tree (a per-column FS-binding digest; it does NOT
 *  appear inside a multi-column batch proof, whose unit of commitment is
 *  the whole row). */
template <typename F, typename Backend = AirFriBackend<F>>
[[nodiscard]] uint256 AirCommittedValuesRoot(const std::vector<F>& values, uint32_t n_coeffs);

// ---------------------------------------------------------------------------
// Concrete instantiation: the Extract-sampler + dequant + LogUp rules of one
// tile (matmul_v4_rc_gkr_air TileWitness) as an AIR over N = 2^k rows.
// Column layout (all length N):
//   base columns 0..31 (feed the γ/α FS derivation):
//     act, kappa, kb0..3, h, hb0..3, mixed, mb0..3, acc, mu, pos, inv_live,
//     u_mix, gold_q, gold_v, v_low28, vb0..3, e0, e1, mu_out, out
//   LogUp columns 32..36 (built AFTER γ, α are fixed):
//     phi, t_fp (COMMITTED fingerprint f, bound to the preprocessed table
//            columns below by the in-circuit logup.tfp.bind identity), m, psi, S
//   Preprocessed table columns 37..39 (CHALLENGE-INDEPENDENT canonical T_M
//     entries, verifier-regenerated): tbl_a=n, tbl_b=acc[n], tbl_c=mu[n]
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
    kColTfp,           // COMMITTED phase-2 fingerprint f, bound by logup.tfp.bind
    kColM,
    kColPsi,
    kColS,
    // Challenge-INDEPENDENT preprocessed table-entry columns (n, acc[n], mu[n]).
    // The verifier regenerates their roots; f = kColTfp is forced to
    // tbl_a + gamma*tbl_b + gamma^2*tbl_c by the in-circuit logup.tfp.bind
    // identity, so the fingerprint carries no post-commitment challenge in any
    // PREPROCESSED column (RAP two-phase order restored; enables challenge-
    // independent bytecode migration of the CoupledExtract transport lane).
    kColTblA,
    kColTblB,
    kColTblC,
    kRcSamplerNumCols            // = 40
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
 * NOTE: the RcSampler* instantiation stays on the DEFAULT backend — its
 * two-epoch γ/α discipline reads per-column base roots out of the batch
 * proof, which a row-wise backend does not carry.
 */
template <typename F>
[[nodiscard]] bool RcSamplerAirVerify(const AirQuotientProof<F>& proof, const uint256& fs_seed,
                                      uint8_t scale_e, const gkr_air::TableTM& tm,
                                      std::string* why = nullptr);

} // namespace matmul::v4::rc::air_quotient

#endif // BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_H
