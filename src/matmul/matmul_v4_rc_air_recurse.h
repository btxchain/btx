// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_AIR_RECURSE_H
#define BTX_MATMUL_MATMUL_V4_RC_AIR_RECURSE_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Poseidon2-as-AIR gadget — Piece 3 of the Stage-C recursion program
// (scratchpad/stage-c-buildable-spec.md §3.2 A/B, §3.4, §6). First half of
// the recursion module: reusable AirConstraint<Fp3> builders expressing
// "these witnessed cells are a correct evaluation of the AlgHash permutation
// / the fixed 2→1 Merkle compression / one Merkle-path level" as low-degree
// polynomial identities, plus the honest-witness builders and the cell-count
// measurement that decides §3.4 feasibility. The full verifier AIR (V_CS,
// spec §3/§4) is Piece 4 and assembles these builders; it is NOT here.
//
// FLATTENED 130-CELL LAYOUT (spec §3.4 — the decisive parameter choice).
// One permutation occupies ONE row of exactly
//     12 input lanes + 118 S-box output witnesses = 130 cells
// (118 = R_F·t + R_P = 8·12 + 22, spec §1.1). Everything BETWEEN S-boxes —
// the up-front M_E, the per-round M_E / M_I linear layers and the round-
// constant additions — is Fp-AFFINE in the witnessed cells, so it is
// VIRTUAL: never witnessed, folded symbolically into the constraint
// polynomials. Each S-box input is an affine form A_s(cells) over the cells
// witnessed strictly earlier in evaluation order (S-box s of a full round
// reads the previous layer's 12 substituted outputs through M_E; a partial
// S-box reads lane 0 of the M_I-propagated state, which is affine in the
// entering state and the previous partial outputs). The 118 constraints are
//     cell[sbox_s] − ( A_s(cells) )^7  =  0            (alg_degree 7)
// and the 12 permutation OUTPUT lanes are affine forms Out_j(cells) — also
// virtual, evaluated on demand (PermOutputLane) and consumed by the Merkle
// glue as degree-1 expressions. Compare the row-per-round strip layout
// (§3.2 A): 30 rows × 12 columns = 360 cells and the same max degree 7; the
// flattened layout is what brings one child FRI verifier under the ~2^20
// cell budget (§3.4: 130/2000 vs 360/2000 of the SHA cost).
//
// Degree accounting: the affine substitution keeps every constraint at total
// multiplicative degree 7 (the x^7 S-box on an affine form), so the composed
// degree bound is 7·(N−1) for kEverywhere rows (AirConstraintSystem::
// ComposedDegreeBound) and QuotientLen ≈ 6N — exactly the §3.3 profile. All
// identities are written over Fp3 (the recursion field); every honest cell
// is a base-field embedding Fp3::FromFp(x), and the identities hold in Fp3
// because Fp ⊂ Fp3 is a ring embedding (x^7 and the Fp-linear layers commute
// with the embedding).
//
// GADGETS
//   1. BuildPermRoundConstraints    — the 118 degree-7 S-box identities of
//                                     one permutation (kEverywhere; a row
//                                     satisfies them iff its 130 cells are a
//                                     correct Permute evaluation).
//   2. BuildCompressCapacityConstraints — the fixed 2→1 compression wiring
//                                     (spec §1.7): capacity lanes pinned to
//                                     [D, 0, 0, 0]. With (1), a row is a
//                                     correct Compress(in[0..4), in[4..8))
//                                     evaluation; digest = Out_{0..3}.
//   3. BuildMerkleGlueConstraints   — one Merkle-path level (spec §3.2 B):
//                                     direction-bit booleanity (deg 2), the
//                                     (acc, sibling)-in-mp_dir-order input
//                                     wiring (deg 2), capacity pins (deg 1),
//                                     and the kTransition accumulator update
//                                     acc(next) = Out(cur) (deg 1).
//   4. BuildMerkleRootBoundaryConstraints — kLastRow pin acc = public root
//                                     (spec §3.2 F, the glue's terminal).
// Witness side: BuildPermWitness runs the REAL alg_hash permutation and
// records every S-box output; FillMerkleGlueRow builds one honest path-level
// row. MeasureSinglePermCompress assembles the single-permutation compression
// system and reports the §3.4 feasibility numbers.
// ============================================================================

namespace matmul::v4::rc::air_recurse {

using gkr_field::Fp;
using gkr_field::Fp3;

// ---------------------------------------------------------------------------
// Flattened permutation layout (spec §3.4: "118 S-box witnesses + 12 in/out").
// ---------------------------------------------------------------------------

/** Input lanes witnessed per permutation (the pre-M_E state): t = 12. */
inline constexpr uint32_t kPermInputCells = alg_hash::kAlgHashT;
/** S-box output witnesses per permutation: R_F·t + R_P = 8·12 + 22 = 118. */
inline constexpr uint32_t kPermSboxCells =
    alg_hash::kAlgHashFullRounds * alg_hash::kAlgHashT + alg_hash::kAlgHashPartialRounds;
/** Total witnessed cells per permutation: 12 + 118 = 130 (§3.4 budget). */
inline constexpr uint32_t kPermCellsPerPerm = kPermInputCells + kPermSboxCells;

/** S-box evaluation-order index (the constraint index): initial full rounds
 *  first (12 per round), then the 22 partial S-boxes, then the final full
 *  rounds. r counts within each phase; lane ∈ [0, 12). */
[[nodiscard]] constexpr uint32_t SboxIndexInitialFull(uint32_t r, uint32_t lane)
{
    return alg_hash::kAlgHashT * r + lane; // s ∈ [0, 48)
}
[[nodiscard]] constexpr uint32_t SboxIndexPartial(uint32_t r)
{
    return alg_hash::kAlgHashT * (alg_hash::kAlgHashFullRounds / 2) + r; // s ∈ [48, 70)
}
[[nodiscard]] constexpr uint32_t SboxIndexFinalFull(uint32_t r, uint32_t lane)
{
    return SboxIndexPartial(alg_hash::kAlgHashPartialRounds) + alg_hash::kAlgHashT * r +
           lane; // s ∈ [70, 118)
}

/**
 * Column plan of one flattened permutation block within a trace row.
 *   [base + 0,   base + 12)   input lanes in_0..in_11 (state BEFORE the
 *                             up-front external layer; for Compress these
 *                             are [L0..L3, R0..R3, D, 0, 0, 0]).
 *   [base + 12,  base + 130)  S-box output witnesses, evaluation order
 *                             (SboxIndex* above).
 * The 12 permutation outputs are NOT columns: Out_j = affine form over the
 * final full round's 12 S-box cells through the trailing M_E (PermOutputLane).
 */
struct PermLayout {
    uint32_t base{0};

    [[nodiscard]] uint32_t InputCol(uint32_t lane) const { return base + lane; }
    [[nodiscard]] uint32_t SboxCol(uint32_t s) const { return base + kPermInputCells + s; }
    /** One past the last column of the block: base + 130. */
    [[nodiscard]] uint32_t End() const { return base + kPermCellsPerPerm; }
};

// ---------------------------------------------------------------------------
// Constraint builders.
// ---------------------------------------------------------------------------

/**
 * The 118 S-box identities cell[sbox_s] = (A_s(cells))^7 of one permutation
 * (kEverywhere, alg_degree 7 each). A row of width ≥ layout.End() satisfies
 * all of them iff cells [base, base+130) are exactly the flattened witness
 * of Permute(in_0..in_11) — completeness by BuildPermWitness, soundness
 * because each substituted cell is pinned by its own identity in evaluation
 * order (x ↦ x^7 is a bijection, so any deviating cell breaks its identity).
 */
[[nodiscard]] std::vector<air_quotient::AirConstraint<Fp3>>
BuildPermRoundConstraints(const PermLayout& layout);

/**
 * Capacity wiring of the fixed 2→1 compression (spec §1.7): in_8 = D (the
 * node domain seed), in_9 = in_10 = in_11 = 0. Four degree-1 kEverywhere
 * constraints. Together with BuildPermRoundConstraints this is the full
 * compression identity: digest_j = PermOutputLane(j), j ∈ [0, 4), equals
 * alg_hash::Compress(in[0..4), in[4..8)).
 */
[[nodiscard]] std::vector<air_quotient::AirConstraint<Fp3>>
BuildCompressCapacityConstraints(const PermLayout& layout);

/**
 * Evaluate the virtual permutation-output affine form Out_lane at a row
 * (degree 1 in the row's final-round S-box cells). This is the expression
 * the Merkle glue and boundary constraints consume.
 */
[[nodiscard]] Fp3 PermOutputLane(const PermLayout& layout, const std::vector<Fp3>& row,
                                 uint32_t lane);

/** Evaluate the affine S-box input form A_s at a row (test/audit hook). */
[[nodiscard]] Fp3 PermSboxInput(const PermLayout& layout, const std::vector<Fp3>& row,
                                uint32_t s);

/**
 * Merkle-path glue block (spec §3.2 B): one path LEVEL per row. Columns
 * besides the embedded permutation block:
 *   dir_col            mp_dir — the path index bit b (0 ⇒ the running
 *                      accumulator is the LEFT child of this node).
 *   [acc_base, +4)     mp_acc_0..3 — the running Fp^4 digest ENTERING this
 *                      level (row 0: the leaf digest).
 *   [sib_base, +4)     the sibling digest opened at this level.
 * Per-level cells: 130 (perm) + 1 (dir) + 4 (acc) + 4 (sib) = 139.
 */
struct MerkleGlueLayout {
    PermLayout perm;
    uint32_t dir_col{0};
    uint32_t acc_base{0};
    uint32_t sib_base{0};

    /** Cells of one glue block (perm + dir + acc + sib) = 139. */
    static constexpr uint32_t kCellsPerLevel =
        kPermCellsPerPerm + 1 + 2 * alg_hash::kAlgHashDigestLen;
};

/**
 * Constraints of one Merkle-path level (17 total):
 *   1 × booleanity          b·(b−1) = 0                        deg 2, everywhere
 *   8 × input wiring        in_j     = (1−b)·acc_j + b·sib_j   deg 2, everywhere
 *                           in_{4+j} = (1−b)·sib_j + b·acc_j
 *   4 × capacity pins       in_8 = D, in_9..11 = 0             deg 1, everywhere
 *   4 × accumulator update  acc_j(next) = Out_j(cur)           deg 1, transition
 * A column of honest glue rows therefore chains digest_{l+1} =
 * Compress(children in mp_dir order) down the trace; the final accumulator
 * is pinned by BuildMerkleRootBoundaryConstraints. NOTE: the kEverywhere
 * constraints hold on EVERY row, so the terminal row carrying the root in
 * mp_acc must itself contain an honest (dummy) glue block, or Piece 4 must
 * gate these families by selectors.
 */
[[nodiscard]] std::vector<air_quotient::AirConstraint<Fp3>>
BuildMerkleGlueConstraints(const MerkleGlueLayout& layout);

/**
 * Terminal pin of the Merkle glue (spec §3.2 F): kLastRow, acc_j = root_j
 * (4 degree-1 constraints against the PUBLIC root).
 */
[[nodiscard]] std::vector<air_quotient::AirConstraint<Fp3>>
BuildMerkleRootBoundaryConstraints(uint32_t acc_base, const alg_hash::Digest& root);

// ---------------------------------------------------------------------------
// Honest-witness builders (run the REAL alg_hash primitive, record every
// intermediate) and the §3.4 measurement.
// ---------------------------------------------------------------------------

/** Flattened witness of one permutation: the 130 cells plus the output state. */
struct PermWitness {
    std::array<Fp, kPermCellsPerPerm> cells{};
    alg_hash::State output{};
};

/**
 * Run the permutation on `input`, recording every S-box output into the
 * flattened layout. `output` equals alg_hash::Permute(input); the cells
 * satisfy BuildPermRoundConstraints by construction.
 */
[[nodiscard]] PermWitness BuildPermWitness(const alg_hash::State& input);

/** Embed a permutation witness into an Fp3 row at layout.base (row.size()
 *  must be ≥ layout.End()); every cell is a base-field embedding. */
void WritePermWitness(const PermLayout& layout, const PermWitness& w, std::vector<Fp3>& row);

/** Honest single-row witness of Compress(left, right): the full column
 *  vector for one permutation, width layout.End(). */
[[nodiscard]] std::vector<Fp3> BuildCompressWitnessRow(const PermLayout& layout,
                                                       const alg_hash::Digest& left,
                                                       const alg_hash::Digest& right);

/**
 * Fill one honest Merkle-glue row: wires (acc, sib) in dir_bit order into
 * the compression, embeds the permutation witness, and returns the parent
 * digest (the value the NEXT row's mp_acc must hold) in *parent_out.
 * row.size() must cover the glue layout's columns.
 */
void FillMerkleGlueRow(const MerkleGlueLayout& layout, const alg_hash::Digest& acc,
                       const alg_hash::Digest& sib, bool dir_bit, std::vector<Fp3>& row,
                       alg_hash::Digest* parent_out);

/** The §3.4 feasibility numbers for the single-permutation compression CS. */
struct PermGadgetMeasurement {
    uint32_t cells_per_perm{0};       // witness columns of one permutation (130)
    uint32_t n_constraints{0};        // 118 S-box + 4 capacity = 122
    uint32_t n_sbox_constraints{0};   // 118
    uint32_t max_alg_degree{0};       // 7
    uint32_t n_rows{0};               // N used for the composed-degree report
    uint64_t max_composed_degree{0};  // 7·(N−1) — the degree-7 S-box drives it
    uint32_t quotient_len{0};         // ≈ 6N (spec §3.3)
    uint32_t cells_per_merkle_level{0}; // 139 = 130 + dir + acc + sib
};

/**
 * Assemble the single-permutation compression system (130 columns, the 118
 * S-box identities + 4 capacity pins) over N = n_rows. Piece 4 tiles this
 * block; here it exists to measure the composed-degree/quotient profile.
 */
[[nodiscard]] air_quotient::AirConstraintSystem<Fp3>
BuildSinglePermCompressSystem(uint32_t n_rows);

/** Measure the §3.4 numbers (cells_per_perm is the feasibility headline). */
[[nodiscard]] PermGadgetMeasurement MeasureSinglePermCompress(uint32_t n_rows);

// ============================================================================
// PIECE 4 — the FRI-verifier-as-AIR (V_CS) plus the recursion API
// (scratchpad/stage-c-buildable-spec.md §3/§4, §6 Piece 4). SECOND HALF of the
// recursion module: assembles the Piece-3 Poseidon2/Merkle gadgets into an
// AirConstraintSystem<Fp3> whose satisfying assignment is a transcript of
// AirQuotientVerify<Fp3, AirFriBackendAlg<Fp3>> ACCEPTING a child proof over
// the algebraic-hash FRI. "V_CS satisfiable ⇔ native verify accepts" is the
// deliverable, checked by the differential test (§6 Piece 4b).
//
// LAYOUT CHOICE (this build): WIDE, one-query-per-row. Each of the child FRI's
// Q query sites occupies ONE V_CS trace row; every constraint is kEverywhere
// and reads only `cur`, so there is no cross-row chaining, no per-segment
// kLastRow boundary, and no selector bookkeeping — the simplest structure that
// is a faithful mirror. A row lays the per-query hash-permutation blocks side
// by side (flattened 130-cell Piece-3 blocks) and wires each block's virtual
// output (PermOutputLane) into the next block's input within the same row. The
// child FRI's SHARED public roots (row_commit, fold-layer roots) are global
// constants; the PER-QUERY public data (query index, fold domain points, y,
// Z_H(y), …) are preprocessed columns pinned through the batch dual-OOD DEEP
// (preprocessed_pin_ood — REQUIRED by the row-wise alg backend, Piece 4a).
//
// FS scalars are NOT arithmetized (spec §3.5): λ, z1, z2, w1, w2,
// fold_challenges and the query indices enter as public inputs (constants /
// preprocessed columns), exactly the values the child proof carries.
// ============================================================================

/** Public inputs of ONE child AirQuotientProof<Fp3, AlgB3> — everything V_CS
 *  pins (spec §3.2 F, §3.5). Extracted identically by prover and verifier from
 *  the child proof so both build the SAME AirConstraintSystem. */
struct ChildPublicInputs {
    using AlgB3 = air_quotient::AirFriBackendAlg<Fp3>;
    // Child AIR / FRI shape.
    uint32_t child_n_rows{0};   // N of the child AIR (H size)
    uint32_t child_w{0};        // trace column count W (batch has W+1 cols)
    uint32_t child_quotient_len{0};
    uint32_t child_n_coeffs{0};
    uint32_t child_n_lde{0};    // n_coeffs * blowup
    uint32_t merkle_depth{0};   // log2(n_lde)
    uint32_t n_folds{0};        // log2(n_coeffs)
    // Shared roots (global constants).
    alg_hash::Digest row_commit_root{};
    alg_hash::Digest rt_root{};                       // trace_commit R_T
    std::vector<alg_hash::Digest> fold_roots;         // fold_layers[l].root, l<n_folds
    // FS scalars (public inputs, not arithmetized).
    Fp3 fri_lambda{};
    Fp3 z1{};
    Fp3 z2{};
    Fp3 w1{};
    Fp3 w2{};
    Fp3 final_value{};
    Fp3 air_lambda{};                                 // airq_lambda (AIR batching)
    std::vector<Fp3> fold_challenges;                 // beta_l
    std::vector<uint32_t> column_len;                 // W+1 entries
    std::vector<Fp3> evals_z1;                         // W+1
    std::vector<Fp3> evals_z2;                         // W+1
    // Per-query public data.
    std::vector<uint32_t> query_index;                // Q entries
    // The child AIR's own constraints (needed to arithmetize the per-point
    // identity C(y)=Q(y)·Z_H(y) — family D). Supplied by the caller because
    // BuildVerifierAIR cannot know the child's rule set from the proof alone.
    std::vector<air_quotient::AirConstraint<Fp3>> child_constraints;
    bool ok{false};
    std::string note;
};

/** Extract the pinned public inputs from a child proof + the child AIR. */
[[nodiscard]] ChildPublicInputs
ExtractChildPublicInputs(const air_quotient::AirConstraintSystem<Fp3>& child_cs,
                         const air_quotient::AirQuotientProof<Fp3, ChildPublicInputs::AlgB3>& child,
                         const uint256& child_fs_seed);

/** Which V_CS constraint families are assembled (build-time toggle used to grow
 *  the mirror family-by-family; the differential test reports per-family). */
struct VerifierAirFamilies {
    bool row_merkle{true};    // (B) row-opening path → row_commit_root
    bool fold{true};          // (B/C/E) fold even/odd paths + HalfDomainFoldPair
    bool deep{true};          // (E) dual-OOD DEEP + fold-path leaf consistency
    bool per_point{true};     // (D) C(y) = Q(y)·Z_H(y)
};

/** The measured V_CS shape (spec §3.4 cell-budget gate). */
struct VerifierAirMeasurement {
    uint32_t k{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t max_alg_degree{0};
    uint32_t quotient_len{0};
    uint64_t cell_count{0};       // n_columns * n_rows
    uint32_t perms_per_query{0};
    uint32_t queries{0};
};

/**
 * Build the k-child verifier AIR fully pinned to `pis` (§4.1). Prover and
 * verifier both call this with the identical `pis` (extracted from the child
 * proofs) so they operate on the SAME constraint system. `families` selects
 * which mirror families are emitted (all on by default).
 */
[[nodiscard]] air_quotient::AirConstraintSystem<Fp3>
BuildVerifierAIRPinned(uint32_t k, const std::vector<ChildPublicInputs>& pis,
                       const VerifierAirFamilies& families = {});

/**
 * Pure-shape variant (spec §4.1 signature): the column count / degree profile
 * of the k-child verifier AIR for the FIXED child-proof shape, WITHOUT pinning
 * to a specific proof (roots/scalars left zero). Used for the self-similarity
 * shape assertion (§4.2) and cell measurement; the pinned build is what
 * Prove/VerifyAggregate use. `shape` supplies the fixed child FRI dimensions.
 */
[[nodiscard]] air_quotient::AirConstraintSystem<Fp3>
BuildVerifierAIR(uint32_t k, const ChildPublicInputs& shape,
                 const VerifierAirFamilies& families = {});

/** Measure BuildVerifierAIRPinned(k, pis). */
[[nodiscard]] VerifierAirMeasurement
MeasureVerifierAIR(uint32_t k, const std::vector<ChildPublicInputs>& pis,
                   const VerifierAirFamilies& families = {});

/** The assembled V_CS + its honest witness (before the FRI prove). */
struct AggregateWitness {
    using AlgB3 = air_quotient::AirFriBackendAlg<Fp3>;
    bool ok{false};
    std::string note;
    air_quotient::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;   // cs.n_columns × cs.n_rows
    std::vector<ChildPublicInputs> pis;
    uint32_t n_witness_cols{0};
};

/** Build V_CS + the honest witness (records each child's opened transcript into
 *  the columns). Fast — no NTT/Merkle. The witness satisfies every constraint
 *  on H iff every child's native verify accepts (the differential core). */
[[nodiscard]] AggregateWitness
BuildAggregateWitness(const air_quotient::AirConstraintSystem<Fp3>& child_cs,
                      const std::vector<air_quotient::AirQuotientProof<Fp3, AggregateWitness::AlgB3>>& children,
                      const uint256& child_fs_seed, const VerifierAirFamilies& families = {});

/** Count constraints that fail to vanish on their applicable rows of H (fast,
 *  no FRI). 0 ⇔ the witness is a satisfying assignment. Reports the first
 *  offending (row, constraint name) if pointers are given. */
[[nodiscard]] uint32_t
CountWitnessViolationsOnH(const air_quotient::AirConstraintSystem<Fp3>& cs,
                          const std::vector<std::vector<Fp3>>& columns,
                          uint32_t* first_row = nullptr, std::string* first_name = nullptr);

/** Result of aggregating k child proofs into one parent proof (§4.1). */
struct AggregateResult {
    using AlgB3 = air_quotient::AirFriBackendAlg<Fp3>;
    bool ok{false};
    bool witness_satisfies{false};   // V_CS witness satisfied every constraint on H
    std::string note;
    air_quotient::AirQuotientProof<Fp3, AlgB3> proof;
    VerifierAirMeasurement measurement;
    std::vector<ChildPublicInputs> pis;  // the pins used (verifier needs these)
    uint256 fs_seed{};
};

/**
 * Aggregate: run AirQuotientVerify on each child, RECORD its accept-transcript
 * into the V_CS columns (§4.1), then AirQuotientProve(BuildVerifierAIRPinned,
 * witness, fs_seed). Faithful mirror: if a child's native verify would reject,
 * the recorded transcript violates a V_CS constraint on H, so the division is
 * inexact and the returned proof (if force-committed) is rejected by
 * VerifyAggregate — V_CS satisfiable ⇔ native accepts.
 */
[[nodiscard]] AggregateResult
ProveAggregate(const air_quotient::AirConstraintSystem<Fp3>& child_cs,
               const std::vector<air_quotient::AirQuotientProof<Fp3, AggregateResult::AlgB3>>& children,
               const uint256& child_fs_seed, const uint256& fs_seed,
               const VerifierAirFamilies& families = {});

/** Verify a parent proof: rebuild the SAME V_CS from `pis` and run
 *  AirQuotientVerify<Fp3, AlgB3> (spec §4.1). */
[[nodiscard]] bool
VerifyAggregate(const air_quotient::AirQuotientProof<Fp3, AggregateResult::AlgB3>& root,
                const std::vector<ChildPublicInputs>& pis, const uint256& fs_seed, uint32_t k,
                const VerifierAirFamilies& families = {}, std::string* why = nullptr);

} // namespace matmul::v4::rc::air_recurse

#endif // BTX_MATMUL_MATMUL_V4_RC_AIR_RECURSE_H
