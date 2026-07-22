// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_AIR_RECURSE_H
#define BTX_MATMUL_MATMUL_V4_RC_AIR_RECURSE_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>

#include <array>
#include <cstdint>
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

} // namespace matmul::v4::rc::air_recurse

#endif // BTX_MATMUL_MATMUL_V4_RC_AIR_RECURSE_H
