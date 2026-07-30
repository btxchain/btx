// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_POSEIDON_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_POSEIDON_AIR_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_recurse.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Stage-3 Poseidon2 operation table: fully quadratic x^7 decomposition.
//
// The existing recursive AIR witnesses one Poseidon2 permutation in the
// flattened 130-column layout:
//
//   12 input lanes || 118 S-box outputs.
//
// Its direct constraints y = x^7 have algebraic degree seven.  This module
// keeps that exact layout and appends three columns for every S-box input x:
//
//   x2 = x*x,  x4 = x2*x2,  x6 = x4*x2,  y = x6*x.
//
// All four residuals are quadratic.  A fixed Poseidon operation table
// therefore uses 484 columns and maximum AIR degree two.  The optional
// selector-gated form uses one additional preprocessed boolean column and
// maximum degree three.  Pinning the selector as a preprocessed column is
// mandatory: without that commitment a prover could set it to zero and
// disable the permutation constraints.
//
// This is an executable proof-only AIR fragment.  It does not implement the
// verifier program, the memory/LogUp bus between operation tables, recursive
// aggregation, or any consensus authority gate.
// ============================================================================

namespace matmul::v4::rc::stage3_poseidon_air {

using gkr_field::Fp3;

inline constexpr uint32_t kSboxAuxColumnsPerSbox = 3;
inline constexpr uint32_t kSboxConstraintCount = 4;
inline constexpr uint32_t kFixedColumns =
    air_recurse::kPermCellsPerPerm +
    kSboxAuxColumnsPerSbox * air_recurse::kPermSboxCells;
inline constexpr uint32_t kFixedConstraints =
    kSboxConstraintCount * air_recurse::kPermSboxCells;
inline constexpr uint32_t kSelectorGatedColumns = kFixedColumns + 1;
inline constexpr uint32_t kSelectorGatedConstraints =
    kFixedConstraints + 1; // selector booleanity

/**
 * Canonical contiguous layout:
 *
 *   [base, base+130)       existing flattened permutation
 *   [base+130, +248)       x2[0..118)
 *   [base+248, +366)       x4[0..118)
 *   [base+366, +484)       x6[0..118)
 */
struct Layout {
    air_recurse::PermLayout perm;
    uint32_t x2_base{0};
    uint32_t x4_base{0};
    uint32_t x6_base{0};

    [[nodiscard]] uint32_t X2Col(uint32_t sbox) const
    {
        return x2_base + sbox;
    }
    [[nodiscard]] uint32_t X4Col(uint32_t sbox) const
    {
        return x4_base + sbox;
    }
    [[nodiscard]] uint32_t X6Col(uint32_t sbox) const
    {
        return x6_base + sbox;
    }
    [[nodiscard]] uint32_t End() const
    {
        return x6_base + air_recurse::kPermSboxCells;
    }
    [[nodiscard]] bool IsCanonical(std::string* why = nullptr) const;
};

[[nodiscard]] Layout CanonicalLayout(uint32_t base = 0);

/** The 4*118 fixed-table quadratic identities. */
[[nodiscard]] std::vector<air_quotient::AirConstraint<Fp3>>
BuildFixedConstraints(const Layout& layout);

/**
 * Selector booleanity plus selector times every fixed-table identity.
 * The selector column must be committed as a canonical preprocessed column;
 * BuildSelectorGatedSystem enforces that contract.
 */
[[nodiscard]] std::vector<air_quotient::AirConstraint<Fp3>>
BuildSelectorGatedConstraints(const Layout& layout, uint32_t selector_col);

/** One honest flattened/decomposed permutation row and its native output. */
struct Witness {
    std::vector<Fp3> row;
    alg_hash::State output{};
};

[[nodiscard]] Witness BuildWitness(const Layout& layout,
                                   const alg_hash::State& input);

/**
 * Fixed operation-table system.  Every row is one Poseidon2 permutation.
 * n_rows must be a power of two >= 2.
 */
[[nodiscard]] bool BuildFixedSystem(
    uint32_t n_rows,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);

/**
 * Selector-gated operation-table system. selector_values is a public,
 * canonical boolean vector of length n_rows and is installed as a
 * preprocessed column. Selected rows must contain BuildWitness output;
 * unselected rows are unconstrained apart from the selector.
 */
[[nodiscard]] bool BuildSelectorGatedSystem(
    uint32_t n_rows,
    const std::vector<Fp3>& selector_values,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);

struct Measurement {
    uint32_t sboxes{0};
    uint32_t base_columns{0};
    uint32_t auxiliary_columns{0};
    uint32_t fixed_columns{0};
    uint32_t selector_gated_columns{0};
    uint32_t fixed_constraints{0};
    uint32_t selector_gated_constraints{0};
    uint32_t fixed_max_degree{0};
    uint32_t selector_gated_max_degree{0};
    uint32_t n_rows{0};
    uint64_t fixed_composed_degree{0};
    uint64_t selector_gated_composed_degree{0};
    uint32_t fixed_quotient_len{0};
    uint32_t selector_gated_quotient_len{0};
};

/** Exact width/degree/quotient report for both physical table choices. */
[[nodiscard]] Measurement Measure(uint32_t n_rows);

inline constexpr bool kPoseidonDecomposedAirExecutable = true;
inline constexpr bool kPoseidonDecomposedConsensusAuthority = false;

} // namespace matmul::v4::rc::stage3_poseidon_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_POSEIDON_AIR_H
