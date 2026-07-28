// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_UNIVERSAL_TWO_CHILD_PARENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_UNIVERSAL_TWO_CHILD_PARENT_H

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::universal_two_child_parent {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;

inline constexpr uint16_t kUniversalTwoChildParentVersionV1 = 1;
inline constexpr uint32_t kUniversalTwoChildParentArityV1 = 2;

/**
 * Consensus-selected V_CS shape.  It deliberately contains dimensions and
 * column lengths only: no child root, query index, Fiat-Shamir challenge,
 * evaluation or proof opening is part of the constraint-system constructor.
 */
struct PublicShapeV1 {
    uint16_t version{kUniversalTwoChildParentVersionV1};
    uint32_t child_rows{0};
    uint32_t child_columns{0};
    uint32_t child_quotient_len{0};
    uint32_t child_coefficients{0};
    uint32_t child_lde{0};
    uint32_t merkle_depth{0};
    uint32_t folds{0};
    uint32_t queries{0};
    bool independent_fri_batching{true};
    std::vector<uint32_t> column_lengths;

    bool operator==(const PublicShapeV1&) const = default;
};

/**
 * Frozen registry input.  The canonical ProgramTable is the sole source of
 * the child relation callbacks.  `program_root` must be the SHA256d
 * commitment of that exact table; a proof tape cannot supply or replace it.
 */
struct FrozenRegistryV1 {
    uint16_t version{kUniversalTwoChildParentVersionV1};
    cb::ProgramTable child_relation_program;
    uint256 program_root{};

    bool operator==(const FrozenRegistryV1&) const = default;
};

/**
 * Verifier-only phase of universalization.
 *
 * The returned CS has a registry-derived callback schedule and a shape-only
 * V_CS layout.  It is intentionally not authority yet: the existing V_CS
 * builder leaves proof-specific public inputs at canonical zero.  The next
 * phase replaces those constants with fixed-trace column reads before witness
 * materialization or proving is allowed.
 */
struct VerifierConstraintSystemV1 {
    uint16_t version{kUniversalTwoChildParentVersionV1};
    uint32_t arity{kUniversalTwoChildParentArityV1};
    PublicShapeV1 shape;
    uint256 registry_program_root{};
    uint256 shape_commitment{};
    uint256 callback_schedule_commitment{};
    aq::AirConstraintSystem<gf::Fp3> child_cs;
    aq::AirConstraintSystem<gf::Fp3> parent_cs;
    bool registry_program_reconstructed{false};
    bool shape_only_parent_reconstructed{false};
    bool proof_tape_independent{false};
    bool proof_specific_constants_lifted_to_fixed_trace{false};
    bool full_child_acceptance_constrained{false};
    bool authority{false};
    std::string note;
};

[[nodiscard]] uint256 CommitPublicShapeV1(
    const PublicShapeV1& shape);

[[nodiscard]] uint256 CommitConstraintScheduleV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs);

/**
 * Rebuild the exact callback schedule from public shape + frozen registry
 * only.  This function has no proof-tape parameter by design.
 */
[[nodiscard]] bool BuildVerifierConstraintSystemV1(
    const PublicShapeV1& shape,
    const FrozenRegistryV1& registry,
    VerifierConstraintSystemV1& out,
    std::string* why = nullptr);

/**
 * Mechanical noninterference test helper.  Requires two distinct byte tapes,
 * rebuilds twice through the tape-free constructor, and confirms identical
 * shape/program/schedule commitments and constraint descriptors.
 */
[[nodiscard]] bool VerifyProofTapeNoninterferenceV1(
    const PublicShapeV1& shape,
    const FrozenRegistryV1& registry,
    const std::vector<unsigned char>& first_tape,
    const std::vector<unsigned char>& second_tape,
    std::string* why = nullptr);

inline constexpr bool kUniversalTwoChildVerifierCsExecutableV1 = true;
inline constexpr bool kUniversalTwoChildFixedTraceLiftCompleteV1 = false;
inline constexpr bool kUniversalTwoChildAuthorityReadyV1 = false;

static_assert(kUniversalTwoChildVerifierCsExecutableV1);
static_assert(!kUniversalTwoChildFixedTraceLiftCompleteV1);
static_assert(!kUniversalTwoChildAuthorityReadyV1);

} // namespace matmul::v4::rc::universal_two_child_parent

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_UNIVERSAL_TWO_CHILD_PARENT_H
