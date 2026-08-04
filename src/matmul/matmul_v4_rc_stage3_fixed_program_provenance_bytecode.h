// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_PROVENANCE_BYTECODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_PROVENANCE_BYTECODE_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::fixed_program_provenance_bytecode {

namespace cb = constraint_bytecode;
namespace ha = stage3_hash_air;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kChallengeWidthV1 = 4;
inline constexpr uint32_t kOutputColumnV1 =
    ha::kFixedProgramProvenanceColumns;
inline constexpr uint32_t kWeightedOutputBaseV1 =
    kOutputColumnV1 + 1;
inline constexpr uint32_t kWeightedInputBaseV1 =
    kWeightedOutputBaseV1 + 2;
inline constexpr uint32_t kColumnsV1 =
    kWeightedInputBaseV1 + 6;
inline constexpr uint32_t kBoundaryProgramsV1 = 4;
inline constexpr uint32_t kChallengeProductProgramsV1 = 8;
inline constexpr uint32_t kProvenanceProgramsV1 = 22;
inline constexpr uint32_t kOutputProgramsV1 = 1;
inline constexpr uint32_t kProgramsV1 =
    462 + kBoundaryProgramsV1 +
    kChallengeProductProgramsV1 +
    kProvenanceProgramsV1 +
    kOutputProgramsV1;

enum ResidualV1 : uint32_t {
    /** Expected public boundary columns are not equality-linked to their
     * role-proof producers by this static ProgramTable. */
    kResidualPublicBoundarySourceLink = 1U << 0,
    /** The immutable selector/address/mask schedule root is computed here,
     * but the normalized parent does not yet consume that root. */
    kResidualFixedTraceRootConsumption = 1U << 1,
    /** One ProgramTable execution does not prove the exact production set of
     * all fixed-program instances. */
    kResidualExactAllInstanceAggregation = 1U << 2,
    /** The normalized parent does not yet verify this child receipt. */
    kResidualRecursiveChildConsumption = 1U << 3,
};

struct ManifestV1 {
    uint16_t version{kVersionV1};
    ha::ProgramKind program_kind{
        ha::ProgramKind::Sha256Compression};
    RCStage3RelationRole role{};
    uint32_t rows{0};
    uint32_t columns{0};
    uint32_t programs{0};
    uint32_t challenge_width{0};
    uint256 fixed_program_commitment{};
    uint256 immutable_schedule_root{};
    std::vector<uint32_t> immutable_schedule_columns;
    uint32_t residual_mask{0};
    bool exact_native_constraint_order{false};
    bool canonical_program_table{false};
    bool immutable_schedule_reconstructed{false};
    bool internal_ssa_provenance_complete{false};
    bool authority_eligible{false};
    std::string note;
};

/**
 * Lower the complete single-instance fixed-program provenance relation:
 *
 *   462 opcode constraints
 *   + 4 public boundary constraints
 *   + 1 selector-muxed output-cell constraint
 *   + 8 verifier-challenge product constraints
 *   + 22 dual-lane internal SSA-copy constraints.
 *
 * gamma1/alpha1/gamma2/alpha2 are verifier-owned challenge columns.  Explicit
 * gamma-times-value columns keep the table's executable degree accounting
 * honest while preserving the native relation: the bytecode validator treats
 * Challenge loads as degree one, whereas native AIR challenges are scalar
 * coefficients.  The eight auxiliary equalities make the two systems
 * equivalent instead of silently understating their degree.
 *
 * The table is independent of the public boundary values and of the fixed
 * program kind; kind-specific immutable schedule columns are committed in
 * `ManifestV1`.
 */
[[nodiscard]] bool BuildCanonicalProgramTableV1(
    RCStage3RelationRole role,
    ha::ProgramKind program_kind,
    cb::ProgramTable& out,
    ManifestV1* manifest = nullptr,
    std::string* why = nullptr);

/**
 * Differentially compare the bytecode relation against the independently
 * authored native provenance AIR over deterministic full-width field rows.
 * The audit populates and checks all eight challenge-product columns, compares
 * the native constraints in their original order, and attacks every auxiliary
 * binding.
 */
struct DifferentialAuditV1 {
    uint32_t native_constraints{0};
    uint32_t bytecode_programs{0};
    uint32_t probes{0};
    uint64_t evaluations{0};
    uint64_t mismatches{0};
    bool exact_order{false};
    bool challenge_products_checked{false};
    bool output_relation_checked{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] DifferentialAuditV1 AuditAgainstNativeV1(
    RCStage3RelationRole role,
    ha::ProgramKind program_kind,
    uint32_t probes = 8);

} // namespace matmul::v4::rc::fixed_program_provenance_bytecode

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_PROVENANCE_BYTECODE_H
