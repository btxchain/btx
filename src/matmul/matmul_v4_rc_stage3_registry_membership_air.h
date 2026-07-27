// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_REGISTRY_MEMBERSHIP_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_REGISTRY_MEMBERSHIP_AIR_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>
#include <matmul/matmul_v4_rc_stage3_universal_topology.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_registry_membership_air {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;
namespace ut = universal_topology;

inline constexpr uint16_t kRegistryMembershipAirVersionV1 = 1;
inline constexpr uint32_t kRegistryFamilyFieldsV1 = 12;
inline constexpr uint32_t kRegistryAbsorbBitsV1 = 32;

/**
 * The exact family tuple exported to the normalized parent. The registry root
 * already commits all other entry metadata (column/degree bounds, external
 * audit hashes and endpoint lists); these are the fields needed to resolve
 * the immutable verifying key and its public-input ABI.
 */
struct SelectedFamilyV1 {
    uint32_t family_index{0};
    soundness_scenarios::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    alg_hash::Digest program_alg_hash{};
    alg_hash::Digest schema_alg_hash{};
    bool semantic_relation_complete{false};

    bool operator==(const SelectedFamilyV1&) const = default;
};

struct StatementV1 {
    uint16_t version{kRegistryMembershipAirVersionV1};
    alg_hash::Digest registry_alg_root{};
    SelectedFamilyV1 selected{};

    bool operator==(const StatementV1&) const = default;
};

/** Build the exact public statement for one canonical registry entry. */
[[nodiscard]] StatementV1 BuildStatementV1(
    const ut::ProductionProgramRegistryV1& registry,
    uint32_t family_index);

/**
 * One row is one Poseidon2 sponge permutation. The full quadratic permutation
 * occupies [0, poseidon.End()); public absorb/table columns are an ordered R0
 * group, while selector, prefix, claims and decomposition bits remain witness
 * columns in Rdep.
 */
struct LayoutV1 {
    pa::Layout poseidon{};
    uint32_t absorb_base{0};       // 8 canonical u32 lanes
    uint32_t absorb_bit_base{0};   // 8 * 32 low-bit decompositions
    uint32_t digest_selector{0};   // one at the last real sponge block
    uint32_t family_active{0};     // one for rows [0,28)
    uint32_t family_field_base{0}; // 12 exact entry fields
    uint32_t selector{0};          // dynamic one-hot witness
    uint32_t selector_prefix{0};   // prefix count before this row
    uint32_t selected_field_base{0}; // 12 parent-exported claim cells
    uint32_t digest_claim_base{0}; // 4 parent-exported registry digest cells
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t Absorb(uint32_t lane) const
    {
        return absorb_base + lane;
    }
    [[nodiscard]] uint32_t AbsorbBit(
        uint32_t lane, uint32_t bit) const
    {
        return absorb_bit_base +
            lane * kRegistryAbsorbBitsV1 + bit;
    }
    [[nodiscard]] uint32_t FamilyField(uint32_t field) const
    {
        return family_field_base + field;
    }
    [[nodiscard]] uint32_t SelectedField(uint32_t field) const
    {
        return selected_field_base + field;
    }
    [[nodiscard]] uint32_t DigestClaim(uint32_t limb) const
    {
        return digest_claim_base + limb;
    }
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct ProductV1 {
    LayoutV1 layout{};
    StatementV1 statement{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_base_columns;
    uint256 preprocessed_row_group_root{};
    uint32_t preimage_lanes{0};
    uint32_t sponge_blocks{0};
    uint32_t trace_rows{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint64_t violations{0};
    bool exact_28_entry_order{false};
    bool exact_registry_alg_hash_replayed{false};
    bool preprocessed_values_root_pinned{false};
    bool dynamic_one_hot_selection_constrained{false};
    bool selected_tuple_constrained{false};
    bool u32_absorb_encoding_constrained{false};
    bool quadratic_poseidon{false};
    bool recursive_parent_consumes_exports{false};
    bool production_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Build the complete deterministic AIR and honest witness. Even on a bad
 * statement the returned CS/columns remain available for adversarial tests;
 * `valid` is false and `violations` is nonzero.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const ut::ProductionProgramRegistryV1& registry,
    const StatementV1& statement);

struct ProveResultV1 {
    StatementV1 statement{};
    aq::AirQuotientSplitRapRowsProof proof{};
    uint256 preprocessed_row_group_root{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] ProveResultV1 ProveV1(
    const ut::ProductionProgramRegistryV1& registry,
    const StatementV1& statement,
    const uint256& public_fs_seed);

struct VerificationAuditV1 {
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint256 preprocessed_row_group_root{};
    bool exact_registry_alg_hash_replayed{false};
    bool exact_ordered_preprocessed_root{false};
    bool dynamic_one_hot_selection_verified{false};
    bool family_index_kind_role_bound{false};
    bool program_and_schema_alg_hash_bound{false};
    bool semantic_completeness_bound{false};
    bool canonical_u32_absorb_encoding_verified{false};
    bool split_rap_quotient_fri_verified{false};
    bool recursive_parent_consumes_exports{false};
    bool production_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] VerificationAuditV1 VerifyV1(
    const ut::ProductionProgramRegistryV1& registry,
    const StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed);

} // namespace matmul::v4::rc::stage3_registry_membership_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_REGISTRY_MEMBERSHIP_AIR_H
