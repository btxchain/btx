// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_PARENT_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_PARENT_JOIN_H

#include <matmul/matmul_v4_rc_stage3_multirow_p2_consumer_bridge.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_proof_abi.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_parent_join {

namespace aq = air_quotient;
namespace abi = stage3_multirow_v11_proof_abi;
namespace cb = stage3_multirow_p2_consumer_bridge;
namespace gf = gkr_field;
namespace tp = stage3_multirow_p2_transcript;

inline constexpr uint16_t kParentJoinVersionV1 = 1;
inline constexpr uint32_t kPublicAbsorbSlotsV1 = alg_hash::kAlgHashRate;
inline constexpr uint32_t kPublicFieldSlotsV1 = 3;
inline constexpr uint32_t kCandidateDigestLimbsV1 =
    alg_hash::kAlgHashDigestLen;
inline constexpr uint32_t kRawBitsV1 = 64;
inline constexpr uint32_t kHighAndBitsV1 = 32;

struct CanonicalSplitLayoutV1 {
    uint32_t active{0};
    uint32_t address_lo{0};
    uint32_t address_hi{0};
    uint32_t parent_column_lo{0};
    uint32_t parent_column_hi{0};
    uint32_t claim_lo{0};
    uint32_t claim_hi{0};
    uint32_t expected_lo{0};
    uint32_t expected_hi{0};
    uint32_t bit_base{0};
    uint32_t high_and_base{0};
    uint32_t low_nonzero{0};
    uint32_t low_inverse{0};

    [[nodiscard]] uint32_t Bit(uint32_t bit) const
    {
        return bit_base + bit;
    }
    [[nodiscard]] uint32_t HighAnd(uint32_t bit) const
    {
        return high_and_base + bit;
    }
};

struct PublicAbsorbSlotLayoutV1 {
    uint32_t active{0};
    uint32_t source_address{0};
    uint32_t parent_column{0};
    uint32_t claim{0};
    uint32_t expected{0};
};

struct LayoutV1 {
    tp::LayoutV1 replay{};
    std::array<PublicAbsorbSlotLayoutV1,
               kPublicAbsorbSlotsV1> public_absorb{};
    std::array<CanonicalSplitLayoutV1,
               kPublicFieldSlotsV1> public_field{};
    std::array<CanonicalSplitLayoutV1,
               kCandidateDigestLimbsV1> candidate_digest{};
    uint32_t selected_ordinal_address{0};
    uint32_t selected_ordinal_claim{0};
    uint32_t query_index_address{0};
    uint32_t query_index_claim{0};
    uint32_t coefficient_active{0};
    uint32_t coefficient_label{0};
    uint32_t n_columns{0};
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct ProductV1 {
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    std::vector<uint32_t> coefficient_replay_rows;
    std::array<uint32_t, 3> coefficient_consumer_columns{};
    uint32_t public_source_cells{0};
    uint32_t public_source_records{0};
    uint32_t derived_candidate_cells{0};
    uint32_t query_index_cells{0};
    uint32_t replay_hash_events{0};
    uint32_t replay_real_sponge_rows{0};
    uint32_t replay_terminal_events{0};
    uint32_t padding_terminal_rows{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint64_t violations{0};
    bool public_inventory_exact{false};
    bool public_parent_columns_root_pinned{false};
    bool public_claims_equal_parent_air_constrained{false};
    bool public_claims_equal_replay_air_constrained{false};
    bool derived_candidates_equal_replay_air_constrained{false};
    bool selected_ordinals_equal_replay_air_constrained{false};
    bool selected_query_indices_equal_proof_air_constrained{false};
    bool independent_coefficients_direct_replay_alias{false};
    bool canonical_u64_decomposition_air_constrained{false};
    bool exact_ordered_preprocessed_root{false};
    bool canonical_abi_claim_cells_air_joined{false};
    bool backend_v11_proof_cells_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Extend the executable V11 Poseidon replay AIR with proof/public joins.
 *
 * The transcript columns keep their physical indices.  Parent-public values,
 * source addresses, parent-column labels and join schedules are added to the
 * same ordered R0 row commitment.  Proof/decoder claims remain witness
 * columns and are constrained to both the pinned public cells and the exact
 * replay absorb/output cells.  Query candidates and selected indices are
 * similarly constrained to the replay output, with a canonical u64
 * decomposition that rejects the Goldilocks x+p alias.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const abi::DecodedV1& decoded,
    const std::vector<abi::ParentPublicCellV1>& parent_public,
    const tp::ProductV1& replay,
    const cb::ProductV1& consumer);

/**
 * Re-evaluate every AIR relation and the exact ordered R0 commitment.
 * Returning nonzero for a pure R0 mutation is intentional: changing a
 * claimed and expected cell together cannot evade the fixed row root.
 */
[[nodiscard]] uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns);

} // namespace matmul::v4::rc::stage3_multirow_v11_parent_join

#endif
