// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_ctl.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_heavy.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::multirow_v11_semantic_recursive {

namespace aq = air_quotient;
namespace ctl = multirow_v11_semantic_ctl;
namespace gf = gkr_field;
namespace heavy = multirow_v11_semantic_heavy;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kEndpointCountV1 = 52;
inline constexpr uint32_t kHeavyEndpointCountV1 = 21;
inline constexpr uint32_t kExistingEndpointCountV1 = 31;
inline constexpr uint32_t kWordsV1 = 8;
inline constexpr uint32_t kWordBitsV1 = 32;
inline constexpr uint32_t kBlockLanesV1 = 64;
inline constexpr uint32_t kHeaderLanesV1 = 16;

enum class OutputOriginV1 : uint32_t {
    ExistingRoleDirectAlias = 1,
    HeavyVerifierReceiptR0 = 2,
};

/**
 * One canonical parent input block.
 *
 * `producer_authentication_root` and `consumer_authentication_root` are
 * canonical AlgHash digests over the exact route/common-root/value tuple.
 * They are installed in the parent's ordered R0 group.  No `verified` boolean
 * exists: the parent consumes cells and roots, not host success flags.
 */
struct ReceiptOutputBlockV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t ordinal{0};
    OutputOriginV1 origin{
        OutputOriginV1::ExistingRoleDirectAlias};
    uint256 statement_root{};
    uint256 program_root{};
    uint256 transcript_root{};
    uint256 producer_authentication_root{};
    uint256 consumer_authentication_root{};
    std::array<uint64_t, kWordsV1> producer_words{};
    std::array<uint64_t, kWordsV1> consumer_words{};

    bool operator==(const ReceiptOutputBlockV1&) const = default;
};

struct LayoutV1 {
    stage3_poseidon_air::Layout poseidon{};
    uint32_t hash_active{0};
    uint32_t endpoint_first{0};
    uint32_t terminal{0};
    uint32_t endpoint{0};
    uint32_t role{0};
    uint32_t ordinal{0};
    uint32_t origin{0};
    uint32_t statement_base{0};
    uint32_t program_base{0};
    uint32_t transcript_base{0};
    uint32_t producer_auth_base{0};
    uint32_t consumer_auth_base{0};
    uint32_t producer_base{0};
    uint32_t consumer_base{0};
    uint32_t producer_bits_base{0};
    uint32_t consumer_bits_base{0};
    uint32_t message_base{0};
    uint32_t expected_statement_base{0};
    uint32_t expected_program_base{0};
    uint32_t expected_transcript_base{0};
    uint32_t expected_endpoint{0};
    uint32_t expected_role{0};
    uint32_t expected_ordinal{0};
    uint32_t expected_origin{0};
    uint32_t ordered_root_base{0};
    uint32_t total_columns{0};

    [[nodiscard]] uint32_t ProducerBit(
        uint32_t word, uint32_t bit) const
    {
        return producer_bits_base +
            word * kWordBitsV1 + bit;
    }
    [[nodiscard]] uint32_t ConsumerBit(
        uint32_t word, uint32_t bit) const
    {
        return consumer_bits_base +
            word * kWordBitsV1 + bit;
    }

};

struct ProductV1 {
    uint16_t version{kVersionV1};
    uint256 expected_statement_root{};
    uint256 expected_program_root{};
    uint256 expected_transcript_root{};
    uint256 ordered_set_root{};
    uint256 parent_fs_seed{};
    uint256 preprocessed_row_group_root{};
    std::vector<uint32_t> preprocessed_columns;
    std::vector<ReceiptOutputBlockV1> blocks;
    std::vector<ctl::EndpointCellsV1> literal_pairs;
    LayoutV1 layout;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t hash_rows{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_degree{0};
    uint32_t existing_outputs{0};
    uint32_t heavy_outputs{0};
    uint64_t violations{UINT64_MAX};
    bool role_products_canonical{false};
    bool exact_endpoint_order{false};
    bool exact_origin_partition{false};
    bool common_roots_constrained{false};
    bool producer_consumer_equality_constrained{false};
    bool canonical_u32_constrained{false};
    bool ordered_poseidon_root_constrained{false};
    bool exact_r0_root_pinned{false};
    bool child_verifier_cells_connected{false};
    bool recursive_authority{false};
    bool valid_foundation{false};
    std::string note;
};

/**
 * Build the exact 31 direct-role plus 21 heavy-receipt-R0 output blocks from
 * canonical executed role products.  Heavy blocks are intentionally labelled
 * R0 output blocks: this function does not convert a native verifier result
 * into an in-parent verifier cell.
 */
[[nodiscard]] std::vector<ReceiptOutputBlockV1>
BuildReceiptOutputBlocksV1(
    const std::vector<RCStage3RoleAirProduct>& roles,
    const uint256& statement_root,
    const uint256& program_root,
    const uint256& transcript_root,
    std::string* why = nullptr);

/**
 * Build the 512-row bounded Poseidon2 parent.  The complete ordered payload is
 * absorbed in 64-lane endpoint blocks with a length-bound header and 10*
 * padding.  The emitted `literal_pairs` are exactly the 52 source/consumer
 * words accepted by the parent.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const std::vector<RCStage3RoleAirProduct>& roles,
    const uint256& statement_root,
    const uint256& program_root,
    const uint256& transcript_root);

[[nodiscard]] uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns);

[[nodiscard]] bool ValidateProductV1(
    const ProductV1& product,
    const std::vector<RCStage3RoleAirProduct>& roles,
    const uint256& statement_root,
    const uint256& program_root,
    const uint256& transcript_root,
    std::string* why = nullptr);

inline constexpr bool kChildVerifierCellsConnectedV1 = false;
inline constexpr bool kRecursiveAuthorityV1 = false;
static_assert(!kChildVerifierCellsConnectedV1);
static_assert(!kRecursiveAuthorityV1);

} // namespace matmul::v4::rc::multirow_v11_semantic_recursive

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_RECURSIVE_H
