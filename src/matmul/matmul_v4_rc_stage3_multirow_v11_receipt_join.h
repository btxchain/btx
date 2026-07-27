// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECEIPT_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECEIPT_JOIN_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_verifier.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_receipt_join {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;
namespace rv = stage3_multirow_v11_recursive_verifier;

inline constexpr uint16_t kReceiptJoinVersionV1 = 1;
inline constexpr uint32_t kReceiptPreimageLanesV1 = 102;
inline constexpr uint32_t kReceiptHashBlocksV1 = 13;
inline constexpr uint32_t kDirectSetHashBlocksV1 = 4;
inline constexpr uint32_t kFirstBinaryHashBlocksV1 = 4;
inline constexpr uint32_t kRootBinaryHashBlocksV1 = 5;
inline constexpr uint32_t kRealHashRowsV1 =
    rv::kQueryShardsV1 * kReceiptHashBlocksV1 +
    kDirectSetHashBlocksV1 +
    kFirstBinaryHashBlocksV1 +
    kRootBinaryHashBlocksV1;
inline constexpr uint32_t kTraceRowsV1 = 64;
inline constexpr uint32_t kU32BitsV1 = 32;
inline constexpr uint32_t kBinaryRootExportRowV1 =
    kRealHashRowsV1 - 1;

static_assert(kRealHashRowsV1 == 52);
static_assert(kTraceRowsV1 >= kRealHashRowsV1);

// Additive throughput profile. These are two disjoint slices of the same
// canonical Q192 transcript, never two independent query lanes.
inline constexpr uint32_t kQ96QueryShardsV1 = 2;
inline constexpr uint32_t kQ96QueriesPerShardV1 = 96;
static_assert(
    kQ96QueryShardsV1 *
        kQ96QueriesPerShardV1 ==
    rv::abi::kQueryCountV11);

[[nodiscard]] constexpr std::array<
    rv::QueryRangeV1,
    kQ96QueryShardsV1>
CanonicalQ96QueryRangesV1()
{
    return {{
        {0, 0, kQ96QueriesPerShardV1},
        {1, kQ96QueriesPerShardV1,
         kQ96QueriesPerShardV1},
    }};
}

struct Q96CapAuditV1 {
    uint32_t child_columns{0};
    uint32_t child_constraints{0};
    uint32_t assumed_instructions_per_constraint{0};
    uint32_t relation_receipts_per_query_shard{0};
    uint64_t rows_per_query{0};
    uint64_t raw_rows_per_shard{0};
    uint32_t rounded_trace_rows{0};
    uint32_t lde_rows{0};
    uint64_t maximum_rows_per_query{0};
    uint64_t rows_per_query_headroom{0};
    uint32_t q64_parent_leaf_receipts{0};
    uint32_t q96_parent_leaf_receipts{0};
    bool exact_single_q192_partition{false};
    bool independent_query_lanes{false};
    bool fits_trace_cap{false};
    bool fits_lde_cap{false};
    bool executable_program_inventory_measured{false};
    bool valid_as_capacity_evaluation{false};
    std::string note;
};

/**
 * Checked capacity arithmetic only. The caller-supplied instruction count
 * remains an assumption until the canonical verifier ProgramTable inventory
 * is measured; therefore this function never claims executable recursion.
 */
[[nodiscard]] Q96CapAuditV1 AuditQ96TwoShardV1(
    uint32_t child_columns,
    uint32_t child_constraints,
    uint32_t assumed_instructions_per_constraint,
    uint32_t relation_receipts_per_query_shard);

struct Q96ReceiptSetV1 {
    std::array<
        rv::ShardReceiptV1,
        kQ96QueryShardsV1> receipts{};
    uint256 receipt_set_root{};
    bool exact_single_q192_partition{false};
    bool common_child_identity{false};
    bool leaf_roots_recomputed{false};
    bool canonical_alg_hash_root{false};
    bool executable_join_air{false};
    bool recursive_authority_ready{false};
    bool valid_as_binding_profile{false};
    std::string note;
};

[[nodiscard]] uint256 ComputeQ96ReceiptSetRootV1(
    const std::array<
        rv::ShardReceiptV1,
        kQ96QueryShardsV1>& receipts);

[[nodiscard]] Q96ReceiptSetV1 BuildQ96ReceiptSetV1(
    const std::array<
        rv::ShardReceiptV1,
        kQ96QueryShardsV1>& receipts);

/**
 * The statement carries the three materialized verifier-shard receipts and
 * both ordered aggregate roots. expected_shard_set_root is byte-compatible
 * with recursive_verifier::ComputeShardSetRootV1. expected_binary_root is
 * the fixed two-node tree:
 *
 *   n01  = H([0,64), [64,128))
 *   root = H(n01=[0,128), receipt_2=[128,192), shard_set_root)
 *
 * The direct root in the second preimage prevents the binary aggregation
 * layer from drifting from the already-published three-receipt commitment.
 */
struct StatementV1 {
    uint16_t version{kReceiptJoinVersionV1};
    std::array<rv::ShardReceiptV1, rv::kQueryShardsV1> receipts{};
    uint256 expected_shard_set_root{};
    uint256 expected_binary_root{};
};

[[nodiscard]] StatementV1 BuildStatementV1(
    const std::array<
        rv::ShardReceiptV1,
        rv::kQueryShardsV1>& receipts);

/**
 * Exact field preimage used by ComputeShardReceiptRootV1. This is exported
 * only so cross-module tests can detect any future receipt-codec drift.
 * Every arbitrary uint64/uint256 is represented by u32 limbs.
 */
[[nodiscard]] std::vector<gf::Fp> BuildReceiptPreimageV1(
    const rv::ShardReceiptV1& receipt);

[[nodiscard]] uint256 ComputeBinaryRootV1(
    const std::array<
        rv::ShardReceiptV1,
        rv::kQueryShardsV1>& receipts,
    const uint256& shard_set_root);

struct LayoutV1 {
    pa::Layout poseidon{};
    uint32_t absorb_base{0};
    uint32_t u32_mask_base{0};
    uint32_t u32_bit_base{0};
    uint32_t first_block{0};
    uint32_t last_block{0};
    uint32_t expected_digest_base{0};
    uint32_t bind_mask_base{0};
    uint32_t bind_expected_base{0};
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t Absorb(uint32_t lane) const
    {
        return absorb_base + lane;
    }
    [[nodiscard]] uint32_t U32Mask(uint32_t lane) const
    {
        return u32_mask_base + lane;
    }
    [[nodiscard]] uint32_t U32Bit(
        uint32_t lane, uint32_t bit) const
    {
        return u32_bit_base +
            lane * kU32BitsV1 + bit;
    }
    [[nodiscard]] uint32_t ExpectedDigest(uint32_t limb) const
    {
        return expected_digest_base + limb;
    }
    [[nodiscard]] uint32_t BindMask(uint32_t lane) const
    {
        return bind_mask_base + lane;
    }
    [[nodiscard]] uint32_t BindExpected(uint32_t lane) const
    {
        return bind_expected_base + lane;
    }
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct ProductV1 {
    StatementV1 statement{};
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint256 computed_shard_set_root{};
    uint256 computed_binary_root{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    uint64_t materialized_trace_cells{0};
    uint64_t violations{0};
    bool exact_q192_partition{false};
    bool exact_common_child_identity{false};
    bool all_leaf_receipt_roots_recomputed{false};
    bool direct_shard_set_root_recomputed{false};
    bool ordered_binary_tree_recomputed{false};
    bool binary_root_export_constrained{false};
    bool canonical_u32_absorb_encoding{false};
    bool preprocessed_values_root_pinned{false};
    bool quadratic_poseidon_air{false};
    /** Deliberately false until each leaf proof is verified by a child AIR. */
    bool child_receipt_proofs_verified_in_air{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProductV1 BuildProductV1(
    const StatementV1& statement);

struct ProveResultV1 {
    aq::AirQuotientSplitRapRowsProof proof{};
    uint256 preprocessed_row_group_root{};
    uint256 binary_root{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    uint64_t proof_wire_bytes{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] ProveResultV1 ProveV1(
    const StatementV1& statement,
    const uint256& public_fs_seed);

struct VerificationAuditV1 {
    uint256 preprocessed_row_group_root{};
    uint256 binary_root{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    bool exact_q192_partition{false};
    bool exact_common_child_identity{false};
    bool all_leaf_receipt_roots_recomputed{false};
    bool ordered_binary_tree_recomputed{false};
    bool binary_root_export_constrained{false};
    bool canonical_u32_absorb_encoding_verified{false};
    bool split_rap_quotient_fri_verified{false};
    bool child_receipt_proofs_verified_in_air{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] VerificationAuditV1 VerifyV1(
    const StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed);

} // namespace matmul::v4::rc::stage3_multirow_v11_receipt_join

#endif
