// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECEIPT_JOIN_Q96_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECEIPT_JOIN_Q96_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_receipt_join.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_receipt_join_q96 {

namespace aq = air_quotient;
namespace base = stage3_multirow_v11_receipt_join;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;
namespace rv = stage3_multirow_v11_recursive_verifier;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kReceiptHashBlocksV1 =
    base::kReceiptHashBlocksV1;
inline constexpr uint32_t kSetHashBlocksV1 = 4;
inline constexpr uint32_t kRealHashRowsV1 =
    base::kQ96QueryShardsV1 *
        kReceiptHashBlocksV1 +
    kSetHashBlocksV1;
inline constexpr uint32_t kTraceRowsV1 = 32;
inline constexpr uint32_t kRootExportRowV1 =
    kRealHashRowsV1 - 1;

static_assert(kRealHashRowsV1 == 30);
static_assert(kTraceRowsV1 >= kRealHashRowsV1);

struct StatementV1 {
    uint16_t version{kVersionV1};
    std::array<
        rv::ShardReceiptV1,
        base::kQ96QueryShardsV1> receipts{};
    uint256 expected_receipt_set_root{};
};

[[nodiscard]] StatementV1 BuildStatementV1(
    const std::array<
        rv::ShardReceiptV1,
        base::kQ96QueryShardsV1>& receipts);

using LayoutV1 = base::LayoutV1;

struct ProductV1 {
    StatementV1 statement{};
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint256 computed_receipt_set_root{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    uint64_t materialized_trace_cells{0};
    uint64_t violations{0};
    bool exact_single_q192_partition{false};
    bool exact_common_child_identity{false};
    bool all_leaf_receipt_roots_recomputed{false};
    bool ordered_receipt_set_root_recomputed{false};
    bool root_export_constrained{false};
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
    uint256 receipt_set_root{};
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
    uint256 receipt_set_root{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    bool exact_single_q192_partition{false};
    bool exact_common_child_identity{false};
    bool all_leaf_receipt_roots_recomputed{false};
    bool ordered_receipt_set_root_recomputed{false};
    bool root_export_constrained{false};
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

} // namespace matmul::v4::rc::stage3_multirow_v11_receipt_join_q96

#endif
