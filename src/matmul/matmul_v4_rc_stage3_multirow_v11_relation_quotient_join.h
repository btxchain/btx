// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RELATION_QUOTIENT_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RELATION_QUOTIENT_JOIN_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_relation_shards.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_relation_quotient_join {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace rs = stage3_multirow_v11_relation_shards;

inline constexpr uint16_t kRelationQuotientJoinVersionV1 = 1;
inline constexpr uint32_t kQueryRangesV1 = 3;
inline constexpr uint32_t kQueriesPerRangeV1 = 64;
inline constexpr uint32_t kRelationShardsV1 = rs::kRelationShardsV1;
inline constexpr uint32_t kLeafReceiptsV1 =
    kQueryRangesV1 * kRelationShardsV1;
inline constexpr uint32_t kRealQueryRowsV1 =
    kQueryRangesV1 * kQueriesPerRangeV1;
inline constexpr uint32_t kSchedulerReserveRowsV1 = 64;
inline constexpr uint32_t kTraceRowsV1 =
    kRealQueryRowsV1 + kSchedulerReserveRowsV1;

static_assert(kQueryRangesV1 == rs::kFallbackQueryShardsV1);
static_assert(kQueriesPerRangeV1 == rs::kFallbackQueriesPerShardV1);
static_assert(kLeafReceiptsV1 == rs::kFallbackLeafReceiptsV1);
static_assert(kRealQueryRowsV1 == 192);
static_assert(kTraceRowsV1 == 256);

struct QueryInputV1 {
    uint32_t query_ordinal{0};
    gf::Fp3 y{};
    gf::Fp3 zh{};
    std::array<gf::Fp3, kRelationShardsV1> partial_compositions{};
    std::array<gf::Fp3, kRelationShardsV1> partial_quotients{};
};

struct InputV1 {
    rs::PlanV1 relation_plan{};
    alg_hash::Digest full_q192_transcript_root{};
    std::array<
        std::array<alg_hash::Digest, kRelationShardsV1>,
        kQueryRangesV1> leaf_receipt_roots{};
    std::vector<QueryInputV1> queries;
};

struct DigestPairLayoutV1 {
    std::array<uint32_t, alg_hash::kAlgHashDigestLen> claim{};
    std::array<uint32_t, alg_hash::kAlgHashDigestLen> expected{};
};

struct ScalarPairLayoutV1 {
    uint32_t claim{0};
    uint32_t expected{0};
};

struct LeafLayoutV1 {
    ScalarPairLayoutV1 relation_ordinal{};
    DigestPairLayoutV1 local_program_root{};
    DigestPairLayoutV1 receipt_root{};
    std::array<uint32_t, alg_hash::kAlgHashDigestLen> manifest_root_alias{};
    std::array<uint32_t, alg_hash::kAlgHashDigestLen> transcript_root_alias{};
    uint32_t query_ordinal_alias{0};
    uint32_t range_ordinal_alias{0};
    uint32_t range_local_ordinal_alias{0};
    uint32_t y_alias{0};
    uint32_t zh_alias{0};
    uint32_t partial_composition{0};
    uint32_t partial_quotient{0};
    uint32_t composition_before{0};
    uint32_t composition_after{0};
    uint32_t quotient_before{0};
    uint32_t quotient_after{0};
};

struct LayoutV1 {
    ScalarPairLayoutV1 active{};
    ScalarPairLayoutV1 query_ordinal{};
    ScalarPairLayoutV1 range_ordinal{};
    ScalarPairLayoutV1 range_local_ordinal{};
    ScalarPairLayoutV1 y{};
    ScalarPairLayoutV1 zh{};
    DigestPairLayoutV1 manifest_root{};
    DigestPairLayoutV1 transcript_root{};
    std::array<LeafLayoutV1, kRelationShardsV1> leaves{};
    uint32_t n_columns{0};
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct ProductV1 {
    InputV1 input{};
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint32_t trace_rows{0};
    uint32_t active_query_rows{0};
    uint32_t scheduler_reserve_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    uint32_t leaf_receipts{0};
    uint64_t materialized_trace_cells{0};
    uint64_t violations{0};
    bool q64x3_production_safe_fallback{false};
    bool exact_q192_partition{false};
    bool exact_relation_partition{false};
    bool ordered_quotient_sum_identity{false};
    bool preprocessed_values_root_pinned{false};
    bool fiat_shamir_query_derivation_verified{false};
    bool relation_leaf_receipt_payloads_verified{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Construct the arithmetic join for all 192 canonical queries. Each active
 * row checks all six relation-shard equations
 *
 *   C_s(y) = Z_H(y) Q_s(y)
 *
 * and an ordered accumulator ending in
 *
 *   sum_s C_s(y) = Z_H(y) sum_s Q_s(y).
 *
 * The Q64x3 split is the production-safe fallback. The extra 64 trace rows
 * are an explicit scheduler reserve, rather than unmeasured headroom.
 * Receipt roots and all routing metadata are pinned in the ordered R0
 * preprocessed row-group root. This module deliberately does not claim that
 * the child receipt payloads themselves have already been recursively
 * verified.
 */
[[nodiscard]] ProductV1 BuildProductV1(const InputV1& input);

/**
 * Re-evaluate every AIR constraint and also recompute the ordered R0 root.
 * The latter makes a simultaneous claim+expected mutation visible here,
 * even when the equality constraints alone still vanish.
 */
[[nodiscard]] uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns);

struct ProveResultV1 {
    aq::AirQuotientSplitRapRowsProof proof{};
    uint256 preprocessed_row_group_root{};
    uint64_t proof_wire_bytes{0};
    uint64_t prove_micros{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] ProveResultV1 ProveV1(
    const InputV1& input,
    const uint256& public_fs_seed);

struct VerifyResultV1 {
    uint64_t verify_micros{0};
    bool accepted{false};
    bool relation_leaf_receipt_payloads_verified{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] VerifyResultV1 VerifyV1(
    const InputV1& input,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed);

inline constexpr bool kRelationQuotientJoinExecutableV1 = true;
inline constexpr bool kRelationLeafReceiptPayloadsVerifiedV1 = false;
inline constexpr bool kRecursiveAuthorityReadyV1 = false;
static_assert(kRelationQuotientJoinExecutableV1);
static_assert(!kRelationLeafReceiptPayloadsVerifiedV1);
static_assert(!kRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_multirow_v11_relation_quotient_join

#endif
