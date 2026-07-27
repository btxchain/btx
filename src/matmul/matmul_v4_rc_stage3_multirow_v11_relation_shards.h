// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RELATION_SHARDS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RELATION_SHARDS_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_normalized_program.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_relation_shards {

namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace np = stage3_multirow_v11_normalized_program;

inline constexpr uint16_t kRelationShardVersionV1 = 1;
inline constexpr uint32_t kRelationShardsV1 = 6;
inline constexpr uint32_t kPreferredQueryShardsV1 = 2;
inline constexpr uint32_t kPreferredQueriesPerShardV1 = 96;
inline constexpr uint32_t kFallbackQueryShardsV1 = 3;
inline constexpr uint32_t kFallbackQueriesPerShardV1 = 64;
inline constexpr uint32_t kPreferredLeafReceiptsV1 =
    kRelationShardsV1 * kPreferredQueryShardsV1;
inline constexpr uint32_t kFallbackLeafReceiptsV1 =
    kRelationShardsV1 * kFallbackQueryShardsV1;

static_assert(kPreferredLeafReceiptsV1 == 12);
static_assert(kFallbackLeafReceiptsV1 == 18);
static_assert(
    kPreferredQueryShardsV1 * kPreferredQueriesPerShardV1 == 192);
static_assert(
    kFallbackQueryShardsV1 * kFallbackQueriesPerShardV1 == 192);

enum ResidualV1 : uint32_t {
    kResidualFullProgramInvalid = 1U << 0,
    kResidualPartitionIncomplete = 1U << 1,
    kResidualShardInstructionCap = 1U << 2,
    kResidualShardLdeCap = 1U << 3,
    kResidualManifestBinding = 1U << 4,
    kResidualRecursiveLeafReceipts = 1U << 5,
    kResidualRecursiveQuotientJoin = 1U << 6,
};

struct ShardV1 {
    uint32_t ordinal{0};
    uint32_t first_program{0};
    uint32_t program_count{0};
    uint32_t first_lambda_exponent{0};
    uint64_t instruction_count{0};
    uint64_t q64_real_rows{0};
    uint32_t q64_trace_rows{0};
    uint64_t q64_lde_rows{0};
    uint64_t q96_real_rows{0};
    uint32_t q96_trace_rows{0};
    uint64_t q96_lde_rows{0};
    cb::ProgramTable local_table{};
    alg_hash::Digest local_program_root{};
    bool program_boundary_exact{false};
    bool register_dependencies_local{false};
    bool instruction_cap_fits{false};
    bool trace_rows_fit{false};
    bool lde_rows_fit{false};
    bool q96_trace_rows_fit{false};
    bool q96_lde_rows_fit{false};
    bool valid{false};
};

struct SymbolicCompositionAuditV1 {
    uint32_t expected_terms{0};
    uint32_t covered_terms{0};
    uint32_t missing_terms{0};
    uint32_t duplicate_terms{0};
    uint32_t wrong_lambda_exponents{0};
    bool exact_disjoint_partition{false};
    bool coefficientwise_lambda_identity{false};
    bool quotient_sum_identity{false};
    bool valid{false};
};

struct PlanV1 {
    std::array<ShardV1, kRelationShardsV1> shards{};
    alg_hash::Digest full_program_root{};
    alg_hash::Digest shard_manifest_root{};
    uint32_t full_programs{0};
    uint64_t full_instructions{0};
    uint32_t query_shards{kPreferredQueryShardsV1};
    uint32_t queries_per_query_shard{kPreferredQueriesPerShardV1};
    uint32_t leaf_receipts{kPreferredLeafReceiptsV1};
    uint32_t fallback_query_shards{kFallbackQueryShardsV1};
    uint32_t fallback_queries_per_query_shard{
        kFallbackQueriesPerShardV1};
    uint32_t fallback_leaf_receipts{kFallbackLeafReceiptsV1};
    uint32_t residual_mask{0};
    SymbolicCompositionAuditV1 symbolic_composition{};
    bool every_relation_shard_executable{false};
    bool exact_program_reassembly{false};
    bool manifest_poseidon_bound{false};
    bool q96_exact_partition_of_one_q192_transcript{false};
    bool q96_independent_lanes{false};
    bool q96_soundness_multiplication_claimed{false};
    bool recursive_leaf_receipts_verified{false};
    bool recursive_quotient_join_executed{false};
    bool recursive_authority_ready{false};
    bool valid_foundation{false};
    std::string note;
};

/**
 * Greedily slice the exact normalized table at program boundaries. Since the
 * complete instruction inventory is >5*cap and <=6*cap and no individual
 * program exceeds cap, the canonical result is exactly six nonempty shards.
 * Every program is self-contained SSA, so no register can cross a boundary.
 */
[[nodiscard]] PlanV1 BuildPlanV1(
    const cb::ProgramTable& full_table);

/**
 * Rebuild the global table from all six local tables, restoring global
 * constraint ordinals, and require byte-for-byte equality with `full_table`.
 */
[[nodiscard]] bool ReassemblesExactlyV1(
    const cb::ProgramTable& full_table,
    const PlanV1& plan);

[[nodiscard]] alg_hash::Digest ComputeManifestRootV1(
    const cb::ProgramTable& full_table,
    const std::array<ShardV1, kRelationShardsV1>& shards);

/**
 * Exact Poseidon2 manifest preimage. All scalar metadata are typed u32 before
 * embedding and every digest limb is required to be a canonical base-field
 * representative. Local table roots and instruction counts are recomputed;
 * caller-supplied aliases are rejected rather than absorbed.
 */
[[nodiscard]] bool BuildManifestPreimageV1(
    const cb::ProgramTable& full_table,
    const std::array<ShardV1, kRelationShardsV1>& shards,
    std::vector<gf::Fp>& out,
    std::string* why = nullptr);

/**
 * Exact field evaluation of
 *
 *   C = sum_i lambda^i selector_i residual_i
 *
 * and of the sum of its six range-restricted partials.  This is a diagnostic
 * evaluator. The plan's symbolic claim is instead established
 * coefficient-by-coefficient from exact coverage and global exponents.
 */
struct CompositionEvaluationV1 {
    gf::Fp3 monolithic{};
    std::array<gf::Fp3, kRelationShardsV1> partials{};
    gf::Fp3 partial_sum{};
    gf::Fp3 quotient_sum{};
    gf::Fp3 zh_times_quotient_sum{};
    bool input_shape_exact{false};
    bool partial_sum_matches{false};
    bool quotient_sum_matches{false};
    bool valid{false};
};

[[nodiscard]] CompositionEvaluationV1 EvaluateCompositionV1(
    const PlanV1& plan,
    const std::vector<gf::Fp3>& residuals,
    const std::vector<gf::Fp3>& selectors,
    const gf::Fp3& lambda,
    const gf::Fp3& zh);

inline constexpr bool kRelationShardLeavesReadyV1 = false;
inline constexpr bool kRecursiveQuotientJoinReadyV1 = false;
inline constexpr bool kRecursiveAuthorityReadyV1 = false;
static_assert(!kRelationShardLeavesReadyV1);
static_assert(!kRecursiveQuotientJoinReadyV1);
static_assert(!kRecursiveAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_multirow_v11_relation_shards

#endif
