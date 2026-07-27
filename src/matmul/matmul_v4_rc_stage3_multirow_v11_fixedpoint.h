// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_FIXEDPOINT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_FIXEDPOINT_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_decoder_join.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_deep_vm.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_parent.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_fixedpoint {

namespace cb = constraint_bytecode;
namespace backend = stage3_multirow_v11_backend;
namespace dj = stage3_multirow_v11_decoder_join;
namespace dvm = stage3_multirow_v11_deep_vm;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace pj = stage3_multirow_v11_parent_join;
namespace rp = stage3_multirow_v11_recursive_parent;
namespace abi = stage3_multirow_v11_proof_abi;

inline constexpr uint16_t kFixedPointVersionV1 = 1;
inline constexpr uint32_t kRelayBudgetMicrosV1 = 900000;
inline constexpr size_t kWireBudgetBytesV1 = 16U << 20;
inline constexpr uint32_t kDefaultSchedulerColumnsV1 = 32;
inline constexpr uint32_t kAuthenticationPathsPerQueryUpperV1 = 8;
inline constexpr uint32_t kDigestBytesV1 = 32;

enum ResidualV1 : uint32_t {
    kResidualCanonicalParentBytecode = 1U << 0,
    kResidualChildVerifierNotInParentAir = 1U << 1,
    kResidualWholeRootVerifyUnmeasured = 1U << 2,
    kResidualWholeRootWireUnmeasured = 1U << 3,
    kResidualFullQueryShardsNotMaterialized = 1U << 4,
    kResidualSemanticCtlNotRecursivelyConsumed = 1U << 5,
};

enum class EvidenceClassV1 : uint8_t {
    Missing = 0,
    Computed = 1,
    Measured = 2,
};

struct WireMeasurementV1 {
    uint32_t trace_rows{0};
    uint32_t columns{0};
    size_t proof_bytes{0};
    uint64_t verify_micros{0};
    EvidenceClassV1 proof_bytes_evidence{EvidenceClassV1::Missing};
    EvidenceClassV1 verify_evidence{EvidenceClassV1::Missing};
};

/**
 * Exact operation inventory taken from executable V11 products.
 *
 * A one-query Merkle/fold shard is allowed: `merkle_query_count` records its
 * exact coverage and the fixed-point screen repeats its rows exactly Q192/q
 * times. It never pretends that those repeated shards were materialized.
 */
struct ExecutableInventoryV1 {
    uint32_t child_trace_columns{0};
    uint32_t parent_join_columns{0};
    uint32_t parent_join_rows{0};
    uint32_t merkle_hash_columns{0};
    uint32_t merkle_hash_rows{0};
    uint32_t merkle_fold_columns{0};
    uint32_t merkle_fold_rows{0};
    uint32_t merkle_query_count{0};
    uint32_t decoder_columns{0};
    uint32_t decoder_rows{0};
    uint32_t deep_vm_columns{0};
    uint32_t deep_vm_rows{0};
    uint32_t deep_vm_real_rows{0};
    uint32_t deep_vm_query_count{0};
    uint32_t deep_vm_instruction_rows{0};
    uint32_t recursive_parent_columns{0};
    uint32_t recursive_parent_rows{0};
    size_t recursive_parent_proof_bytes{0};
    size_t recursive_parent_receipt_bytes{0};
    uint64_t recursive_parent_verify_micros{0};
    bool every_product_valid{false};
    bool full_query_shards_materialized{false};
};

[[nodiscard]] ExecutableInventoryV1 CaptureExecutableInventoryV1(
    const pj::ProductV1& parent_join,
    const mf::ShardProductV1& merkle_fold,
    const dj::ProductV1& decoder,
    const dvm::ProductV1& deep_vm,
    const rp::ProductV1& recursive_parent);

struct CanonicalVmBudgetV1 {
    uint32_t child_proof_columns{0};
    uint32_t query_count{0};
    uint32_t exact_instruction_count{0};
    uint64_t exact_real_rows{0};
    uint32_t trace_rows{0};
    uint64_t lde_rows{0};
    uint32_t max_instructions_under_lde_cap{0};
    bool canonical_table_present{false};
    bool exact_instruction_inventory{false};
    bool trace_rows_fit{false};
    bool lde_rows_fit{false};
};

/**
 * Exact V11 DEEP/VM row law:
 *
 *   q * (batch_columns + instructions + 2)
 *
 * where batch_columns = child trace columns + the quotient column. This is
 * equivalently q * (child_trace_columns + instructions + 3).
 */
[[nodiscard]] CanonicalVmBudgetV1 AssessCanonicalVmBudgetV1(
    uint32_t child_trace_columns,
    const cb::ProgramTable* canonical_parent_table,
    uint32_t query_count = abi::kQueryCountV11);

struct LevelShapeV1 {
    uint32_t arity{0};
    uint32_t max_chip_columns{0};
    uint32_t scheduler_columns{0};
    uint32_t normalized_columns{0};
    uint64_t vertical_active_rows{0};
    uint32_t normalized_trace_rows{0};
    uint64_t lde_rows{0};
    size_t projected_max_proof_bytes{0};
    size_t measured_reference_proof_bytes{0};
    size_t measured_normalized_root_proof_bytes{0};
    size_t measured_root_receipt_bytes{0};
    uint64_t measured_reference_verify_micros{0};
    uint64_t measured_normalized_root_verify_micros{0};
    bool columns_fit{false};
    bool lde_fit{false};
    bool projected_wire_fits{false};
    bool normalized_root_wire_measured{false};
    bool normalized_root_verify_measured{false};
    bool every_wire_proof_fits{false};
    bool root_verify_within_budget{false};
};

struct QueryShardPlanV1 {
    uint32_t arity{0};
    uint32_t queries_per_shard{0};
    uint32_t shards_per_child{0};
    uint32_t binary_receipt_levels{0};
    uint64_t active_rows_per_parent{0};
    uint32_t trace_rows_per_parent{0};
    uint64_t lde_rows_per_parent{0};
    bool exact_vm_inventory{false};
    bool covers_q192_exactly{false};
    bool every_shard_lde_fits{false};
    bool receipt_aggregation_executable{false};
};

/**
 * Find the largest contiguous query shard whose arity-many verifier rows fit
 * under the real LDE cap. `fixed_rows_per_parent` charges transcript/decoder
 * work which cannot be divided by query; `per_query_non_vm_rows` charges the
 * exact Merkle/fold schedule. Receipt aggregation remains explicitly open.
 */
[[nodiscard]] QueryShardPlanV1 SearchQueryShardsV1(
    const CanonicalVmBudgetV1& vm,
    uint32_t arity,
    uint64_t fixed_rows_per_parent,
    uint32_t per_query_non_vm_rows);

struct FixedPointAssessmentV1 {
    LevelShapeV1 level1{};
    LevelShapeV1 level2{};
    CanonicalVmBudgetV1 parent_vm{};
    QueryShardPlanV1 shard_plan{};
    uint32_t width_slope_per_child_proof_column{0};
    uint32_t scheduler_columns_headroom{0};
    uint32_t residual_mask{0};
    bool vertical_chip_multiplexing{false};
    bool width_fixed_point{false};
    bool level_one_fits{false};
    bool level_two_fits{false};
    bool native_level_reentry_available{false};
    bool complete_fixed_point{false};
    bool aggregation_ready{false};
    std::string note;
};

/**
 * Screen an arity-one or arity-two normalized parent. `level1` and `level2`
 * must be independently captured from the actual leaf and parent-proof
 * products. Width is max(chip width)+scheduler because one row-tagged union
 * reuses the same physical chip columns; rows, never columns, grow with
 * arity. `parent_join_wire` is a measured proof, not a declared estimate.
 */
[[nodiscard]] FixedPointAssessmentV1 AssessFixedPointV1(
    const ExecutableInventoryV1& level1,
    const ExecutableInventoryV1& level2,
    const WireMeasurementV1& level1_wire,
    const WireMeasurementV1& level2_wire,
    const cb::ProgramTable* canonical_parent_table,
    uint32_t arity = rp::kRecursiveParentArityV1,
    uint32_t scheduler_columns = kDefaultSchedulerColumnsV1);

/** Convenience screen when one reference measurement projects both levels. */
[[nodiscard]] FixedPointAssessmentV1 AssessFixedPointV1(
    const ExecutableInventoryV1& level1,
    const ExecutableInventoryV1& level2,
    const WireMeasurementV1& reference_wire,
    const cb::ProgramTable* canonical_parent_table,
    uint32_t arity = rp::kRecursiveParentArityV1,
    uint32_t scheduler_columns = kDefaultSchedulerColumnsV1);

struct ReentryAuditV1 {
    uint32_t level_two_child_ordinal{0};
    uint256 level_one_parent_proof_root{};
    uint256 consumed_level_two_child_root{};
    bool exact_child_ordinal{false};
    bool exact_parent_proof_payload{false};
    bool exact_parent_program_continuity{false};
    bool exact_parent_statement_continuity{false};
    bool exact_parent_seed_continuity{false};
    bool exact_parent_shape_continuity{false};
    bool level_two_receipt_native_verified{false};
    bool level_two_parent_own_proof_verified{false};
    bool child_verifier_executed_in_parent_air{false};
    bool recursive_authority_ready{false};
    bool valid_foundation{false};
    std::string note;
};

/**
 * Audit a real level-one V11 parent proof as the exact ordered child of a
 * level-two V11 parent. This re-runs the level-two native receipt verifier and
 * compares proof bytes/root, program, application statement, seed and shape.
 * It deliberately remains a foundation while the child verifier is executed
 * by the host instead of by the parent AIR.
 */
[[nodiscard]] ReentryAuditV1 AuditLevelOneToLevelTwoV1(
    const rp::ProductV1& level_one,
    const std::array<rp::ChildInputV1,
                     rp::kRecursiveParentArityV1>& level_two_inputs,
    const rp::ProductV1& level_two,
    uint32_t level_two_child_ordinal);

inline constexpr bool kCompleteFixedPointReadyV1 = false;
inline constexpr bool kAggregationReadyV1 = false;
static_assert(!kCompleteFixedPointReadyV1);
static_assert(!kAggregationReadyV1);

} // namespace matmul::v4::rc::stage3_multirow_v11_fixedpoint

#endif
