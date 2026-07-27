// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_fixedpoint.h>

#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::stage3_multirow_v11_fixedpoint {
namespace {

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value == 0 || value > (uint64_t{1} << 31)) return 0;
    uint64_t out = 1;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

uint32_t Log2Exact(uint32_t value)
{
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

uint32_t ExactInstructionCount(const cb::ProgramTable& table)
{
    uint64_t count = 0;
    for (const auto& program : table.programs) {
        count += program.instructions.size();
    }
    return count > std::numeric_limits<uint32_t>::max()
        ? 0
        : static_cast<uint32_t>(count);
}

uint32_t MaxChipColumns(const ExecutableInventoryV1& inventory)
{
    return std::max({
        inventory.parent_join_columns,
        inventory.merkle_hash_columns,
        inventory.merkle_fold_columns,
        inventory.decoder_columns,
        inventory.deep_vm_columns,
        inventory.recursive_parent_columns,
    });
}

uint64_t MerkleRowsAllQueries(const ExecutableInventoryV1& inventory)
{
    if (inventory.merkle_query_count == 0 ||
        abi::kQueryCountV11 % inventory.merkle_query_count != 0) {
        return 0;
    }
    const uint64_t shards =
        abi::kQueryCountV11 / inventory.merkle_query_count;
    return shards *
        (uint64_t{inventory.merkle_hash_rows} +
         inventory.merkle_fold_rows);
}

uint64_t PerChildRows(
    const ExecutableInventoryV1& inventory,
    uint32_t exact_deep_vm_rows)
{
    const uint64_t merkle = MerkleRowsAllQueries(inventory);
    if (merkle == 0) return 0;
    return uint64_t{inventory.parent_join_rows} +
        merkle +
        inventory.decoder_rows +
        std::max(
            inventory.deep_vm_rows,
            exact_deep_vm_rows);
}

size_t SaturatingMulDivCeil(
    size_t value, uint64_t numerator, uint64_t denominator)
{
    if (denominator == 0) return 0;
    const unsigned __int128 product =
        static_cast<unsigned __int128>(value) * numerator;
    const unsigned __int128 result =
        (product + denominator - 1) / denominator;
    return result > std::numeric_limits<size_t>::max()
        ? std::numeric_limits<size_t>::max()
        : static_cast<size_t>(result);
}

size_t ProjectWireBytes(
    const WireMeasurementV1& wire,
    uint32_t normalized_columns,
    uint32_t normalized_trace_rows)
{
    if (wire.proof_bytes_evidence != EvidenceClassV1::Measured ||
        wire.proof_bytes == 0 || wire.columns == 0 ||
        wire.trace_rows == 0 || normalized_trace_rows == 0) {
        return 0;
    }
    size_t out = SaturatingMulDivCeil(
        wire.proof_bytes, normalized_columns, wire.columns);
    const uint32_t base_depth =
        Log2Exact(NextPowerOfTwo(wire.trace_rows) * kRCFriBlowup);
    const uint32_t normalized_depth =
        Log2Exact(normalized_trace_rows * kRCFriBlowup);
    if (normalized_depth > base_depth) {
        const uint64_t depth_delta = normalized_depth - base_depth;
        const uint64_t path_bytes =
            depth_delta * abi::kQueryCountV11 *
            kAuthenticationPathsPerQueryUpperV1 *
            kDigestBytesV1;
        if (path_bytes >
            std::numeric_limits<size_t>::max() - out) {
            return std::numeric_limits<size_t>::max();
        }
        out += static_cast<size_t>(path_bytes);
    }
    return out;
}

uint32_t SchedulerHeadroom(
    const WireMeasurementV1& wire,
    uint32_t trace_rows)
{
    if (wire.proof_bytes_evidence != EvidenceClassV1::Measured ||
        wire.proof_bytes == 0 || wire.columns == 0) {
        return 0;
    }
    uint32_t low = 0;
    uint32_t high =
        kRCFri3AlgBatchMaxColumns > wire.columns
        ? kRCFri3AlgBatchMaxColumns - wire.columns
        : 0;
    while (low < high) {
        const uint32_t mid = low + (high - low + 1) / 2;
        if (ProjectWireBytes(
                wire, wire.columns + mid, trace_rows) <=
            kWireBudgetBytesV1) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    return low;
}

LevelShapeV1 AssessLevel(
    const ExecutableInventoryV1& inventory,
    const WireMeasurementV1& wire,
    uint32_t arity,
    uint32_t scheduler_columns,
    uint32_t exact_deep_vm_rows)
{
    LevelShapeV1 out;
    out.arity = arity;
    out.max_chip_columns = MaxChipColumns(inventory);
    out.scheduler_columns = scheduler_columns;
    const uint64_t width =
        uint64_t{out.max_chip_columns} + scheduler_columns;
    out.normalized_columns =
        width <= std::numeric_limits<uint32_t>::max()
        ? static_cast<uint32_t>(width) : 0;
    const uint64_t child_rows =
        PerChildRows(inventory, exact_deep_vm_rows);
    out.vertical_active_rows =
        child_rows == 0 ? 0 :
        child_rows * arity + inventory.recursive_parent_rows;
    out.normalized_trace_rows =
        NextPowerOfTwo(out.vertical_active_rows);
    out.lde_rows =
        uint64_t{out.normalized_trace_rows} * kRCFriBlowup;
    out.projected_max_proof_bytes = ProjectWireBytes(
        wire, out.normalized_columns, out.normalized_trace_rows);
    out.measured_root_receipt_bytes =
        inventory.recursive_parent_receipt_bytes;
    out.measured_root_verify_micros =
        inventory.recursive_parent_verify_micros;
    out.columns_fit =
        out.normalized_columns != 0 &&
        out.normalized_columns <= kRCFri3AlgBatchMaxColumns;
    out.lde_fit =
        out.normalized_trace_rows != 0 &&
        out.lde_rows <=
            (uint64_t{1} << kRCFriMaxLdeLog2);
    out.every_wire_proof_fits =
        out.projected_max_proof_bytes != 0 &&
        out.projected_max_proof_bytes <= kWireBudgetBytesV1 &&
        out.measured_root_receipt_bytes != 0 &&
        out.measured_root_receipt_bytes <= kWireBudgetBytesV1;
    out.root_verify_within_budget =
        out.measured_root_verify_micros != 0 &&
        out.measured_root_verify_micros <= kRelayBudgetMicrosV1;
    return out;
}

bool EqualProofPayload(
    const backend::ProofV1& a,
    const backend::ProofV1& b)
{
    std::vector<unsigned char> aw;
    std::vector<unsigned char> bw;
    return backend::SerializeV1(a, aw) != 0 &&
        backend::SerializeV1(b, bw) != 0 &&
        aw == bw;
}

} // namespace

ExecutableInventoryV1 CaptureExecutableInventoryV1(
    const pj::ProductV1& parent_join,
    const mf::ShardProductV1& merkle_fold,
    const dj::ProductV1& decoder,
    const dvm::ProductV1& deep_vm,
    const rp::ProductV1& recursive_parent)
{
    ExecutableInventoryV1 out;
    out.child_trace_columns =
        recursive_parent.receipt.children[0].trace_columns;
    out.parent_join_columns = parent_join.cs.n_columns;
    out.parent_join_rows = parent_join.cs.n_rows;
    out.merkle_hash_columns = merkle_fold.hash_cs.n_columns;
    out.merkle_hash_rows = merkle_fold.hash_trace_rows;
    out.merkle_fold_columns = merkle_fold.fold_cs.n_columns;
    out.merkle_fold_rows = merkle_fold.fold_trace_rows;
    out.merkle_query_count = merkle_fold.query_count;
    out.decoder_columns = decoder.cs.n_columns;
    out.decoder_rows = decoder.trace_rows;
    out.deep_vm_columns = deep_vm.cs.n_columns;
    out.deep_vm_rows = deep_vm.trace_rows;
    out.deep_vm_real_rows = deep_vm.real_rows;
    out.deep_vm_query_count = deep_vm.query_count;
    out.deep_vm_instruction_rows =
        deep_vm.vm_instruction_rows;
    out.recursive_parent_columns =
        recursive_parent.parent_proof_cs.n_columns;
    out.recursive_parent_rows =
        recursive_parent.parent_proof_cs.n_rows;
    out.recursive_parent_proof_bytes =
        recursive_parent.parent_proof_bytes;
    out.recursive_parent_receipt_bytes =
        recursive_parent.encoded_bytes;
    out.recursive_parent_verify_micros =
        recursive_parent.parent_verify_micros;
    out.every_product_valid =
        parent_join.valid && merkle_fold.valid &&
        decoder.valid && deep_vm.valid &&
        recursive_parent.valid;
    out.full_query_shards_materialized =
        recursive_parent.fully_materialized_children ==
            rp::kRecursiveParentArityV1;
    return out;
}

CanonicalVmBudgetV1 AssessCanonicalVmBudgetV1(
    uint32_t child_trace_columns,
    const cb::ProgramTable* canonical_parent_table,
    uint32_t query_count)
{
    CanonicalVmBudgetV1 out;
    out.child_proof_columns = child_trace_columns;
    out.query_count = query_count;
    if (child_trace_columns == 0 || query_count == 0) return out;
    // At most floor(2^20/Q)-W-3 instructions: trace rows are bounded by
    // 2^20 because the FRI blowup is 16 under a 2^24 LDE cap.
    const uint32_t max_trace_rows =
        uint32_t{1} << (kRCFriMaxLdeLog2 - 4);
    const uint32_t per_query_cap = max_trace_rows / query_count;
    out.max_instructions_under_lde_cap =
        per_query_cap > child_trace_columns + 3
        ? per_query_cap - child_trace_columns - 3
        : 0;
    if (canonical_parent_table == nullptr) return out;
    std::string why;
    out.canonical_table_present =
        cb::ValidateProgramTable(*canonical_parent_table, &why);
    if (!out.canonical_table_present) return out;
    out.exact_instruction_count =
        ExactInstructionCount(*canonical_parent_table);
    out.exact_instruction_inventory =
        out.exact_instruction_count != 0;
    if (!out.exact_instruction_inventory) return out;
    out.exact_real_rows =
        uint64_t{query_count} *
        (uint64_t{child_trace_columns} +
         out.exact_instruction_count + 3);
    out.trace_rows = NextPowerOfTwo(out.exact_real_rows);
    out.lde_rows = uint64_t{out.trace_rows} * kRCFriBlowup;
    out.trace_rows_fit =
        out.trace_rows != 0 &&
        out.trace_rows <= max_trace_rows;
    out.lde_rows_fit =
        out.lde_rows != 0 &&
        out.lde_rows <=
            (uint64_t{1} << kRCFriMaxLdeLog2);
    return out;
}

QueryShardPlanV1 SearchQueryShardsV1(
    const CanonicalVmBudgetV1& vm,
    uint32_t arity,
    uint64_t fixed_rows_per_parent,
    uint32_t per_query_non_vm_rows)
{
    QueryShardPlanV1 out;
    out.arity = arity;
    out.exact_vm_inventory =
        vm.canonical_table_present &&
        vm.exact_instruction_inventory;
    if (!out.exact_vm_inventory ||
        (arity != 1 && arity != 2)) {
        return out;
    }
    const uint64_t vm_rows_per_query =
        uint64_t{vm.child_proof_columns} +
        vm.exact_instruction_count + 3;
    for (uint32_t queries = 1;
         queries <= abi::kQueryCountV11; ++queries) {
        const uint64_t rows =
            fixed_rows_per_parent +
            uint64_t{arity} * queries *
                (vm_rows_per_query +
                 per_query_non_vm_rows);
        const uint32_t trace = NextPowerOfTwo(rows);
        if (trace != 0 &&
            uint64_t{trace} * kRCFriBlowup <=
                (uint64_t{1} << kRCFriMaxLdeLog2)) {
            out.queries_per_shard = queries;
            out.active_rows_per_parent = rows;
            out.trace_rows_per_parent = trace;
            out.lde_rows_per_parent =
                uint64_t{trace} * kRCFriBlowup;
        }
    }
    if (out.queries_per_shard == 0) return out;
    out.shards_per_child =
        (abi::kQueryCountV11 +
         out.queries_per_shard - 1) /
        out.queries_per_shard;
    uint32_t receipts =
        out.shards_per_child * arity;
    while (receipts > 1) {
        receipts = (receipts + 1) / 2;
        ++out.binary_receipt_levels;
    }
    out.covers_q192_exactly =
        out.shards_per_child != 0 &&
        uint64_t{out.shards_per_child} *
            out.queries_per_shard >=
            abi::kQueryCountV11;
    out.every_shard_lde_fits =
        out.lde_rows_per_parent <=
            (uint64_t{1} << kRCFriMaxLdeLog2);
    // The schedule is exact, but no executable in-parent receipt-tree chip
    // currently consumes its roots/order. Never turn a shape calculation
    // into an AggregationReady claim.
    out.receipt_aggregation_executable = false;
    return out;
}

FixedPointAssessmentV1 AssessFixedPointV1(
    const ExecutableInventoryV1& level1,
    const ExecutableInventoryV1& level2,
    const WireMeasurementV1& parent_join_wire,
    const cb::ProgramTable* canonical_parent_table,
    uint32_t arity,
    uint32_t scheduler_columns)
{
    FixedPointAssessmentV1 out;
    if ((arity != 1 && arity != 2) ||
        scheduler_columns == 0 ||
        !level1.every_product_valid ||
        !level2.every_product_valid) {
        out.note = "stage3:v11_fixedpoint:invalid_inventory";
        return out;
    }
    out.parent_vm = AssessCanonicalVmBudgetV1(
        MaxChipColumns(level2) + scheduler_columns,
        canonical_parent_table);
    out.level1 = AssessLevel(
        level1, parent_join_wire, arity,
        scheduler_columns, 0);
    out.level2 = AssessLevel(
        level2, parent_join_wire, arity,
        scheduler_columns, out.parent_vm.trace_rows);
    const uint64_t merkle_all =
        MerkleRowsAllQueries(level2);
    const uint32_t merkle_per_query =
        merkle_all == 0
        ? 0
        : static_cast<uint32_t>(
            merkle_all / abi::kQueryCountV11);
    out.shard_plan = SearchQueryShardsV1(
        out.parent_vm, arity,
        uint64_t{level2.parent_join_rows} +
            level2.decoder_rows +
            level2.recursive_parent_rows,
        merkle_per_query);
    out.vertical_chip_multiplexing = true;
    out.width_slope_per_child_proof_column =
        out.level2.normalized_columns ==
            out.level1.normalized_columns
        ? 0
        : (out.level2.normalized_columns >
                out.level1.normalized_columns &&
            level2.child_trace_columns >
                level1.child_trace_columns
            ? (out.level2.normalized_columns -
               out.level1.normalized_columns) /
              (level2.child_trace_columns -
               level1.child_trace_columns)
            : std::numeric_limits<uint32_t>::max());
    out.width_fixed_point =
        out.width_slope_per_child_proof_column == 0 &&
        out.level1.normalized_columns ==
            out.level2.normalized_columns;
    out.scheduler_columns_headroom = SchedulerHeadroom(
        parent_join_wire,
        std::max(
            out.level1.normalized_trace_rows,
            out.level2.normalized_trace_rows));
    out.level_one_fits =
        out.level1.columns_fit && out.level1.lde_fit &&
        out.level1.every_wire_proof_fits &&
        out.level1.root_verify_within_budget;
    out.level_two_fits =
        out.level2.columns_fit && out.level2.lde_fit &&
        out.level2.every_wire_proof_fits &&
        out.level2.root_verify_within_budget;
    out.native_level_reentry_available = true;
    if (!out.parent_vm.canonical_table_present ||
        !out.parent_vm.exact_instruction_inventory) {
        out.residual_mask |= kResidualCanonicalParentBytecode;
    }
    out.residual_mask |=
        kResidualChildVerifierNotInParentAir |
        kResidualSemanticCtlNotRecursivelyConsumed;
    if (parent_join_wire.verify_evidence !=
        EvidenceClassV1::Measured) {
        out.residual_mask |= kResidualWholeRootVerifyUnmeasured;
    }
    if (parent_join_wire.proof_bytes_evidence !=
        EvidenceClassV1::Measured) {
        out.residual_mask |= kResidualWholeRootWireUnmeasured;
    }
    if (!level1.full_query_shards_materialized ||
        !level2.full_query_shards_materialized) {
        out.residual_mask |=
            kResidualFullQueryShardsNotMaterialized;
    }
    out.complete_fixed_point =
        out.width_fixed_point &&
        out.level_one_fits &&
        out.level_two_fits &&
        out.parent_vm.lde_rows_fit &&
        out.residual_mask == 0;
    out.aggregation_ready = false;
    out.note =
        out.complete_fixed_point
        ? "stage3:v11_fixedpoint:complete"
        : "stage3:v11_fixedpoint:shape_screen;"
          "recursive_child_verifier_pending";
    return out;
}

ReentryAuditV1 AuditLevelOneToLevelTwoV1(
    const rp::ProductV1& level_one,
    const std::array<rp::ChildInputV1,
                     rp::kRecursiveParentArityV1>& level_two_inputs,
    const rp::ProductV1& level_two,
    uint32_t level_two_child_ordinal)
{
    ReentryAuditV1 out;
    out.level_two_child_ordinal = level_two_child_ordinal;
    if (!level_one.valid || !level_two.valid ||
        level_two_child_ordinal >= rp::kRecursiveParentArityV1) {
        out.note = "stage3:v11_reentry:invalid_input";
        return out;
    }
    const auto& input =
        level_two_inputs[level_two_child_ordinal];
    const auto& consumed =
        level_two.receipt.children[level_two_child_ordinal];
    out.level_one_parent_proof_root =
        level_one.receipt.parent_proof_root;
    out.consumed_level_two_child_root =
        consumed.proof_wire_root;
    out.exact_child_ordinal =
        consumed.ordinal == level_two_child_ordinal;
    out.exact_parent_proof_payload =
        EqualProofPayload(
            input.proof, level_one.receipt.parent_proof) &&
        consumed.proof_wire_root ==
            level_one.receipt.parent_proof_root;
    out.exact_parent_program_continuity =
        input.statement.program_root ==
            level_one.receipt.parent_program_root &&
        consumed.program_root ==
            level_one.receipt.parent_program_root;
    out.exact_parent_statement_continuity =
        input.statement.application_statement_root ==
            level_one.receipt.parent_application_statement_root &&
        consumed.application_statement_root ==
            level_one.receipt.parent_application_statement_root;
    out.exact_parent_seed_continuity =
        input.statement.public_fs_seed ==
            level_one.receipt.parent_fs_seed &&
        consumed.public_fs_seed ==
            level_one.receipt.parent_fs_seed;
    out.exact_parent_shape_continuity =
        input.cs.n_rows == level_one.parent_proof_cs.n_rows &&
        input.cs.n_columns ==
            level_one.parent_proof_cs.n_columns &&
        consumed.trace_rows ==
            level_one.parent_proof_cs.n_rows &&
        consumed.trace_columns ==
            level_one.parent_proof_cs.n_columns;
    std::string why;
    out.level_two_receipt_native_verified =
        rp::VerifyReceiptV1(
            level_two_inputs, level_two.receipt, &why);
    out.level_two_parent_own_proof_verified =
        level_two.parent_own_v11_proof_verified;
    out.child_verifier_executed_in_parent_air =
        level_two.child_verifier_executed_in_parent_air;
    out.recursive_authority_ready =
        out.child_verifier_executed_in_parent_air &&
        level_two.recursive_authority_ready;
    out.valid_foundation =
        out.exact_child_ordinal &&
        out.exact_parent_proof_payload &&
        out.exact_parent_program_continuity &&
        out.exact_parent_statement_continuity &&
        out.exact_parent_seed_continuity &&
        out.exact_parent_shape_continuity &&
        out.level_two_receipt_native_verified &&
        out.level_two_parent_own_proof_verified &&
        !out.recursive_authority_ready;
    out.note =
        out.valid_foundation
        ? "stage3:v11_reentry:exact_native_foundation;"
          "child_verifier_not_in_parent_air"
        : "stage3:v11_reentry:continuity_failure:" + why;
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_fixedpoint
