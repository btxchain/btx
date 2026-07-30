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

bool IsPowerOfTwo(uint64_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a > std::numeric_limits<uint64_t>::max() - b) return false;
    out = a + b;
    return true;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 &&
        b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

ConstraintDegreeProfileV1 DegreeProfile(
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& cs)
{
    ConstraintDegreeProfileV1 out;
    if (cs.n_rows < 2 || cs.constraints.empty()) return out;
    for (const auto& constraint : cs.constraints) {
        switch (constraint.kind) {
        case air_quotient::AirKind::kEverywhere:
            out.max_everywhere_degree = std::max(
                out.max_everywhere_degree,
                constraint.alg_degree);
            break;
        case air_quotient::AirKind::kTransition:
            out.max_transition_degree = std::max(
                out.max_transition_degree,
                constraint.alg_degree);
            break;
        case air_quotient::AirKind::kFirstRow:
        case air_quotient::AirKind::kLastRow:
            out.max_boundary_degree = std::max(
                out.max_boundary_degree,
                constraint.alg_degree);
            break;
        }
    }
    out.exact =
        out.max_everywhere_degree != 0 ||
        out.max_transition_degree != 0 ||
        out.max_boundary_degree != 0;
    return out;
}

ConstraintDegreeProfileV1 DegreeProfile(
    const cb::ProgramTable& table)
{
    ConstraintDegreeProfileV1 out;
    if (!cb::ValidateProgramTable(table, nullptr)) return out;
    for (const auto& program : table.programs) {
        switch (program.kind) {
        case air_quotient::AirKind::kEverywhere:
            out.max_everywhere_degree = std::max(
                out.max_everywhere_degree,
                program.declared_degree);
            break;
        case air_quotient::AirKind::kTransition:
            out.max_transition_degree = std::max(
                out.max_transition_degree,
                program.declared_degree);
            break;
        case air_quotient::AirKind::kFirstRow:
        case air_quotient::AirKind::kLastRow:
            out.max_boundary_degree = std::max(
                out.max_boundary_degree,
                program.declared_degree);
            break;
        }
    }
    out.exact =
        out.max_everywhere_degree != 0 ||
        out.max_transition_degree != 0 ||
        out.max_boundary_degree != 0;
    return out;
}

ConstraintDegreeProfileV1 MergeProfiles(
    const ConstraintDegreeProfileV1& a,
    const ConstraintDegreeProfileV1& b)
{
    ConstraintDegreeProfileV1 out;
    out.max_everywhere_degree = std::max(
        a.max_everywhere_degree, b.max_everywhere_degree);
    out.max_transition_degree = std::max(
        a.max_transition_degree, b.max_transition_degree);
    out.max_boundary_degree = std::max(
        a.max_boundary_degree, b.max_boundary_degree);
    out.exact = a.exact && b.exact;
    return out;
}

struct DomainShapeV1 {
    uint32_t max_constraint_degree{0};
    uint64_t max_composed_degree{0};
    uint64_t quotient_len{0};
    uint32_t coefficient_rows{0};
    uint64_t lde_rows{0};
    bool exact{false};
};

DomainShapeV1 DomainForTraceRows(
    const ConstraintDegreeProfileV1& profile,
    uint32_t trace_rows)
{
    DomainShapeV1 out;
    if (!profile.exact || trace_rows < 2) return out;
    const uint64_t n_minus_one =
        static_cast<uint64_t>(trace_rows) - 1;
    auto add_kind = [&out, n_minus_one](
                        uint32_t degree,
                        uint64_t selector_degree) {
        if (degree == 0) return true;
        uint64_t composed = 0;
        if (!CheckedMul(degree, n_minus_one, composed) ||
            !CheckedAdd(
                composed, selector_degree, composed)) {
            return false;
        }
        out.max_constraint_degree = std::max(
            out.max_constraint_degree, degree);
        out.max_composed_degree = std::max(
            out.max_composed_degree, composed);
        return true;
    };
    if (!add_kind(profile.max_everywhere_degree, 0) ||
        !add_kind(profile.max_transition_degree, 1) ||
        !add_kind(
            profile.max_boundary_degree, n_minus_one)) {
        return out;
    }
    out.quotient_len =
        out.max_composed_degree < trace_rows
        ? 1
        : out.max_composed_degree - trace_rows + 1;
    if (out.quotient_len >
        std::numeric_limits<uint32_t>::max()) {
        return out;
    }
    out.coefficient_rows = NextPowerOfTwo(
        std::max<uint64_t>(
            trace_rows, out.quotient_len));
    if (out.coefficient_rows == 0 ||
        !CheckedMul(
            out.coefficient_rows,
            kRCFriBlowup, out.lde_rows)) {
        return out;
    }
    out.exact = true;
    return out;
}

bool RowsForVm(
    uint32_t child_columns,
    uint32_t instructions,
    uint32_t query_count,
    uint64_t& real_rows,
    uint32_t& trace_rows)
{
    uint64_t rows_per_query = 0;
    if (!CheckedAdd(
            child_columns, instructions, rows_per_query) ||
        !CheckedAdd(rows_per_query, 3, rows_per_query) ||
        !CheckedMul(
            rows_per_query, query_count, real_rows)) {
        return false;
    }
    trace_rows = NextPowerOfTwo(real_rows);
    return trace_rows != 0;
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
    uint64_t out = inventory.parent_join_rows;
    return CheckedAdd(out, merkle, out) &&
        CheckedAdd(out, inventory.decoder_rows, out) &&
        CheckedAdd(
            out,
            std::max(
                inventory.deep_vm_rows,
                exact_deep_vm_rows),
            out)
        ? out : 0;
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
    uint64_t normalized_lde_rows)
{
    if (wire.proof_bytes_evidence != EvidenceClassV1::Measured ||
        wire.lde_rows_evidence != EvidenceClassV1::Measured ||
        wire.proof_bytes == 0 || wire.columns == 0 ||
        wire.trace_rows == 0 ||
        !IsPowerOfTwo(wire.lde_rows) ||
        !IsPowerOfTwo(normalized_lde_rows) ||
        wire.lde_rows >
            std::numeric_limits<uint32_t>::max() ||
        normalized_lde_rows >
            std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    const auto wire_domain = DomainForTraceRows(
        wire.constraint_degrees,
        NextPowerOfTwo(wire.trace_rows));
    if (!wire_domain.exact ||
        wire.lde_rows != wire_domain.lde_rows) {
        return 0;
    }
    size_t out = SaturatingMulDivCeil(
        wire.proof_bytes, normalized_columns, wire.columns);
    const uint32_t base_depth =
        Log2Exact(static_cast<uint32_t>(wire.lde_rows));
    const uint32_t normalized_depth =
        Log2Exact(static_cast<uint32_t>(normalized_lde_rows));
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
    uint64_t lde_rows)
{
    if (wire.proof_bytes_evidence != EvidenceClassV1::Measured ||
        wire.lde_rows_evidence != EvidenceClassV1::Measured ||
        wire.proof_bytes == 0 || wire.columns == 0 ||
        wire.lde_rows == 0) {
        return 0;
    }
    uint32_t low = 0;
    uint32_t high =
        kRCFri3AlgBatchMaxColumns > wire.columns
        ? kRCFri3AlgBatchMaxColumns - wire.columns
        : 0;
    while (low < high) {
        const uint32_t mid = low + (high - low + 1) / 2;
        const size_t projected = ProjectWireBytes(
            wire, wire.columns + mid, lde_rows);
        if (projected != 0 &&
            projected <= kWireBudgetBytesV1) {
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
    uint32_t exact_deep_vm_rows,
    const ConstraintDegreeProfileV1& degree_profile)
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
    uint64_t arity_rows = 0;
    if (child_rows != 0 &&
        CheckedMul(child_rows, arity, arity_rows) &&
        CheckedAdd(
            arity_rows,
            inventory.recursive_parent_rows,
            out.vertical_active_rows)) {
        // Set by checked arithmetic above.
    }
    out.normalized_trace_rows =
        NextPowerOfTwo(out.vertical_active_rows);
    const auto domain = DomainForTraceRows(
        degree_profile, out.normalized_trace_rows);
    out.max_constraint_degree =
        domain.max_constraint_degree;
    out.max_composed_degree =
        domain.max_composed_degree;
    out.quotient_len = domain.quotient_len;
    out.coefficient_domain_rows =
        domain.coefficient_rows;
    out.lde_rows = domain.lde_rows;
    out.exact_degree_accounting = domain.exact;
    out.projected_max_proof_bytes = ProjectWireBytes(
        wire, out.normalized_columns, out.lde_rows);
    out.measured_reference_proof_bytes =
        wire.proof_bytes_evidence == EvidenceClassV1::Measured
        ? wire.proof_bytes : 0;
    out.measured_reference_verify_micros =
        wire.verify_evidence == EvidenceClassV1::Measured
        ? wire.verify_micros : 0;
    const bool exact_normalized_shape =
        wire.columns == out.normalized_columns &&
        wire.trace_rows == out.normalized_trace_rows &&
        wire.lde_rows == out.lde_rows &&
        wire.lde_rows_evidence ==
            EvidenceClassV1::Measured;
    out.normalized_root_wire_measured =
        exact_normalized_shape &&
        wire.proof_bytes_evidence == EvidenceClassV1::Measured &&
        wire.proof_bytes != 0;
    out.normalized_root_verify_measured =
        exact_normalized_shape &&
        wire.verify_evidence == EvidenceClassV1::Measured &&
        wire.verify_micros != 0;
    out.measured_normalized_root_proof_bytes =
        out.normalized_root_wire_measured
        ? wire.proof_bytes : 0;
    out.measured_normalized_root_verify_micros =
        out.normalized_root_verify_measured
        ? wire.verify_micros : 0;
    out.measured_root_receipt_bytes =
        inventory.recursive_parent_receipt_bytes;
    out.columns_fit =
        out.normalized_columns != 0 &&
        out.normalized_columns <= kRCFri3AlgBatchMaxColumns;
    out.lde_fit =
        out.exact_degree_accounting &&
        out.normalized_trace_rows != 0 &&
        out.lde_rows <=
            (uint64_t{1} << kRCFriMaxLdeLog2);
    out.projected_wire_fits =
        out.projected_max_proof_bytes != 0 &&
        out.projected_max_proof_bytes <= kWireBudgetBytesV1;
    out.every_wire_proof_fits =
        out.normalized_root_wire_measured &&
        out.measured_normalized_root_proof_bytes <=
            kWireBudgetBytesV1 &&
        out.measured_root_receipt_bytes != 0 &&
        out.measured_root_receipt_bytes <= kWireBudgetBytesV1;
    out.root_verify_within_budget =
        out.normalized_root_verify_measured &&
        out.measured_normalized_root_verify_micros <=
            kRelayBudgetMicrosV1;
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
    out.constraint_degrees = DegreeProfile(parent_join.cs);
    out.constraint_degrees = MergeProfiles(
        out.constraint_degrees,
        DegreeProfile(merkle_fold.hash_cs));
    out.constraint_degrees = MergeProfiles(
        out.constraint_degrees,
        DegreeProfile(merkle_fold.fold_cs));
    out.constraint_degrees = MergeProfiles(
        out.constraint_degrees,
        DegreeProfile(decoder.cs));
    out.constraint_degrees = MergeProfiles(
        out.constraint_degrees,
        DegreeProfile(deep_vm.cs));
    out.constraint_degrees = MergeProfiles(
        out.constraint_degrees,
        DegreeProfile(recursive_parent.parent_proof_cs));
    out.every_product_valid =
        parent_join.valid && merkle_fold.valid &&
        decoder.valid && deep_vm.valid &&
        recursive_parent.valid &&
        out.constraint_degrees.exact;
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
    if (canonical_parent_table == nullptr) return out;
    std::string why;
    out.canonical_table_present =
        cb::ValidateProgramTable(*canonical_parent_table, &why);
    if (!out.canonical_table_present) return out;
    out.constraint_degrees =
        DegreeProfile(*canonical_parent_table);
    if (!out.constraint_degrees.exact) return out;
    out.exact_instruction_count =
        ExactInstructionCount(*canonical_parent_table);
    out.exact_instruction_inventory =
        out.exact_instruction_count != 0;
    if (!out.exact_instruction_inventory) return out;
    if (!RowsForVm(
            child_trace_columns,
            out.exact_instruction_count,
            query_count,
            out.exact_real_rows,
            out.trace_rows)) {
        return out;
    }
    const auto domain = DomainForTraceRows(
        out.constraint_degrees, out.trace_rows);
    out.max_constraint_degree =
        domain.max_constraint_degree;
    out.max_composed_degree =
        domain.max_composed_degree;
    out.quotient_len = domain.quotient_len;
    out.coefficient_domain_rows =
        domain.coefficient_rows;
    out.lde_rows = domain.lde_rows;
    out.exact_degree_accounting = domain.exact;
    const uint32_t max_trace_rows =
        uint32_t{1} << (kRCFriMaxLdeLog2 - 4);
    out.trace_rows_fit =
        out.exact_degree_accounting &&
        out.trace_rows <= max_trace_rows;
    out.lde_rows_fit =
        out.exact_degree_accounting &&
        out.lde_rows != 0 &&
        out.lde_rows <=
            (uint64_t{1} << kRCFriMaxLdeLog2);

    const uint32_t row_instruction_cap =
        max_trace_rows / query_count >
            child_trace_columns + 3
        ? max_trace_rows / query_count -
            child_trace_columns - 3
        : 0;
    uint32_t low = 0;
    uint32_t high = row_instruction_cap;
    while (low < high) {
        const uint32_t mid =
            low + (high - low + 1) / 2;
        uint64_t real_rows = 0;
        uint32_t trace_rows = 0;
        bool fits = RowsForVm(
            child_trace_columns, mid, query_count,
            real_rows, trace_rows);
        const auto candidate = fits
            ? DomainForTraceRows(
                out.constraint_degrees, trace_rows)
            : DomainShapeV1{};
        fits =
            fits && candidate.exact &&
            candidate.lde_rows <=
                (uint64_t{1} << kRCFriMaxLdeLog2);
        if (fits) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    out.max_instructions_under_lde_cap = low;
    return out;
}

QueryShardPlanV1 SearchQueryShardsV1(
    const CanonicalVmBudgetV1& vm,
    uint32_t arity,
    uint64_t fixed_rows_per_parent,
    uint32_t per_query_non_vm_rows,
    const ConstraintDegreeProfileV1* normalized_parent_profile)
{
    QueryShardPlanV1 out;
    out.arity = arity;
    out.exact_vm_inventory =
        vm.canonical_table_present &&
        vm.exact_instruction_inventory &&
        vm.exact_degree_accounting;
    const auto& degree_profile =
        normalized_parent_profile != nullptr
        ? *normalized_parent_profile
        : vm.constraint_degrees;
    if (!out.exact_vm_inventory ||
        !degree_profile.exact ||
        (arity != 1 && arity != 2)) {
        return out;
    }
    const uint64_t vm_rows_per_query =
        uint64_t{vm.child_proof_columns} +
        vm.exact_instruction_count + 3;
    for (uint32_t queries = 1;
         queries <= abi::kQueryCountV11; ++queries) {
        uint64_t rows_per_query = 0;
        uint64_t variable_rows = 0;
        uint64_t rows = 0;
        if (!CheckedAdd(
                vm_rows_per_query,
                per_query_non_vm_rows,
                rows_per_query) ||
            !CheckedMul(
                arity, queries, variable_rows) ||
            !CheckedMul(
                variable_rows,
                rows_per_query,
                variable_rows) ||
            !CheckedAdd(
                fixed_rows_per_parent,
                variable_rows, rows)) {
            break;
        }
        const uint32_t trace = NextPowerOfTwo(rows);
        const auto domain =
            DomainForTraceRows(
                degree_profile, trace);
        if (domain.exact &&
            domain.lde_rows <=
                (uint64_t{1} << kRCFriMaxLdeLog2)) {
            out.queries_per_shard = queries;
            out.active_rows_per_parent = rows;
            out.trace_rows_per_parent = trace;
            out.max_constraint_degree =
                domain.max_constraint_degree;
            out.max_composed_degree =
                domain.max_composed_degree;
            out.quotient_len =
                domain.quotient_len;
            out.coefficient_domain_rows =
                domain.coefficient_rows;
            out.lde_rows_per_parent =
                domain.lde_rows;
            out.exact_degree_accounting =
                true;
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
        out.exact_degree_accounting &&
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
    const WireMeasurementV1& level1_wire,
    const WireMeasurementV1& level2_wire,
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
    const uint64_t parent_vm_columns =
        uint64_t{MaxChipColumns(level2)} +
        scheduler_columns;
    out.parent_vm = AssessCanonicalVmBudgetV1(
        parent_vm_columns <=
            std::numeric_limits<uint32_t>::max()
        ? static_cast<uint32_t>(parent_vm_columns)
        : 0,
        canonical_parent_table);
    const auto level2_degree_profile = MergeProfiles(
        level2.constraint_degrees,
        out.parent_vm.constraint_degrees);
    out.level1 = AssessLevel(
        level1, level1_wire, arity,
        scheduler_columns, 0,
        level1.constraint_degrees);
    out.level2 = AssessLevel(
        level2, level2_wire, arity,
        scheduler_columns, out.parent_vm.trace_rows,
        level2_degree_profile);
    const uint64_t merkle_all =
        MerkleRowsAllQueries(level2);
    const uint64_t merkle_per_query_u64 =
        merkle_all == 0
        ? 0
        : merkle_all / abi::kQueryCountV11;
    uint64_t fixed_rows = level2.parent_join_rows;
    const bool fixed_rows_valid =
        CheckedAdd(
            fixed_rows,
            level2.decoder_rows,
            fixed_rows) &&
        CheckedAdd(
            fixed_rows,
            level2.recursive_parent_rows,
            fixed_rows);
    if (fixed_rows_valid &&
        merkle_per_query_u64 <=
            std::numeric_limits<uint32_t>::max()) {
        out.shard_plan = SearchQueryShardsV1(
            out.parent_vm, arity,
            fixed_rows,
            static_cast<uint32_t>(
                merkle_per_query_u64),
            &level2_degree_profile);
    }
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
        level2_wire,
        std::max(
            out.level1.lde_rows,
            out.level2.lde_rows));
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
        !out.parent_vm.exact_instruction_inventory ||
        !out.parent_vm.exact_degree_accounting ||
        !out.level1.exact_degree_accounting ||
        !out.level2.exact_degree_accounting ||
        !out.shard_plan.exact_degree_accounting) {
        out.residual_mask |= kResidualCanonicalParentBytecode;
    }
    out.residual_mask |=
        kResidualChildVerifierNotInParentAir |
        kResidualSemanticCtlNotRecursivelyConsumed;
    if (!out.level1.normalized_root_verify_measured ||
        !out.level2.normalized_root_verify_measured) {
        out.residual_mask |= kResidualWholeRootVerifyUnmeasured;
    }
    if (!out.level1.normalized_root_wire_measured ||
        !out.level2.normalized_root_wire_measured) {
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

FixedPointAssessmentV1 AssessFixedPointV1(
    const ExecutableInventoryV1& level1,
    const ExecutableInventoryV1& level2,
    const WireMeasurementV1& reference_wire,
    const cb::ProgramTable* canonical_parent_table,
    uint32_t arity,
    uint32_t scheduler_columns)
{
    return AssessFixedPointV1(
        level1, level2, reference_wire, reference_wire,
        canonical_parent_table, arity, scheduler_columns);
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
