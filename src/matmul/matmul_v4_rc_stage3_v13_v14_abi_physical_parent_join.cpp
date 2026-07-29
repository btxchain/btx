// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_v14_abi_physical_parent_join.h>

#include <hash.h>
#include <streams.h>

#include <algorithm>
#include <numeric>
#include <utility>

namespace matmul::v4::rc::stage3_v13_v14_abi_physical_parent_join {
namespace {

using AirCS = aq::AirConstraintSystem<gf::Fp3>;
using gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:v13_v14_abi_physical_parent:" + detail;
    }
    return false;
}

bool CopyShiftedColumns(
    const std::vector<std::vector<Fp3>>& local,
    uint32_t offset,
    uint32_t local_rows,
    uint32_t parent_rows,
    std::vector<std::vector<Fp3>>& parent,
    std::string* why)
{
    if (offset + local.size() > parent.size()) {
        return Fail(why, "copy_columns");
    }
    for (uint32_t column = 0;
         column < local.size(); ++column) {
        if (local[column].size() != local_rows ||
            parent[offset + column].size() !=
                parent_rows) {
            return Fail(why, "copy_rows");
        }
        std::copy(
            local[column].begin(),
            local[column].end(),
            parent[offset + column].begin());
    }
    return true;
}

bool FillWrapBroadcast(
    const std::vector<std::vector<Fp3>>& local,
    const composer::ChildAttachmentV1& attachment,
    uint32_t parent_rows,
    std::vector<std::vector<Fp3>>& parent,
    std::string* why)
{
    if (!attachment.valid ||
        attachment.semantic_child_columns !=
            local.size()) {
        return Fail(why, "wrap_shape");
    }
    if (!attachment.row_lifted) return true;
    if (
        attachment.column_base +
                2 * local.size() >
            parent.size()) {
        return Fail(why, "wrap_shape");
    }
    const uint32_t wrap_base =
        attachment.column_base +
        attachment.semantic_child_columns;
    for (uint32_t column = 0;
         column < local.size(); ++column) {
        if (local[column].empty() ||
            parent[wrap_base + column].size() !=
                parent_rows) {
            return Fail(why, "wrap_rows");
        }
        std::fill(
            parent[wrap_base + column].begin(),
            parent[wrap_base + column].end(),
            local[column][0]);
    }
    return true;
}

void AppendDigest(
    HashWriter& hash,
    const alg_hash::Digest& digest)
{
    for (const gf::Fp lane : digest) {
        hash << static_cast<uint64_t>(lane);
    }
}

uint256 CommitPlan(
    const PlanV1& plan,
    const tape::PublicBindingV1& tape_binding,
    const alg_hash::Digest& transcript_commitment,
    const derived::BindingV1& derived_binding)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_V13_V14_ABI_PHYSICAL_PARENT_JOIN_V1"};
    hash << plan.version;
    hash << plan.parent_rows;
    hash << plan.tape_offset;
    hash << plan.tape_columns;
    hash << plan.tape_rows;
    hash << plan.prefix_offset;
    hash << plan.prefix_columns;
    hash << plan.prefix_rows;
    hash << plan.v14_offset;
    hash << plan.resident_columns;
    hash << plan.tape_attachment.column_base;
    hash << plan.tape_attachment.semantic_child_columns;
    hash << plan.tape_attachment.column_count;
    hash << plan.prefix_attachment.column_base;
    hash << plan.prefix_attachment.semantic_child_columns;
    hash << plan.prefix_attachment.column_count;
    hash << tape_binding.program_root;
    hash << tape_binding.statement_root;
    hash << tape_binding.public_fs_seed;
    hash << tape_binding.proof_wire_root;
    AppendDigest(hash, tape_binding.tape_root);
    AppendDigest(hash, transcript_commitment);
    AppendDigest(hash, derived_binding.shape_commit);
    AppendDigest(
        hash,
        derived_binding.ood_evaluation_commit);
    AppendDigest(hash, plan.abi_plan.plan_root);
    hash << static_cast<uint32_t>(
        plan.complete_r0_base_column_indices.size());
    for (const uint32_t column :
         plan.complete_r0_base_column_indices) {
        hash << column;
    }
    return hash.GetHash();
}

bool SamePublicPrefix(
    const prefix::ProductV1& product,
    const occurrence::ManifestV1& manifest)
{
    return product.valid &&
        product.program_root ==
            manifest.program_root &&
        product.provenance_relation_resident &&
        product.verifier_rebuilt_prefix_preprocessed &&
        product.consumer_u32_decomposition_constrained &&
        product.every_prefix_occurrence_bound &&
        product.exact_multiplicity_consumed &&
        !product.canonical_abi_relation_resident &&
        !product.recursively_consumed &&
        !product.recursive_authority_ready;
}

bool FillResidentColumns(
    const tape::ProductV1& tape_product,
    const prefix::ProductV1& prefix_product,
    const PlanV1& plan,
    const AirCS& resident_parent_cs,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    if (tape_product.cs.n_rows !=
            plan.tape_rows ||
        tape_product.cs.n_columns !=
            plan.tape_columns ||
        prefix_product.cs.n_rows !=
            plan.prefix_rows ||
        prefix_product.cs.n_columns !=
            plan.prefix_columns ||
        resident_parent_cs.n_columns !=
            plan.resident_columns) {
        return Fail(why, "product_shape");
    }
    columns.assign(
        plan.resident_columns,
        std::vector<Fp3>(
            plan.parent_rows,
            Fp3::Zero()));
    if (!CopyShiftedColumns(
            tape_product.columns,
            plan.tape_offset,
            plan.tape_rows,
            plan.parent_rows,
            columns,
            why) ||
        !CopyShiftedColumns(
            prefix_product.columns,
            plan.prefix_offset,
            plan.prefix_rows,
            plan.parent_rows,
            columns,
            why) ||
        !FillWrapBroadcast(
            tape_product.columns,
            plan.tape_attachment,
            plan.parent_rows,
            columns,
            why) ||
        !FillWrapBroadcast(
            prefix_product.columns,
            plan.prefix_attachment,
            plan.parent_rows,
            columns,
            why)) {
        return false;
    }
    for (const auto& [column, values] :
         resident_parent_cs.preprocessed) {
        if (column >= columns.size() ||
            values.size() != plan.parent_rows) {
            return Fail(
                why, "product_preprocessed");
        }
        columns[column] = values;
    }
    return true;
}

abi_join::LayoutV1 ShiftLayout(
    const abi_join::LayoutV1& local,
    uint32_t column_base)
{
    abi_join::LayoutV1 out = local;
    out.original_columns += column_base;
    out.consumer_bit_base += column_base;
    out.consumer_decompose_mask_base += column_base;
    out.source_active_base += column_base;
    out.source_multiplicity_base += column_base;
    out.consumer_active_base += column_base;
    out.consumer_key_base += column_base;
    out.dependent_base += column_base;
    out.source_inverse_base += column_base;
    out.consumer_inverse_base += column_base;
    out.running_base += column_base;
    out.end += column_base;
    return out;
}

bool RelocateEmbeddedBase(
    const PublicDeterministicComponentV1& component,
    const composer::ChildAttachmentV1& attachment,
    const AirCS& parent_cs,
    abi_join::PlanV1& relocated_plan,
    abi_join::EmbeddedBaseV1& relocated_base,
    std::string* why)
{
    relocated_plan = {};
    relocated_base = {};
    if (!component.valid ||
        !attachment.valid ||
        attachment.row_lifted ||
        !attachment.literal_column_mapping ||
        attachment.semantic_child_columns !=
            component.cs.n_columns ||
        attachment.column_base >
            parent_cs.n_columns ||
        component.cs.n_columns >
            parent_cs.n_columns -
                attachment.column_base ||
        parent_cs.n_rows !=
            component.cs.n_rows) {
        return Fail(
            why, "component_relocation_input");
    }
    std::string local_why;
    if (!abi_join::BuildCanonicalPlanV1(
            component.shape,
            component.tape_binding,
            component.manifest.canonical_program,
            component.manifest,
            parent_cs.n_rows,
            attachment.ParentColumn(
                component.plan.tape_offset),
            attachment.ParentColumn(
                component.plan.v14_offset),
            relocated_plan,
            &local_why)) {
        return Fail(
            why, "component_relocation_plan:" +
                     local_why);
    }
    relocated_base =
        component.abi_base;
    relocated_base.plan =
        relocated_plan;
    relocated_base.layout =
        ShiftLayout(
            component.abi_base.layout,
            attachment.column_base);
    relocated_base.original_columns +=
        attachment.column_base;
    for (uint32_t& column :
         relocated_base
             .complete_r0_base_column_indices) {
        column =
            attachment.ParentColumn(column);
    }
    relocated_base.valid =
        component.abi_base.valid &&
        relocated_base.layout.dependent_base ==
            attachment.column_base +
                component.abi_base
                    .layout.dependent_base &&
        relocated_base
                .complete_r0_base_column_indices
                .size() ==
            component.abi_base
                .complete_r0_base_column_indices
                .size();
    relocated_base.note =
        relocated_base.valid
        ? "canonical ABI base relocated into global parent"
        : "relocated ABI base incomplete";
    if (!relocated_base.valid) {
        return Fail(
            why, "component_relocation_invariant");
    }
    return true;
}

} // namespace

bool BuildResidentParentV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    AirCS& resident_parent_cs,
    PlanV1& plan,
    std::string* why)
{
    resident_parent_cs = {};
    plan = {};
    AirCS tape_cs;
    AirCS prefix_cs;
    tape::LayoutV1 tape_layout;
    tape::ScheduleV1 tape_schedule;
    prefix::PlanV1 prefix_plan;
    provenance::PlanV1 provenance_plan;
    std::string local_why;
    if (!occurrence::
            ValidateCanonicalOccurrenceManifestV1(
                shape, manifest.canonical_program,
                manifest, &local_why) ||
        !tape::BuildConstraintSystemV1(
            shape, tape_binding, tape_cs,
            &tape_layout, &tape_schedule,
            &local_why) ||
        !prefix::BuildConstraintSystemV1(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            prefix_cs, &prefix_plan,
            &local_why) ||
        !provenance::BuildCanonicalPlanV1(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            provenance_plan, &local_why)) {
        return Fail(
            why, "public_rebuild:" + local_why);
    }
    if (!tape_schedule.valid ||
        !prefix_plan.valid ||
        !provenance_plan.valid ||
        tape_cs.n_rows < 2 ||
        prefix_cs.n_rows < 2) {
        return Fail(why, "resident_shape");
    }

    plan.parent_rows =
        std::max(
            tape_cs.n_rows,
            prefix_cs.n_rows);
    plan.tape_columns = tape_cs.n_columns;
    plan.tape_rows = tape_cs.n_rows;
    plan.prefix_columns = prefix_cs.n_columns;
    plan.prefix_rows = prefix_cs.n_rows;
    std::vector<std::vector<Fp3>> parent_columns;
    const std::vector<std::vector<Fp3>> zero_tape(
        tape_cs.n_columns,
        std::vector<Fp3>(
            tape_cs.n_rows, Fp3::Zero()));
    const std::vector<std::vector<Fp3>> zero_prefix(
        prefix_cs.n_columns,
        std::vector<Fp3>(
            prefix_cs.n_rows, Fp3::Zero()));
    const auto append =
        [&](const AirCS& child_cs,
            const std::vector<
                std::vector<Fp3>>& child_columns,
            uint32_t ordinal,
            composer::ChildAttachmentV1& attachment) {
            if (child_cs.n_rows ==
                plan.parent_rows) {
                return composer::AppendChildV1(
                    resident_parent_cs,
                    parent_columns,
                    child_cs, child_columns,
                    ordinal, attachment, why);
            }
            return composer::AppendChildLiftedV1(
                resident_parent_cs,
                parent_columns,
                child_cs, child_columns,
                plan.parent_rows, ordinal,
                attachment, why);
        };
    if (!append(
            tape_cs, zero_tape, 0,
            plan.tape_attachment) ||
        !append(
            prefix_cs, zero_prefix, 1,
            plan.prefix_attachment)) {
        resident_parent_cs = {};
        plan = {};
        return false;
    }
    plan.tape_offset =
        plan.tape_attachment.column_base;
    plan.prefix_offset =
        plan.prefix_attachment.column_base;
    plan.v14_offset =
        plan.prefix_offset +
        provenance_plan.fused_offset;
    plan.resident_columns =
        resident_parent_cs.n_columns;

    plan.complete_r0_base_column_indices.resize(
        plan.resident_columns);
    std::iota(
        plan.complete_r0_base_column_indices.begin(),
        plan.complete_r0_base_column_indices.end(),
        0U);
    if (!abi_join::BuildCanonicalPlanV1(
            shape, tape_binding,
            manifest.canonical_program,
            manifest, plan.parent_rows,
            plan.tape_offset, plan.v14_offset,
            plan.abi_plan, &local_why)) {
        resident_parent_cs = {};
        plan = {};
        return Fail(
            why, "abi_plan:" + local_why);
    }

    plan.tape_layout_rebuilt =
        tape_layout.End() == tape_cs.n_columns &&
        plan.tape_attachment.valid &&
        plan.tape_attachment.literal_column_mapping &&
        (!plan.tape_attachment.row_lifted ||
         plan.tape_attachment.padding_zero_constrained) &&
        plan.tape_attachment.semantic_child_columns ==
            tape_cs.n_columns;
    plan.prefix_layout_rebuilt =
        prefix_plan.total_columns ==
            prefix_cs.n_columns &&
        prefix_plan.provenance_columns ==
            provenance_plan.total_columns &&
        plan.prefix_attachment.valid &&
        plan.prefix_attachment.literal_column_mapping &&
        (!plan.prefix_attachment.row_lifted ||
         plan.prefix_attachment.padding_zero_constrained) &&
        plan.prefix_attachment.semantic_child_columns ==
            prefix_cs.n_columns;
    plan.exact_abi_plan_rebuilt =
        plan.abi_plan.valid &&
        plan.abi_plan.tape_column_offset ==
            plan.tape_offset &&
        plan.abi_plan.v14_column_offset ==
            plan.v14_offset;
    plan.complete_parent_r0 =
        plan.complete_r0_base_column_indices.size() ==
            resident_parent_cs.n_columns &&
        !plan.complete_r0_base_column_indices.empty() &&
        plan.complete_r0_base_column_indices.front() ==
            0 &&
        plan.complete_r0_base_column_indices.back() +
                1 ==
            resident_parent_cs.n_columns;
    plan.plan_root = CommitPlan(
        plan, tape_binding,
        expected_transcript_commitment,
        expected_derived_binding);
    plan.valid =
        plan.tape_layout_rebuilt &&
        plan.prefix_layout_rebuilt &&
        plan.exact_abi_plan_rebuilt &&
        plan.complete_parent_r0 &&
        !plan.plan_root.IsNull();
    plan.note = plan.valid
        ? "actual proof-tape and V14 prefix verifiers share one "
          "parent; exact physical ABI map and complete R0 rebuilt"
        : "physical parent plan incomplete";
    if (!plan.valid) {
        resident_parent_cs = {};
        return Fail(why, "plan_invariant");
    }
    if (why != nullptr) *why = plan.note;
    return true;
}

bool BuildDeterministicConstraintSystemV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    PublicDeterministicComponentV1& out,
    std::string* why)
{
    out = {};
    out.shape = shape;
    out.tape_binding = tape_binding;
    out.manifest = manifest;
    out.transcript_commitment =
        expected_transcript_commitment;
    out.derived_binding =
        expected_derived_binding;
    if (!BuildResidentParentV1(
            shape, tape_binding, manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            out.cs, out.plan, why) ||
        !abi_join::
            AppendEmbeddedBaseConstraintSystemV1(
                out.plan.abi_plan,
                out.plan
                    .complete_r0_base_column_indices,
                out.cs, out.abi_base, why)) {
        out = {};
        return false;
    }
    out.r0_base_column_indices =
        out.abi_base
            .complete_r0_base_column_indices;
    out.actual_verifiers_resident =
        out.plan.tape_layout_rebuilt &&
        out.plan.prefix_layout_rebuilt;
    out.exact_physical_abi_pre_r0 =
        out.plan.exact_abi_plan_rebuilt &&
        out.abi_base.physical_parent_cells_in_r0 &&
        out.abi_base
            .verifier_schedule_preprocessed;
    out.challenge_columns_absent =
        out.abi_base.challenge_columns_absent &&
        out.cs.n_columns ==
            out.abi_base.layout.dependent_base;
    out.valid =
        out.actual_verifiers_resident &&
        out.exact_physical_abi_pre_r0 &&
        out.challenge_columns_absent &&
        out.r0_base_column_indices.size() ==
            out.cs.n_columns &&
        !out.r0_base_column_indices.empty() &&
        out.r0_base_column_indices.front() == 0 &&
        out.r0_base_column_indices.back() + 1 ==
            out.cs.n_columns &&
        out.cs.preprocessed_row_group_roots.empty();
    out.note = out.valid
        ? "exact V13 tape and V14 replay resident before global R0"
        : "physical transcript deterministic component incomplete";
    if (!out.valid) {
        return Fail(
            why, "deterministic_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildDeterministicComponentV1(
    const tape::ProductV1& tape_product,
    const prefix::ProductV1& prefix_product,
    const occurrence::ManifestV1& manifest,
    DeterministicComponentV1& out,
    std::string* why)
{
    out = {};
    if (!tape_product.valid ||
        !SamePublicPrefix(
            prefix_product, manifest) ||
        !BuildDeterministicConstraintSystemV1(
            tape_product.schedule.shape,
            tape_product.binding,
            manifest,
            prefix_product.transcript_commitment,
            prefix_product.derived_binding,
            out.public_component,
            why)) {
        return Fail(
            why, "deterministic_product_input");
    }

    AirCS resident_cs;
    PlanV1 resident_plan;
    if (!BuildResidentParentV1(
            tape_product.schedule.shape,
            tape_product.binding,
            manifest,
            prefix_product.transcript_commitment,
            prefix_product.derived_binding,
            resident_cs, resident_plan, why) ||
        !FillResidentColumns(
            tape_product, prefix_product,
            resident_plan, resident_cs,
            out.columns, why) ||
        !abi_join::AppendEmbeddedBaseProductV1(
            resident_plan.abi_plan,
            resident_plan
                .complete_r0_base_column_indices,
            resident_cs, out.columns,
            out.public_component.abi_base,
            why)) {
        out = {};
        return false;
    }
    out.public_component.cs =
        std::move(resident_cs);
    out.public_component.plan =
        std::move(resident_plan);
    out.public_component.r0_base_column_indices =
        out.public_component.abi_base
            .complete_r0_base_column_indices;
    out.violations =
        abi_join::CountViolationsV1(
            out.public_component.cs,
            out.columns);
    out.actual_tape_witness_resident =
        tape_product.violations == 0;
    out.actual_v14_prefix_witness_resident =
        prefix_product.violations == 0;
    out.valid =
        out.public_component.valid &&
        out.violations == 0 &&
        out.actual_tape_witness_resident &&
        out.actual_v14_prefix_witness_resident &&
        out.columns.size() ==
            out.public_component.cs.n_columns;
    out.note = out.valid
        ? "exact physical transcript witness retained before global R0"
        : "physical transcript deterministic witness incomplete";
    if (!out.valid) {
        return Fail(
            why, "deterministic_product_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool AppendFinalConstraintSystemToParentV1(
    const PublicDeterministicComponentV1& component,
    const composer::ChildAttachmentV1& component_attachment,
    const uint256& domain_separated_public_seed,
    const uint256& global_r0_row_root,
    const std::vector<uint32_t>&
        global_r0_base_column_indices,
    AirCS& parent_cs,
    ComponentFinalizationV1& out,
    std::string* why)
{
    out = {};
    if (!RelocateEmbeddedBase(
            component, component_attachment,
            parent_cs, out.relocated_abi_plan,
            out.relocated_abi_base, why) ||
        !abi_join::
            AppendEmbeddedFinalConstraintSystemV1(
                out.relocated_abi_plan,
                out.relocated_abi_base,
                domain_separated_public_seed,
                global_r0_row_root,
                global_r0_base_column_indices,
                parent_cs,
                out.abi_finalization,
                why)) {
        out = {};
        return false;
    }
    out.plan_rebuilt_at_parent_offsets =
        out.relocated_abi_plan
                .tape_column_offset ==
            component_attachment.ParentColumn(
                component.plan.tape_offset) &&
        out.relocated_abi_plan
                .v14_column_offset ==
            component_attachment.ParentColumn(
                component.plan.v14_offset);
    out.exact_global_r0_consumed =
        out.abi_finalization.valid &&
        out.abi_finalization
                .global_r0_row_root ==
            global_r0_row_root;
    out.valid =
        out.plan_rebuilt_at_parent_offsets &&
        out.exact_global_r0_consumed;
    out.note = out.valid
        ? "physical transcript relation finalized from global parent R0"
        : "physical transcript verifier finalization incomplete";
    if (!out.valid) {
        return Fail(
            why, "component_finalize_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool AppendFinalRelationToParentV1(
    const DeterministicComponentV1& component,
    const composer::ChildAttachmentV1& component_attachment,
    const uint256& domain_separated_public_seed,
    const aq::AirQuotientTwoEpochBaseRowSession&
        global_r0_session,
    AirCS& parent_cs,
    std::vector<std::vector<Fp3>>&
        parent_columns,
    ComponentFinalizationV1& out,
    std::string* why)
{
    out = {};
    if (!component.valid ||
        !RelocateEmbeddedBase(
            component.public_component,
            component_attachment,
            parent_cs, out.relocated_abi_plan,
            out.relocated_abi_base, why) ||
        !abi_join::
            AppendEmbeddedFinalProductV1(
                out.relocated_abi_plan,
                out.relocated_abi_base,
                domain_separated_public_seed,
                global_r0_session,
                parent_cs, parent_columns,
                out.abi_finalization,
                why)) {
        out = {};
        return false;
    }
    out.plan_rebuilt_at_parent_offsets =
        out.relocated_abi_plan
                .tape_column_offset ==
            component_attachment.ParentColumn(
                component.public_component
                    .plan.tape_offset) &&
        out.relocated_abi_plan
                .v14_column_offset ==
            component_attachment.ParentColumn(
                component.public_component
                    .plan.v14_offset);
    out.exact_global_r0_consumed =
        out.abi_finalization.valid &&
        out.abi_finalization
                .global_r0_row_root ==
            global_r0_session
                .base_row_commitment;
    out.valid =
        out.plan_rebuilt_at_parent_offsets &&
        out.exact_global_r0_consumed;
    out.note = out.valid
        ? "physical transcript witness finalized from retained global R0"
        : "physical transcript product finalization incomplete";
    if (!out.valid) {
        return Fail(
            why, "component_product_finalize_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildProductV1(
    const tape::ProductV1& tape_product,
    const prefix::ProductV1& prefix_product,
    const occurrence::ManifestV1& manifest,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why)
{
    out = {};
    if (!tape_product.valid ||
        !SamePublicPrefix(
            prefix_product, manifest) ||
        public_seed.IsNull()) {
        return Fail(why, "product_input");
    }
    out.tape_binding = tape_product.binding;
    out.transcript_commitment =
        prefix_product.transcript_commitment;
    out.derived_binding =
        prefix_product.derived_binding;
    if (!BuildResidentParentV1(
            tape_product.schedule.shape,
            tape_product.binding,
            manifest,
            prefix_product.transcript_commitment,
            prefix_product.derived_binding,
            out.resident_parent_cs,
            out.plan, why)) {
        out = {};
        return false;
    }
    if (tape_product.cs.n_rows !=
            out.plan.tape_rows ||
        tape_product.cs.n_columns !=
            out.plan.tape_columns ||
        prefix_product.cs.n_rows !=
            out.plan.prefix_rows ||
        prefix_product.cs.n_columns !=
            out.plan.prefix_columns) {
        out = {};
        return Fail(why, "product_shape");
    }
    out.resident_parent_columns.assign(
        out.plan.resident_columns,
        std::vector<Fp3>(
            out.plan.parent_rows,
            Fp3::Zero()));
    if (!CopyShiftedColumns(
            tape_product.columns,
            out.plan.tape_offset,
            out.plan.tape_rows,
            out.plan.parent_rows,
            out.resident_parent_columns,
            why) ||
        !CopyShiftedColumns(
            prefix_product.columns,
            out.plan.prefix_offset,
            out.plan.prefix_rows,
            out.plan.parent_rows,
            out.resident_parent_columns,
            why) ||
        !FillWrapBroadcast(
            tape_product.columns,
            out.plan.tape_attachment,
            out.plan.parent_rows,
            out.resident_parent_columns,
            why) ||
        !FillWrapBroadcast(
            prefix_product.columns,
            out.plan.prefix_attachment,
            out.plan.parent_rows,
            out.resident_parent_columns,
            why)) {
        out = {};
        return false;
    }
    for (const auto& [column, values] :
         out.resident_parent_cs.preprocessed) {
        if (column >=
                out.resident_parent_columns.size() ||
            values.size() != out.plan.parent_rows) {
            out = {};
            return Fail(
                why, "product_preprocessed");
        }
        out.resident_parent_columns[column] =
            values;
    }
    if (!abi_join::BuildProductV1(
            out.plan.abi_plan,
            public_seed,
            out.resident_parent_cs,
            out.resident_parent_columns,
            out.plan.complete_r0_base_column_indices,
            out.abi_product, why)) {
        out = {};
        return false;
    }

    out.violations =
        out.abi_product.violations;
    out.actual_tape_verifier_resident =
        tape_product.valid &&
        tape_product.violations == 0;
    out.actual_v14_prefix_verifier_resident =
        prefix_product.valid &&
        prefix_product.violations == 0;
    out.actual_tape_cells_referenced =
        out.abi_product.actual_tape_cells_referenced;
    out.actual_v14_message_cells_referenced =
        out.abi_product
            .actual_v14_message_cells_referenced;
    out.no_host_copied_value_vector =
        out.abi_product.layout.original_columns ==
            out.plan.resident_columns;
    out.complete_parent_r0_committed =
        out.plan.complete_parent_r0 &&
        out.abi_product.challenges_after_complete_r0;
    out.dual_fp3_logup_constrained =
        out.abi_product
            .dual_fp3_rational_identity_constrained &&
        out.abi_product
            .terminal_cancellation_constrained;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.actual_tape_verifier_resident &&
        out.actual_v14_prefix_verifier_resident &&
        out.actual_tape_cells_referenced &&
        out.actual_v14_message_cells_referenced &&
        out.no_host_copied_value_vector &&
        out.complete_parent_r0_committed &&
        out.dual_fp3_logup_constrained &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "physical V13 tape to V14 transcript ABI equality "
          "closed in one parent; recursive receipt consumption pending"
        : "physical ABI parent relation incomplete";
    if (!out.valid) {
        return Fail(why, "product_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool ProveV1(
    const ProductV1& product,
    const uint256& public_seed,
    ProofV1& out,
    std::string* why)
{
    out = {};
    if (!product.valid ||
        product.recursively_consumed ||
        product.recursive_authority_ready ||
        !abi_join::ProveV1(
            product.abi_product,
            public_seed,
            out.abi_proof, why)) {
        return Fail(why, "prove");
    }
    out.plan_root = product.plan.plan_root;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.note =
        "physical parent ABI proof; normalized recursive "
        "receipt consumption remains separate";
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    const uint256& public_seed,
    const ProofV1& proof,
    std::string* why)
{
    if (proof.version !=
            kPhysicalParentJoinVersionV1 ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready ||
        public_seed.IsNull()) {
        return Fail(why, "verify_envelope");
    }
    AirCS resident_cs;
    PlanV1 plan;
    if (!BuildResidentParentV1(
            shape, tape_binding, manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            resident_cs, plan, why) ||
        proof.plan_root != plan.plan_root) {
        return Fail(why, "verify_plan");
    }
    std::string verify_why;
    if (!abi_join::VerifyV1(
            shape, tape_binding,
            manifest.canonical_program,
            manifest, plan.abi_plan,
            public_seed, resident_cs,
            plan.complete_r0_base_column_indices,
            proof.abi_proof, &verify_why)) {
        return Fail(
            why, "verify_abi:" + verify_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_v14_abi_physical_parent:verified";
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_v13_v14_abi_physical_parent_join
