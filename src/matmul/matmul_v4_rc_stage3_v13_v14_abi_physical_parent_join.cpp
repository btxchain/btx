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
