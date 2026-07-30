// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_relation_receipt_consumer.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc::normalized_relation_receipt_consumer {
namespace {

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:normalized_relation_receipt_consumer:" + detail;
    }
    return false;
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value <= 2) return 2;
    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value + 1;
}

uint64_t CountViolations(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (!PowerOfTwo(cs.n_rows) ||
        cs.n_columns != columns.size()) {
        return UINT64_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return UINT64_MAX;
    }
    uint64_t violations = 0;
    std::vector<gf::Fp3> current(cs.n_columns);
    std::vector<gf::Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row = (row + 1) % cs.n_rows;
        for (uint32_t col = 0; col < cs.n_columns; ++col) {
            current[col] = columns[col][row];
            next[col] = columns[col][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            bool active = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                active = true;
                break;
            case aq::AirKind::kTransition:
                active = row + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                active = row == 0;
                break;
            case aq::AirKind::kLastRow:
                active = row + 1 == cs.n_rows;
                break;
            }
            if (active &&
                !gf::IsZero(constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool StrictColumns(
    const std::vector<uint32_t>& indices,
    uint32_t n_columns)
{
    if (indices.empty() || indices.size() >= n_columns) return false;
    for (size_t i = 0; i < indices.size(); ++i) {
        if (indices[i] >= n_columns ||
            (i != 0 && indices[i - 1] >= indices[i])) {
            return false;
        }
    }
    return true;
}

void PopulateReceiptPublicInputs(
    const nav3::RebuiltVerifierInputsV3& inputs,
    nav3::NormalizedAuthorityReceiptV3& receipt)
{
    receipt.outer_binding_kind =
        inputs.outer_binding_kind;
    receipt.public_statement =
        inputs.public_statement;
    receipt.outer_statement_root = inputs.outer_statement_root;
    receipt.program_registry_root = inputs.program_registry_root;
    receipt.topology_manifest_root = inputs.topology_manifest_root;
    receipt.aggregation_schedule_root = inputs.aggregation_schedule_root;
    receipt.occurrence_manifest_root = inputs.occurrence_manifest_root;
    receipt.verifier_program_root = inputs.verifier_program_root;
    receipt.abi_plan_root = inputs.abi_plan_root;
    receipt.selection_plan_root = inputs.selection_plan_root;
    receipt.derived_hash_plan_root = inputs.derived_hash_plan_root;
    receipt.fixed_trace_columns = inputs.fixed_trace_columns;
    receipt.fixed_trace_row_root = inputs.fixed_trace_row_root;
    receipt.roles = inputs.roles;
    receipt.parent_shape = inputs.parent_shape;
    receipt.parent_node_binding = inputs.parent_node_binding;
    receipt.parent_context_binding = inputs.parent_context_binding;
    receipt.parent_program_root = inputs.parent_program_root;
    receipt.parent_cs_commitment = inputs.parent_cs_commitment;
}

} // namespace

bool DeriveParentShapeV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    nav3::ParentShapeV3& out,
    std::string* why)
{
    out = {};
    if (!PowerOfTwo(cs.n_rows) ||
        cs.n_columns < 2 ||
        cs.n_columns >= kRCFri3AlgBatchMaxColumns ||
        cs.constraints.empty()) {
        return Fail(why, "parent_cs_shape");
    }
    uint32_t max_alg_degree = 0;
    for (const auto& constraint : cs.constraints) {
        if (constraint.alg_degree == 0 || !constraint.eval) {
            return Fail(why, "parent_constraint");
        }
        max_alg_degree =
            std::max(max_alg_degree, constraint.alg_degree);
    }
    const uint32_t quotient_rows = cs.QuotientLen();
    const uint32_t coefficient_rows =
        NextPowerOfTwo(std::max(cs.n_rows, quotient_rows));
    if (coefficient_rows <
            std::max(cs.n_rows, quotient_rows) ||
        coefficient_rows >
            std::numeric_limits<uint32_t>::max() /
                kRCFriBlowup) {
        return Fail(why, "parent_domain_overflow");
    }
    out = {
        .trace_rows = cs.n_rows,
        .semantic_columns = cs.n_columns,
        .proof_columns = cs.n_columns,
        .constraints =
            static_cast<uint32_t>(cs.constraints.size()),
        .max_constraint_degree = max_alg_degree,
        .quotient_rows = quotient_rows,
        .fri_n_coeffs = coefficient_rows,
        .lde_rows = coefficient_rows * kRCFriBlowup,
    };
    return true;
}

bool BuildReceiptV1(
    const CanonicalRelationParentProductV1& product,
    ReceiptBuildV1& out,
    const aq::AirProveOptions& options,
    std::string* why)
{
    out = {};
    if (product.version !=
            kNormalizedRelationReceiptConsumerVersionV1) {
        return Fail(why, "parent_product_version");
    }
    nav3::ParentShapeV3 derived_shape;
    if (!DeriveParentShapeV1(product.cs, derived_shape, why)) {
        return false;
    }
    if (product.verifier_inputs.parent_shape != derived_shape ||
        product.verifier_inputs.fixed_trace_columns !=
            product.r0_base_column_indices ||
        product.verifier_inputs.fixed_trace_row_root !=
            product.r0_session.base_row_commitment ||
        !StrictColumns(
            product.r0_base_column_indices,
            product.cs.n_columns) ||
        !product.r0_session.valid ||
        product.r0_session.trace_rows != product.cs.n_rows ||
        product.r0_session.base_column_indices !=
            product.r0_base_column_indices ||
        product.r0_session.base_row_commitment.IsNull()) {
        return Fail(why, "r0_or_shape_binding");
    }
    out.violations = CountViolations(product.cs, product.columns);
    if (out.violations != 0) {
        return Fail(why, "parent_witness_violation");
    }

    nav3::NormalizedAuthorityReceiptV3 receipt;
    PopulateReceiptPublicInputs(product.verifier_inputs, receipt);
    receipt.fixed_trace_manifest_root =
        nav3::ComputeFixedTraceManifestRootV3(
            receipt.parent_shape,
            receipt.fixed_trace_columns,
            receipt.fixed_trace_row_root);
    receipt.role_manifest_root =
        nav3::ComputeRoleManifestRootV3(receipt.roles);
    receipt.parent_statement_root =
        nav3::ComputeParentStatementRootV3(
            product.verifier_inputs);
    receipt.parent_fs_seed =
        nav3::DeriveParentFsSeedV3(
            receipt.parent_statement_root);
    if (receipt.fixed_trace_manifest_root.IsNull() ||
        receipt.role_manifest_root.IsNull() ||
        receipt.parent_statement_root.IsNull() ||
        receipt.parent_fs_seed.IsNull()) {
        return Fail(why, "derived_public_root");
    }

    const aq::AirQuotientFixedTracePinV3 fixed_trace{
        .version = 1,
        .ordered_columns =
            product.r0_base_column_indices,
        .row_root =
            product.r0_session.base_row_commitment,
    };
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            product.cs, product.columns, fixed_trace,
            receipt.parent_fs_seed, options,
            &product.r0_session);
    if (!proved.ok) {
        return Fail(why, "parent_prove:" + proved.note);
    }
    if (proved.proof.trace_rows != derived_shape.trace_rows ||
        proved.proof.batch.n_coeffs != derived_shape.fri_n_coeffs ||
        proved.proof.batch.column_len.size() !=
            static_cast<size_t>(derived_shape.proof_columns) + 1 ||
        proved.proof.batch.column_len.back() !=
            derived_shape.quotient_rows) {
        return Fail(why, "proved_shape");
    }
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, receipt.parent_proof_bytes) == 0) {
        return Fail(why, "parent_proof_codec");
    }
    receipt.parent_proof_root =
        nav3::ComputeParentProofRootV3(
            receipt.parent_proof_bytes);
    receipt.receipt_root =
        nav3::ComputeReceiptRootV3(receipt);

    std::string validate_why;
    if (!nav3::ValidateNormalizedAuthorityReceiptV3(
            receipt, &validate_why)) {
        return Fail(why, "receipt:" + validate_why);
    }
    std::vector<unsigned char> receipt_bytes;
    if (nav3::SerializeNormalizedAuthorityReceiptV3(
            receipt, receipt_bytes) == 0) {
        return Fail(why, "receipt_codec");
    }
    const auto decoded_receipt =
        nav3::DeserializeNormalizedAuthorityReceiptV3(
            receipt_bytes, &validate_why);
    if (!decoded_receipt.has_value() ||
        *decoded_receipt != receipt) {
        return Fail(
            why, "receipt_roundtrip:" + validate_why);
    }

    aq::AirQuotientSplitRapRowsProof decoded_parent_proof;
    aq::AirQuotientFixedTracePinV3 decoded_fixed_trace;
    if (!nav3::ValidateAndDecodeVerifierInputsV3(
            *decoded_receipt, product.verifier_inputs,
            decoded_parent_proof, decoded_fixed_trace,
            &validate_why)) {
        return Fail(
            why, "verifier_inputs:" + validate_why);
    }
    if (!aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            product.cs, decoded_parent_proof,
            decoded_fixed_trace,
            receipt.parent_fs_seed, &validate_why)) {
        return Fail(
            why, "parent_verify:" + validate_why);
    }

    out.receipt = std::move(receipt);
    out.decoded_parent_proof =
        std::move(decoded_parent_proof);
    out.fixed_trace = std::move(decoded_fixed_trace);
    out.receipt_bytes = std::move(receipt_bytes);
    out.exact_parent_shape_derived = true;
    out.actual_r0_session_consumed = true;
    out.actual_parent_cs_proved = true;
    out.canonical_parent_proof_codec = true;
    out.verifier_inputs_rebuilt_and_equal = true;
    out.unmodified_parent_verifier_accepted = true;
    out.normalized_recursive_child_verifier_consumed = false;
    out.recursive_authority_ready = false;
    out.valid = true;
    out.note =
        "stage3:normalized_relation_receipt_consumer:"
        "parent_proved_verified_and_canonically_encoded;"
        "recursive_child_verifier_fixed_point_open";
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyReceiptV1(
    const aq::AirConstraintSystem<gf::Fp3>& rebuilt_parent_cs,
    const nav3::RebuiltVerifierInputsV3& rebuilt_inputs,
    const std::vector<unsigned char>& receipt_bytes,
    aq::AirQuotientSplitRapRowsProof* decoded_parent_proof,
    std::string* why)
{
    if (decoded_parent_proof != nullptr) {
        *decoded_parent_proof = {};
    }
    nav3::ParentShapeV3 derived_shape;
    if (!DeriveParentShapeV1(
            rebuilt_parent_cs, derived_shape, why) ||
        rebuilt_inputs.parent_shape != derived_shape) {
        return false;
    }
    std::string verify_why;
    const auto receipt =
        nav3::DeserializeNormalizedAuthorityReceiptV3(
            receipt_bytes, &verify_why);
    if (!receipt.has_value()) {
        return Fail(why, "receipt:" + verify_why);
    }
    aq::AirQuotientSplitRapRowsProof proof;
    aq::AirQuotientFixedTracePinV3 fixed_trace;
    if (!nav3::ValidateAndDecodeVerifierInputsV3(
            *receipt, rebuilt_inputs, proof,
            fixed_trace, &verify_why)) {
        return Fail(
            why, "verifier_inputs:" + verify_why);
    }
    if (!aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            rebuilt_parent_cs, proof, fixed_trace,
            receipt->parent_fs_seed, &verify_why)) {
        return Fail(
            why, "parent_verify:" + verify_why);
    }
    if (decoded_parent_proof != nullptr) {
        *decoded_parent_proof = proof;
    }
    if (why != nullptr) {
        *why =
            "stage3:normalized_relation_receipt_consumer:"
            "verified";
    }
    return true;
}

} // namespace matmul::v4::rc::normalized_relation_receipt_consumer
