// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_q96_child_verifier_bridge.h>

#include <algorithm>
#include <chrono>
#include <limits>

namespace matmul::v4::rc::
    stage3_multirow_v11_q96_child_verifier_bridge {
namespace {

using gf::Fp3;

bool IsGroupZeroRoot(
    const va::MultiRowV2ProgramRowV1& row)
{
    return
        row.kind ==
            va::MultiRowV2CheckKindV1::GroupRoot &&
        row.group == 0 &&
        row.active_lanes == kRootLimbsV1;
}

uint32_t FindGroupZeroRootRow(
    const va::MultiRowV2SplitRapProgramV1& program)
{
    for (uint32_t row = 0;
         row < program.active_rows;
         ++row) {
        if (IsGroupZeroRoot(
                program.rows[row])) {
            return row;
        }
    }
    return program.air_rows;
}

uint32_t MaxDegree(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    uint32_t out = 0;
    for (const auto& constraint : cs.constraints) {
        out = std::max(
            out, constraint.alg_degree);
    }
    return out;
}

bool AllActiveRowsAccepted(
    const va::MultiRowV2SplitRapVerifierWitnessV1&
        verifier)
{
    if (verifier.witness_columns.size() <=
            va::kMultiRowV2LocallyAccepted ||
        verifier.witness_columns[
            va::kMultiRowV2Active].size() !=
            verifier.constraint_system.n_rows ||
        verifier.witness_columns[
            va::kMultiRowV2LocallyAccepted].size() !=
            verifier.constraint_system.n_rows) {
        return false;
    }
    for (uint32_t row = 0;
         row < verifier.constraint_system.n_rows;
         ++row) {
        const auto& active =
            verifier.witness_columns[
                va::kMultiRowV2Active][row];
        const auto& accepted =
            verifier.witness_columns[
                va::kMultiRowV2LocallyAccepted][row];
        if (!gf::Eq(active, accepted)) {
            return false;
        }
    }
    return true;
}

void AddR0OutputAliases(
    ProductV1& out,
    const alg_hash::Digest& expected_r0)
{
    out.expected_r0_limb_base =
        out.parent_cs.n_columns;
    out.group0_selector_column =
        out.expected_r0_limb_base +
        kRootLimbsV1;
    out.parent_cs.n_columns =
        out.group0_selector_column + 1;
    out.parent_columns.resize(
        out.parent_cs.n_columns,
        std::vector<Fp3>(
            out.parent_cs.n_rows,
            Fp3::Zero()));

    for (uint32_t limb = 0;
         limb < kRootLimbsV1;
         ++limb) {
        const uint32_t column =
            out.expected_r0_limb_base + limb;
        out.parent_columns[column].assign(
            out.parent_cs.n_rows,
            Fp3::FromFp(
                gf::Canonical(
                    expected_r0[limb])));
        out.parent_cs.preprocessed.emplace_back(
            column, out.parent_columns[column]);

        aq::AirConstraint<Fp3> alias;
        alias.name =
            "stage3.v11_q96_child_verifier."
            "group0_r0_direct_alias";
        alias.kind = aq::AirKind::kEverywhere;
        alias.alg_degree = 2;
        alias.eval =
            [selector =
                 out.group0_selector_column,
             expected = column,
             claimed =
                 va::kMultiRowV2Claimed0 +
                 limb](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[selector],
                    gf::Sub(
                        row[claimed],
                        row[expected]));
            };
        out.parent_cs.constraints.push_back(
            std::move(alias));
    }
    out.parent_columns[
        out.group0_selector_column]
            [out.group0_program_row] =
        Fp3::One();
    out.parent_cs.preprocessed.emplace_back(
        out.group0_selector_column,
        out.parent_columns[
            out.group0_selector_column]);
}

std::vector<uint32_t> PreprocessedColumns(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    std::vector<uint32_t> out;
    out.reserve(cs.preprocessed.size());
    for (const auto& [column, values] :
         cs.preprocessed) {
        (void)values;
        out.push_back(column);
    }
    std::sort(out.begin(), out.end());
    out.erase(
        std::unique(out.begin(), out.end()),
        out.end());
    return out;
}

} // namespace

CapacityAuditV1 AuditCapacityV1(
    const q96::StatementV1& statement)
{
    CapacityAuditV1 out;
    const auto child =
        q96::BuildProductV1(statement);
    out.child_rows = child.trace_rows;
    out.child_columns = child.trace_columns;
    out.child_constraints = child.constraints;
    out.child_quotient_len = child.quotient_len;
    out.exact_q96_child_shape =
        child.valid &&
        child.trace_rows == q96::kTraceRowsV1 &&
        child.trace_columns == 778 &&
        child.constraints == 772 &&
        child.quotient_len == 32;
    if (!out.exact_q96_child_shape) {
        out.note =
            "stage3:v11_q96_child_verifier:"
            "audit:child_shape";
        return out;
    }
    const auto program =
        va::BuildCanonicalMultiRowV2SplitRapProgramV1(
            child.cs,
            child.preprocessed_columns);
    out.canonical_split_rap_program =
        program.valid;
    out.verifier_active_rows =
        program.active_rows;
    out.verifier_trace_rows =
        program.air_rows;
    const auto poseidon =
        stage3_poseidon_air::Measure(
            program.air_rows);
    out.verifier_max_constraint_degree =
        std::max<uint32_t>(
            2,
            poseidon.selector_gated_max_degree);
    out.verifier_quotient_len =
        poseidon.selector_gated_quotient_len;
    out.verifier_commitment_coefficients =
        FriNextPow2(
            std::max(
                out.verifier_trace_rows,
                out.verifier_quotient_len));
    const uint64_t verifier_lde_rows =
        uint64_t{
            out.verifier_commitment_coefficients} *
        kRCFriBlowup;
    out.verifier_lde_rows =
        verifier_lde_rows >
            std::numeric_limits<uint32_t>::max()
        ? 0
        : static_cast<uint32_t>(
            verifier_lde_rows);
    out.verifier_poseidon_rows =
        program.poseidon_permutation_rows;
    out.verifier_merkle_depth =
        program.merkle_depth;
    out.verifier_fold_count =
        program.fold_count;
    out.verifier_queries =
        program.query_count;
    out.quotient_cap_audit_complete =
        poseidon.selector_gated_max_degree == 3 &&
        out.verifier_quotient_len != 0 &&
        out.verifier_commitment_coefficients != 0;
    out.trace_cap_fits =
        program.air_rows != 0 &&
        program.air_rows <= kTraceRowsCapV1;
    out.lde_cap_fits =
        out.quotient_cap_audit_complete &&
        verifier_lde_rows != 0 &&
        verifier_lde_rows <= kLdeRowsCapV1;
    out.valid =
        out.exact_q96_child_shape &&
        out.canonical_split_rap_program &&
        out.quotient_cap_audit_complete &&
        out.trace_cap_fits &&
        out.lde_cap_fits;
    out.note = out.valid
        ? "stage3:v11_q96_child_verifier:"
          "audit:bounded"
        : "stage3:v11_q96_child_verifier:"
          "audit:cap_or_program";
    return out;
}

ProductV1 BuildProductV1(
    const q96::StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof&
        child_proof,
    const uint256& child_fs_seed)
{
    ProductV1 out;
    out.statement = statement;
    out.child = q96::BuildProductV1(statement);
    auto fail = [&out](
                    const std::string& detail) {
        out.valid_foundation = false;
        out.recursive_authority_ready = false;
        out.note =
            "stage3:v11_q96_child_verifier:" +
            detail;
        return out;
    };
    if (!out.child.valid ||
        child_fs_seed.IsNull()) {
        return fail("child_or_seed");
    }
    out.expected_child_r0_root =
        out.child.preprocessed_row_group_root;
    const auto expected_r0 =
        Fri3AlgDigestFromUint256(
            out.expected_child_r0_root);
    if (!expected_r0.has_value()) {
        return fail("child_r0_codec");
    }

    out.verifier_program =
        va::BuildCanonicalMultiRowV2SplitRapProgramV1(
            out.child.cs,
            out.child.preprocessed_columns);
    if (!out.verifier_program.valid ||
        out.verifier_program.air_rows >
            kTraceRowsCapV1 ||
        uint64_t{
            out.verifier_program.air_rows} *
                kRCFriBlowup >
            kLdeRowsCapV1) {
        return fail("verifier_program");
    }
    out.verifier =
        va::BuildMultiRowV2SplitRapVerifierWitnessV1(
            out.child.cs,
            out.verifier_program,
            child_proof,
            child_fs_seed);
    std::string why;
    if (!out.verifier.valid ||
        !va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
            out.child.cs,
            out.verifier_program,
            child_proof,
            child_fs_seed,
            out.verifier, &why)) {
        return fail(
            "child_verifier:" + why +
            out.verifier.note);
    }

    out.group0_program_row =
        FindGroupZeroRootRow(
            out.verifier_program);
    if (out.group0_program_row >=
        out.verifier_program.active_rows) {
        return fail("group0_row");
    }
    out.parent_cs =
        out.verifier.constraint_system;
    out.parent_columns =
        out.verifier.witness_columns;
    AddR0OutputAliases(out, *expected_r0);
    out.preprocessed_columns =
        PreprocessedColumns(out.parent_cs);
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.parent_cs,
            out.parent_columns,
            out.preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        return fail(
            "parent_r0:" + session.note);
    }
    out.preprocessed_row_group_root =
        session.base_row_commitment;
    out.parent_cs
        .preprocessed_row_group_roots
        .push_back({
            .version = 1,
            .role =
                aq::AirPreprocessedRowGroupRole::kR0,
            .ordered_columns =
                out.preprocessed_columns,
            .root =
                out.preprocessed_row_group_root,
        });

    out.trace_rows = out.parent_cs.n_rows;
    out.trace_columns =
        out.parent_cs.n_columns;
    out.constraints =
        static_cast<uint32_t>(
            out.parent_cs.constraints.size());
    out.max_constraint_degree =
        MaxDegree(out.parent_cs);
    out.quotient_len =
        out.parent_cs.QuotientLen();
    out.materialized_trace_cells =
        uint64_t{out.trace_rows} *
        out.trace_columns;
    out.violations =
        va::CountVerifierScalarViolations(
            out.parent_cs,
            out.parent_columns);

    out.exact_q96_statement_to_child_r0 =
        statement.expected_receipt_set_root ==
            out.child.computed_receipt_set_root &&
        out.child
            .ordered_receipt_set_root_recomputed &&
        child_proof.batch.groups.size() == 3 &&
        Fri3AlgDigestToUint256(
            child_proof.batch.groups[0]
                .row_commit.root) ==
            out.expected_child_r0_root;
    out.child_split_rap_proof_native_verified =
        out.verifier.host_verifier_accepted;
    out.canonical_verifier_program =
        out.verifier.canonical_program;
    out.all_merkle_fold_deep_quotient_checks_in_air =
        out.verifier
            .preprocessed_relation_satisfied &&
        out.verifier.all_merkle_paths_replayed &&
        out.verifier
            .all_deep_fold_identities_checked &&
        out.verifier
            .all_quotient_identities_checked;
    out.all_active_rows_locally_accepted =
        AllActiveRowsAccepted(out.verifier);
    out.group0_r0_output_directly_aliased_in_air =
        out.violations == 0;
    out.child_program_statement =
        out.verifier.program_statement;
    out.child_proof_statement =
        out.verifier.proof_statement;
    out.child_output_statement =
        out.verifier.output_statement;
    out.exact_program_proof_output_statements =
        !out.child_program_statement.IsNull() &&
        !out.child_proof_statement.IsNull() &&
        !out.child_output_statement.IsNull();
    out.ordered_parent_r0_root_pinned =
        !out.preprocessed_row_group_root.IsNull();

    out.cs_independent_of_child_witness =
        false;
    out.verifier_input_excludes_child_proof =
        false;
    out.child_proof_codec_owned_in_parent_air =
        false;
    out.poseidon_semantic_copy_bus_complete =
        false;
    out.fiat_shamir_replayed_in_parent_air =
        false;
    out.every_consumed_cell_constrained =
        out.child_proof_codec_owned_in_parent_air &&
        out.poseidon_semantic_copy_bus_complete &&
        out.fiat_shamir_replayed_in_parent_air;
    out.recursive_authority_ready = false;
    out.valid_foundation =
        out.exact_q96_statement_to_child_r0 &&
        out.child_split_rap_proof_native_verified &&
        out.canonical_verifier_program &&
        out.all_merkle_fold_deep_quotient_checks_in_air &&
        out.all_active_rows_locally_accepted &&
        out.group0_r0_output_directly_aliased_in_air &&
        out.exact_program_proof_output_statements &&
        out.ordered_parent_r0_root_pinned &&
        out.violations == 0 &&
        !out.cs_independent_of_child_witness &&
        !out.verifier_input_excludes_child_proof &&
        !out.every_consumed_cell_constrained &&
        !out.recursive_authority_ready;
    out.note = out.valid_foundation
        ? "stage3:v11_q96_child_verifier:"
          "actual_vcs_checks_and_r0_output_alias;"
          "proof_codec_poseidon_copy_fs_ownership_open"
        : "stage3:v11_q96_child_verifier:"
          "constraint_or_alias_failure";
    return out;
}

ProveResultV1 ProveV1(
    const q96::StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof&
        child_proof,
    const uint256& child_fs_seed,
    const uint256& parent_fs_seed)
{
    ProveResultV1 out;
    const auto product =
        BuildProductV1(
            statement, child_proof,
            child_fs_seed);
    out.parent_r0_root =
        product.preprocessed_row_group_root;
    if (!product.valid_foundation ||
        parent_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_q96_child_verifier:"
            "prove:" + product.note;
        return out;
    }
    const auto begin =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.parent_cs,
            product.parent_columns,
            product.preprocessed_columns,
            parent_fs_seed);
    out.prove_micros =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            begin).count();
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.note =
            "stage3:v11_q96_child_verifier:"
            "prove:" + proved.note;
        return out;
    }
    std::vector<unsigned char> wire;
    const size_t bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, wire);
    if (bytes == 0 || bytes != wire.size()) {
        out.note =
            "stage3:v11_q96_child_verifier:"
            "prove:serialize";
        return out;
    }
    out.proof = proved.proof;
    out.proof_wire_bytes = bytes;
    out.ok = true;
    out.note =
        "stage3:v11_q96_child_verifier:"
        "prove:actual_vcs_parent;"
        "authority_false";
    return out;
}

VerifyResultV1 VerifyV1(
    const q96::StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof&
        child_proof,
    const uint256& child_fs_seed,
    const aq::AirQuotientSplitRapRowsProof&
        parent_proof,
    const uint256& parent_fs_seed)
{
    VerifyResultV1 out;
    const auto product =
        BuildProductV1(
            statement, child_proof,
            child_fs_seed);
    if (!product.valid_foundation ||
        parent_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_q96_child_verifier:"
            "verify:" + product.note;
        return out;
    }
    const auto begin =
        std::chrono::steady_clock::now();
    std::string why;
    out.accepted =
        aq::AirQuotientVerifyRowsSplitRap(
            product.parent_cs,
            parent_proof,
            product.preprocessed_columns,
            parent_fs_seed, &why);
    out.verify_micros =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            begin).count();
    if (parent_proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            parent_proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.accepted = false;
        why = "parent_r0_root";
    }
    out.every_consumed_cell_constrained =
        product.every_consumed_cell_constrained;
    out.recursive_authority_ready = false;
    out.note = out.accepted
        ? "stage3:v11_q96_child_verifier:"
          "verify:actual_vcs_parent;"
          "ownership_residuals_open"
        : "stage3:v11_q96_child_verifier:"
          "verify:" + why;
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_q96_child_verifier_bridge
