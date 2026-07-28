// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_two_child_parent.h>

#include <hash.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <numeric>
#include <utility>

namespace matmul::v4::rc::stage3_v13_two_child_parent {
namespace {

using AirCS = aq::AirConstraintSystem<gf::Fp3>;
using Fp3 = gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_two_child_parent:" +
            detail;
    }
    return false;
}

void Add(
    AirCS& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back(
        {name, kind, degree, std::move(eval)});
}

void HashDigest(
    HashWriter& hash,
    const alg_hash::Digest& digest)
{
    for (const auto lane : digest) {
        hash << lane;
    }
}

void HashChildPublicFields(
    HashWriter& hash,
    const complete::PublicStatementV1&
        statement,
    bool include_local_seed)
{
    hash << statement.version;
    hash << statement.tape_shape.trace_rows;
    hash << statement.tape_shape.trace_columns;
    hash << statement.tape_shape.quotient_len;
    hash << statement.tape_shape.n_coeffs;
    hash << static_cast<uint64_t>(
        statement.tape_shape
            .base_column_indices.size());
    for (const uint32_t column :
         statement.tape_shape
             .base_column_indices) {
        hash << column;
    }
    hash << statement.tape_binding.program_root;
    hash << statement.tape_binding.statement_root;
    hash << statement.tape_binding.public_fs_seed;
    hash << statement.tape_binding.proof_wire_root;
    HashDigest(
        hash, statement.tape_binding.tape_root);
    hash << statement.range.ordinal;
    hash << statement.range.first_query;
    hash << statement.range.query_count;
    HashDigest(
        hash, statement.child_program_root);
    if (include_local_seed) {
        hash << statement.public_seed;
    }
}

bool SameFp3Vector(
    const std::vector<Fp3>& left,
    const std::vector<Fp3>& right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (uint32_t index = 0;
         index < left.size(); ++index) {
        if (!gf::Eq(left[index], right[index])) {
            return false;
        }
    }
    return true;
}

bool SameConstraintSystemStructure(
    const AirCS& left,
    const AirCS& right)
{
    if (left.n_rows != right.n_rows ||
        left.n_columns != right.n_columns ||
        left.constraints.size() !=
            right.constraints.size() ||
        left.preprocessed.size() !=
            right.preprocessed.size() ||
        left.preprocessed_roots !=
            right.preprocessed_roots ||
        left.preprocessed_pin_ood !=
            right.preprocessed_pin_ood ||
        left.preprocessed_row_group_roots !=
            right.preprocessed_row_group_roots) {
        return false;
    }
    for (uint32_t index = 0;
         index < left.constraints.size();
         ++index) {
        if (left.constraints[index].name !=
                right.constraints[index].name ||
            left.constraints[index].kind !=
                right.constraints[index].kind ||
            left.constraints[index].alg_degree !=
                right.constraints[index].alg_degree) {
            return false;
        }
    }
    for (uint32_t index = 0;
         index < left.preprocessed.size();
         ++index) {
        if (left.preprocessed[index].first !=
                right.preprocessed[index].first ||
            !SameFp3Vector(
                left.preprocessed[index].second,
                right.preprocessed[index].second)) {
            return false;
        }
    }
    return true;
}

bool AppendChildConstraintSystem(
    AirCS& parent,
    const AirCS& child,
    uint32_t ordinal,
    composer::ChildAttachmentV1& out,
    std::string* why)
{
    out = {};
    if (child.n_rows < 2 ||
        (child.n_rows & (child.n_rows - 1)) != 0 ||
        child.n_columns == 0 ||
        !child.preprocessed_row_group_roots.empty() ||
        !parent.preprocessed_row_group_roots.empty()) {
        return Fail(why, "child_shape");
    }
    if (parent.n_columns == 0) {
        if (parent.n_rows != 0 ||
            !parent.constraints.empty() ||
            !parent.preprocessed.empty() ||
            !parent.preprocessed_roots.empty()) {
            return Fail(why, "parent_not_empty");
        }
        parent.n_rows = child.n_rows;
    } else if (parent.n_rows != child.n_rows) {
        return Fail(why, "child_row_mismatch");
    }
    if (child.n_columns >
        std::numeric_limits<uint32_t>::max() -
            parent.n_columns) {
        return Fail(why, "child_column_overflow");
    }

    out.child_ordinal = ordinal;
    out.column_base = parent.n_columns;
    out.semantic_child_columns = child.n_columns;
    out.column_count = child.n_columns;
    out.constraint_begin =
        static_cast<uint32_t>(
            parent.constraints.size());
    out.constraint_count =
        static_cast<uint32_t>(
            child.constraints.size());
    out.preprocessed_count =
        static_cast<uint32_t>(
            child.preprocessed.size());
    parent.n_columns += child.n_columns;
    parent.preprocessed_pin_ood =
        parent.preprocessed_pin_ood ||
        child.preprocessed_pin_ood;

    for (const auto& source : child.constraints) {
        if (!source.eval ||
            source.alg_degree == 0) {
            return Fail(why, "child_constraint");
        }
        aq::AirConstraint<Fp3> shifted;
        shifted.name = source.name;
        shifted.kind = source.kind;
        shifted.alg_degree = source.alg_degree;
        const auto eval = source.eval;
        const uint32_t base = out.column_base;
        const uint32_t width = child.n_columns;
        shifted.eval =
            [eval, base, width](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                if (current.size() <
                        base + width ||
                    next.size() <
                        base + width) {
                    return Fp3::One();
                }
                std::vector<Fp3> child_current(
                    current.begin() + base,
                    current.begin() +
                        base + width);
                std::vector<Fp3> child_next(
                    next.begin() + base,
                    next.begin() +
                        base + width);
                return eval(
                    child_current, child_next);
            };
        parent.constraints.push_back(
            std::move(shifted));
    }
    for (const auto& [column, values] :
         child.preprocessed) {
        if (column >= child.n_columns ||
            values.size() != child.n_rows) {
            return Fail(
                why, "child_preprocessed");
        }
        parent.preprocessed.emplace_back(
            out.column_base + column, values);
    }
    for (const auto& [column, root] :
         child.preprocessed_roots) {
        if (column >= child.n_columns ||
            root.IsNull()) {
            return Fail(
                why, "child_preprocessed_root");
        }
        parent.preprocessed_roots.emplace_back(
            out.column_base + column, root);
    }
    out.literal_column_mapping = true;
    out.constraints_shifted = true;
    out.valid = true;
    return true;
}

bool AppendArityTwoAcceptance(
    AirCS& cs,
    const std::array<
        composer::ChildAttachmentV1,
        kArityV1>& attachments,
    const std::array<uint32_t, kArityV1>&
        child_acceptance,
    uint32_t& parent_acceptance,
    std::string* why)
{
    for (uint32_t child = 0;
         child < kArityV1; ++child) {
        if (!attachments[child].valid ||
            child_acceptance[child] >=
                attachments[child]
                    .semantic_child_columns) {
            return Fail(
                why, "acceptance_child");
        }
    }
    if (cs.n_columns ==
        std::numeric_limits<uint32_t>::max()) {
        return Fail(
            why, "acceptance_column_overflow");
    }
    const uint32_t left =
        attachments[0].ParentColumn(
            child_acceptance[0]);
    const uint32_t right =
        attachments[1].ParentColumn(
            child_acceptance[1]);
    parent_acceptance = cs.n_columns++;
    Add(
        cs, "stage3.v13_two_child.accept_and",
        aq::AirKind::kFirstRow, 2,
        [left, right, parent_acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[parent_acceptance],
                gf::Mul(
                    current[left],
                    current[right]));
        });
    Add(
        cs, "stage3.v13_two_child.accept_one",
        aq::AirKind::kFirstRow, 1,
        [parent_acceptance](
            const auto& current,
            const auto&) {
            return gf::Sub(
                current[parent_acceptance],
                Fp3::One());
        });
    return true;
}

bool AppendArityTwoAcceptanceWitness(
    AirCS& cs,
    std::vector<std::vector<Fp3>>& columns,
    const std::array<
        composer::ChildAttachmentV1,
        kArityV1>& attachments,
    const std::array<uint32_t, kArityV1>&
        child_acceptance,
    uint32_t& parent_acceptance,
    std::string* why)
{
    const uint32_t before = cs.n_columns;
    if (columns.size() != before ||
        !AppendArityTwoAcceptance(
            cs, attachments,
            child_acceptance,
            parent_acceptance, why) ||
        parent_acceptance != before) {
        return false;
    }
    columns.emplace_back(
        cs.n_rows, Fp3::Zero());
    const uint32_t left =
        attachments[0].ParentColumn(
            child_acceptance[0]);
    const uint32_t right =
        attachments[1].ParentColumn(
            child_acceptance[1]);
    columns[parent_acceptance][0] =
        gf::Mul(
            columns[left][0],
            columns[right][0]);
    return true;
}

bool ValidatePublicStatement(
    const PublicStatementV1& statement,
    std::array<uint256, kArityV1>&
        child_roots,
    std::array<uint256, kArityV1>&
        child_identity_roots,
    uint256& statement_root,
    std::array<uint256, kArityV1>&
        child_seeds,
    std::string* why)
{
    if (statement.version != kVersionV1 ||
        statement.parent_public_seed.IsNull()) {
        return Fail(why, "public_statement");
    }
    for (uint32_t child = 0;
         child < kArityV1; ++child) {
        const auto& child_statement =
            statement.children[child];
        if (child_statement.version !=
                complete::kVersionV1 ||
            child_statement.range.query_count ==
                0 ||
            child_statement.public_seed.IsNull() ||
            child_statement.child_program_root !=
                constraint_bytecode::
                    CommitProgramTableAlgHash(
                        child_statement
                            .child_program)) {
            return Fail(
                why, "child_public_statement");
        }
        child_roots[child] =
            CommitChildStatementV1(
                child_statement);
        child_identity_roots[child] =
            CommitChildIdentityV1(
                child_statement);
        if (child_roots[child].IsNull()) {
            return Fail(
                why, "child_statement_root");
        }
    }
    if (child_identity_roots[0].IsNull() ||
        child_identity_roots[1].IsNull() ||
        child_identity_roots[0] ==
            child_identity_roots[1]) {
        return Fail(
            why, "duplicate_child_statement");
    }
    statement_root =
        CommitStatementV1(statement);
    if (statement_root.IsNull()) {
        return Fail(
            why, "parent_statement_root");
    }
    for (uint32_t child = 0;
         child < kArityV1; ++child) {
        child_seeds[child] =
            DeriveChildFinalizationSeedV1(
                statement, child);
        if (child_seeds[child].IsNull()) {
            return Fail(
                why, "child_finalization_seed");
        }
    }
    if (child_seeds[0] == child_seeds[1]) {
        return Fail(
            why, "child_seed_collision");
    }
    return true;
}

} // namespace

uint256 CommitChildStatementV1(
    const complete::PublicStatementV1& statement)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V13_COMPLETE_CHILD_PUBLIC_STATEMENT_V1";
    HashChildPublicFields(
        hash, statement, true);
    return hash.GetHash();
}

uint256 CommitChildIdentityV1(
    const complete::PublicStatementV1& statement)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V13_COMPLETE_CHILD_IDENTITY_V1";
    HashChildPublicFields(
        hash, statement, false);
    return hash.GetHash();
}

uint256 CommitStatementV1(
    const PublicStatementV1& statement)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V13_TWO_CHILD_PUBLIC_STATEMENT_V1";
    hash << statement.version;
    hash << statement.parent_public_seed;
    for (const auto& child :
         statement.children) {
        hash << CommitChildStatementV1(child);
    }
    return hash.GetHash();
}

uint256 DeriveChildFinalizationSeedV1(
    const PublicStatementV1& statement,
    uint32_t child_ordinal)
{
    if (child_ordinal >= kArityV1) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_V13_TWO_CHILD_FINALIZATION_SEED_V1";
    hash << kVersionV1;
    hash << statement.parent_public_seed;
    hash << child_ordinal;
    hash << CommitChildStatementV1(
        statement.children[0]);
    hash << CommitChildStatementV1(
        statement.children[1]);
    return hash.GetHash();
}

bool BuildDeterministicConstraintSystemV1(
    const PublicStatementV1& statement,
    DeterministicParentV1& out,
    std::string* why)
{
    out = {};
    out.statement = statement;
    if (!ValidatePublicStatement(
            statement,
            out.child_statement_roots,
            out.child_identity_roots,
            out.statement_root,
            out.child_finalization_seeds,
            why)) {
        return false;
    }
    for (uint32_t child = 0;
         child < kArityV1; ++child) {
        if (!complete::
                BuildDeterministicConstraintSystemV1(
                    statement.children[child],
                    out.children[child],
                    why) ||
            !AppendChildConstraintSystem(
                out.cs,
                out.children[child].cs,
                child,
                out.child_attachments[child],
                why)) {
            return false;
        }
    }
    const std::array<uint32_t, kArityV1>
        acceptance{
            out.children[0]
                .terminal_acceptance_column,
            out.children[1]
                .terminal_acceptance_column};
    if (!AppendArityTwoAcceptance(
            out.cs, out.child_attachments,
            acceptance,
            out.parent_acceptance_column,
            why)) {
        return false;
    }
    out.ordered_siblings_bound =
        !out.statement_root.IsNull() &&
        out.child_finalization_seeds[0] !=
            out.child_finalization_seeds[1];
    out.duplicate_sibling_rejected =
        out.child_identity_roots[0] !=
            out.child_identity_roots[1];
    out.both_children_pre_r0 =
        out.parent_acceptance_column + 1 ==
            out.cs.n_columns;
    out.arity_two_acceptance_constrained =
        out.cs.constraints.size() >= 2 &&
        out.parent_acceptance_column <
            out.cs.n_columns;
    out.proof_values_excluded =
        out.children[0]
            .proof_values_excluded &&
        out.children[1]
            .proof_values_excluded;
    out.valid =
        out.ordered_siblings_bound &&
        out.duplicate_sibling_rejected &&
        out.both_children_pre_r0 &&
        out.arity_two_acceptance_constrained &&
        out.proof_values_excluded &&
        out.cs.n_columns <
            kRCFri3AlgBatchMaxColumns &&
        out.cs
            .preprocessed_row_group_roots
            .empty();
    out.note = out.valid
        ? "stage3:v13_two_child_parent:"
          "deterministic_parent_rebuilt"
        : "stage3:v13_two_child_parent:"
          "deterministic_parent_invalid";
    if (!out.valid) {
        return Fail(
            why, "deterministic_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildConstraintSystemV1(
    const PublicStatementV1& statement,
    const uint256& r0_row_root,
    VerifierConstraintSystemV1& out,
    std::string* why)
{
    out = {};
    if (r0_row_root.IsNull() ||
        !BuildDeterministicConstraintSystemV1(
            statement,
            out.deterministic, why)) {
        return false;
    }
    out.cs = std::move(
        out.deterministic.cs);
    out.r0_base_column_indices.resize(
        out.cs.n_columns);
    std::iota(
        out.r0_base_column_indices.begin(),
        out.r0_base_column_indices.end(),
        0U);
    for (uint32_t child = 0;
         child < kArityV1; ++child) {
        if (!complete::
                AppendFinalConstraintSystemToParentV1(
                    out.deterministic
                        .children[child],
                    out.deterministic
                        .child_attachments[child],
                    out.deterministic
                        .child_finalization_seeds[child],
                    r0_row_root,
                    out.r0_base_column_indices,
                    out.cs,
                    out.child_finalizations[child],
                    why)) {
            return false;
        }
    }
    out.r0_row_root = r0_row_root;
    out.single_shared_r0 =
        out.cs
            .preprocessed_row_group_roots
            .size() == 1 &&
        out.cs.preprocessed_row_group_roots[0]
            .ordered_columns ==
                out.r0_base_column_indices &&
        out.cs.preprocessed_row_group_roots[0]
            .root == r0_row_root;
    out.both_children_finalized =
        out.child_finalizations[0].valid &&
        out.child_finalizations[1].valid &&
        out.child_finalizations[0]
                .deep.r0_row_root ==
            r0_row_root &&
        out.child_finalizations[1]
                .deep.r0_row_root ==
            r0_row_root;
    out.proof_values_excluded =
        out.deterministic
            .proof_values_excluded;
    out.valid =
        out.single_shared_r0 &&
        out.both_children_finalized &&
        out.proof_values_excluded &&
        out.cs.n_columns <
            kRCFri3AlgBatchMaxColumns;
    out.note = out.valid
        ? "stage3:v13_two_child_parent:"
          "verifier_constraint_system_rebuilt"
        : "stage3:v13_two_child_parent:"
          "verifier_constraint_system_invalid";
    if (!out.valid) {
        return Fail(
            why, "verifier_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyProofV1(
    const PublicStatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof&
        proof,
    std::string* why)
{
    if (proof.batch.groups.empty()) {
        return Fail(
            why, "proof_missing_r0_group");
    }
    const uint256 r0_row_root =
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root);
    VerifierConstraintSystemV1 rebuilt;
    if (!BuildConstraintSystemV1(
            statement, r0_row_root,
            rebuilt, why)) {
        return false;
    }
    std::string verify_why;
    if (!aq::
            AirQuotientVerifyRowsSplitRapSafeV2(
                rebuilt.cs, proof,
                rebuilt
                    .r0_base_column_indices,
                statement.parent_public_seed,
                &verify_why)) {
        return Fail(
            why, "proof:" + verify_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_two_child_parent:"
            "public_rebuilt_cs_verified";
    }
    return true;
}

bool BuildProductV1(
    const PublicStatementV1& statement,
    const std::array<
        complete::DeterministicComponentV1,
        kArityV1>& children,
    ProductV1& out,
    std::string* why)
{
    out = {};
    out.statement = statement;
    DeterministicParentV1 public_parent;
    if (!BuildDeterministicConstraintSystemV1(
            statement, public_parent, why)) {
        return false;
    }
    for (uint32_t child = 0;
         child < kArityV1; ++child) {
        if (!children[child].valid ||
            !SameConstraintSystemStructure(
                children[child].cs,
                public_parent
                    .children[child].cs) ||
            !composer::AppendChildV1(
                out.cs, out.columns,
                children[child].cs,
                children[child].columns,
                child,
                out.child_attachments[child],
                why)) {
            return Fail(
                why, "prover_child");
        }
    }
    const std::array<uint32_t, kArityV1>
        acceptance{
            children[0]
                .terminal_acceptance_column,
            children[1]
                .terminal_acceptance_column};
    if (!AppendArityTwoAcceptanceWitness(
            out.cs, out.columns,
            out.child_attachments,
            acceptance,
            out.parent_acceptance_column,
            why)) {
        return false;
    }
    out.r0_base_column_indices.resize(
        out.cs.n_columns);
    std::iota(
        out.r0_base_column_indices.begin(),
        out.r0_base_column_indices.end(),
        0U);
    out.r0_session =
        aq::
            AirQuotientBuildTwoEpochBaseRowSession(
                out.cs, out.columns,
                out.r0_base_column_indices);
    if (!out.r0_session.valid ||
        out.r0_session
            .base_row_commitment.IsNull()) {
        return Fail(
            why, "prover_r0_session");
    }
    for (uint32_t child = 0;
         child < kArityV1; ++child) {
        if (!complete::
                AppendFinalRelationToParentV1(
                    children[child],
                    out.child_attachments[child],
                    public_parent
                        .child_finalization_seeds[child],
                    out.r0_session,
                    out.cs, out.columns,
                    out.child_finalizations[child],
                    why)) {
            return false;
        }
    }

    VerifierConstraintSystemV1 verifier;
    out.verifier_constraint_system_rebuilt =
        BuildConstraintSystemV1(
            statement,
            out.r0_session
                .base_row_commitment,
            verifier, why) &&
        verifier.r0_base_column_indices ==
            out.r0_base_column_indices &&
        SameConstraintSystemStructure(
            out.cs, verifier.cs);
    out.violations =
        complete::deep::CountViolationsV1(
            out.cs, out.columns);
    out.single_shared_r0 =
        out.r0_session.valid &&
        out.child_finalizations[0]
                .deep.r0_row_root ==
            out.r0_session
                .base_row_commitment &&
        out.child_finalizations[1]
                .deep.r0_row_root ==
            out.r0_session
                .base_row_commitment;
    out.arity_two_acceptance_constrained =
        out.parent_acceptance_column <
            out.r0_base_column_indices.size() &&
        gf::Eq(
            out.columns[
                out.parent_acceptance_column][0],
            Fp3::One());
    out.proof_ready =
        out.verifier_constraint_system_rebuilt &&
        out.single_shared_r0 &&
        out.arity_two_acceptance_constrained &&
        out.violations == 0;
    out.recursively_consumed = false;
    out.authority_ready = false;
    out.valid = out.proof_ready;
    out.note = out.valid
        ? "stage3:v13_two_child_parent:"
          "prover_parent_ready"
        : "stage3:v13_two_child_parent:"
          "prover_parent_invalid";
    if (!out.valid) {
        return Fail(
            why, "prover_invariant");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

} // namespace matmul::v4::rc::stage3_v13_two_child_parent
