// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_universal_two_child_parent.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <string_view>

namespace matmul::v4::rc::universal_two_child_parent {
namespace {

bool Fail(std::string* why, const char* suffix)
{
    if (why != nullptr) {
        *why =
            std::string{
                "stage3:universal_two_child_parent:"} +
            suffix;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value != 0 &&
        (value & (value - 1U)) == 0;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value == 0) return 0;
    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value == std::numeric_limits<uint32_t>::max()
        ? 0
        : value + 1;
}

bool ValidateShape(
    const PublicShapeV1& shape,
    std::string* why)
{
    const uint32_t expected_coefficients =
        NextPowerOfTwo(std::max(
            shape.child_rows,
            shape.child_quotient_len));
    const uint64_t expected_lde =
        uint64_t{expected_coefficients} *
        kRCFriBlowup;
    if (shape.version !=
            kUniversalTwoChildParentVersionV1 ||
        !IsPowerOfTwo(shape.child_rows) ||
        shape.child_columns == 0 ||
        shape.child_quotient_len == 0 ||
        !IsPowerOfTwo(shape.child_coefficients) ||
        !IsPowerOfTwo(shape.child_lde) ||
        expected_coefficients == 0 ||
        shape.child_coefficients !=
            expected_coefficients ||
        expected_lde >
            std::numeric_limits<uint32_t>::max() ||
        shape.child_lde != expected_lde ||
        shape.merkle_depth == 0 ||
        shape.folds == 0 ||
        shape.queries != kRCFri3AlgNumQueries ||
        shape.independent_fri_batching !=
            Fri3AlgQ192IndependentBatching() ||
        shape.column_lengths.size() !=
            uint64_t{shape.child_columns} + 1U) {
        return Fail(why, "shape");
    }
    uint32_t lde = shape.child_lde;
    uint32_t depth = 0;
    while (lde > 1) {
        lde >>= 1;
        ++depth;
    }
    uint32_t coefficients = shape.child_coefficients;
    uint32_t folds = 0;
    while (coefficients > 1) {
        coefficients >>= 1;
        ++folds;
    }
    if (depth != shape.merkle_depth ||
        folds != shape.folds) {
        return Fail(why, "shape_derived");
    }
    for (uint32_t column = 0;
         column < shape.child_columns; ++column) {
        if (shape.column_lengths[column] !=
                shape.child_rows) {
            return Fail(why, "trace_column_length");
        }
    }
    if (shape.column_lengths.back() !=
            shape.child_quotient_len) {
        return Fail(why, "quotient_column_length");
    }
    return true;
}

ar::ChildPublicInputs ShapeOnlyChild(
    const PublicShapeV1& shape,
    const aq::AirConstraintSystem<gf::Fp3>& child_cs)
{
    ar::ChildPublicInputs out;
    out.child_n_rows = shape.child_rows;
    out.child_w = shape.child_columns;
    out.child_quotient_len =
        shape.child_quotient_len;
    out.child_n_coeffs =
        shape.child_coefficients;
    out.child_n_lde = shape.child_lde;
    out.merkle_depth = shape.merkle_depth;
    out.n_folds = shape.folds;
    out.fold_roots.resize(shape.folds);
    out.fold_challenges.assign(
        shape.folds, gf::Fp3::Zero());
    out.column_len = shape.column_lengths;
    out.evals_z1.assign(
        uint64_t{shape.child_columns} + 1U,
        gf::Fp3::Zero());
    out.evals_z2.assign(
        uint64_t{shape.child_columns} + 1U,
        gf::Fp3::Zero());
    out.query_index.assign(shape.queries, 0);
    out.independent_fri_batching =
        shape.independent_fri_batching;
    if (out.independent_fri_batching) {
        out.fri_batch_coefficients.assign(
            uint64_t{shape.child_columns} + 1U,
            gf::Fp3::Zero());
    }
    out.child_constraints = child_cs.constraints;
    out.ok = true;
    out.note =
        "stage3:universal_two_child_parent:"
        "shape_only_child";
    return out;
}

bool SameConstraintDescriptors(
    const aq::AirConstraintSystem<gf::Fp3>& a,
    const aq::AirConstraintSystem<gf::Fp3>& b)
{
    if (a.n_rows != b.n_rows ||
        a.n_columns != b.n_columns ||
        a.constraints.size() != b.constraints.size() ||
        a.preprocessed_pin_ood !=
            b.preprocessed_pin_ood ||
        CommitConstraintScheduleV1(a) !=
            CommitConstraintScheduleV1(b)) {
        return false;
    }
    for (uint32_t i = 0;
         i < a.constraints.size(); ++i) {
        if (std::string_view{a.constraints[i].name} !=
                std::string_view{b.constraints[i].name} ||
            a.constraints[i].kind !=
                b.constraints[i].kind ||
            a.constraints[i].alg_degree !=
                b.constraints[i].alg_degree) {
            return false;
        }
    }
    return true;
}

} // namespace

uint256 CommitPublicShapeV1(
    const PublicShapeV1& shape)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_UNIVERSAL_TWO_CHILD_SHAPE_V1";
    hash << shape.version;
    hash << kUniversalTwoChildParentArityV1;
    hash << shape.child_rows;
    hash << shape.child_columns;
    hash << shape.child_quotient_len;
    hash << shape.child_coefficients;
    hash << shape.child_lde;
    hash << shape.merkle_depth;
    hash << shape.folds;
    hash << shape.queries;
    hash << shape.independent_fri_batching;
    hash << static_cast<uint64_t>(
        shape.column_lengths.size());
    for (uint32_t length : shape.column_lengths) {
        hash << length;
    }
    return hash.GetHash();
}

uint256 CommitConstraintScheduleV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_UNIVERSAL_TWO_CHILD_CS_SCHEDULE_V1";
    hash << kUniversalTwoChildParentVersionV1;
    hash << cs.n_rows;
    hash << cs.n_columns;
    hash << cs.preprocessed_pin_ood;
    hash << static_cast<uint64_t>(
        cs.preprocessed.size());
    for (const auto& column : cs.preprocessed) {
        hash << column.first;
        hash << static_cast<uint64_t>(
            column.second.size());
        for (const auto& value : column.second) {
            hash << value.c0 << value.c1 << value.c2;
        }
    }
    hash << static_cast<uint64_t>(
        cs.preprocessed_roots.size());
    for (const auto& root : cs.preprocessed_roots) {
        hash << root.first << root.second;
    }
    hash << static_cast<uint64_t>(
        cs.preprocessed_row_group_roots.size());
    for (const auto& group :
         cs.preprocessed_row_group_roots) {
        hash << group.version;
        hash << static_cast<uint8_t>(group.role);
        hash << static_cast<uint64_t>(
            group.ordered_columns.size());
        for (uint32_t column :
             group.ordered_columns) {
            hash << column;
        }
        hash << group.root;
    }
    hash << static_cast<uint64_t>(
        cs.constraints.size());
    for (const auto& constraint : cs.constraints) {
        hash << std::string{constraint.name};
        hash << static_cast<uint8_t>(
            constraint.kind);
        hash << constraint.alg_degree;
    }
    return hash.GetHash();
}

bool BuildVerifierConstraintSystemV1(
    const PublicShapeV1& shape,
    const FrozenRegistryV1& registry,
    VerifierConstraintSystemV1& out,
    std::string* why)
{
    out = {};
    if (!ValidateShape(shape, why) ||
        registry.version !=
            kUniversalTwoChildParentVersionV1 ||
        !cb::ValidateProgramTable(
            registry.child_relation_program, why) ||
        registry.program_root.IsNull() ||
        cb::CommitProgramTable(
            registry.child_relation_program) !=
            registry.program_root ||
        registry.child_relation_program.current_width !=
            shape.child_columns ||
        registry.child_relation_program.next_width !=
            shape.child_columns) {
        return Fail(why, "registry");
    }
    aq::AirConstraintSystem<gf::Fp3> child_cs;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            registry.child_relation_program,
            shape.child_rows, child_cs, why) ||
        child_cs.n_columns != shape.child_columns ||
        child_cs.QuotientLen() !=
            shape.child_quotient_len) {
        return Fail(why, "registry_child_cs");
    }
    const ar::ChildPublicInputs child =
        ShapeOnlyChild(shape, child_cs);
    std::vector<ar::ChildPublicInputs> children(
        kUniversalTwoChildParentArityV1, child);
    const ar::VerifierAirFamilies families{};
    aq::AirConstraintSystem<gf::Fp3> parent =
        ar::BuildVerifierAIRPinned(
            kUniversalTwoChildParentArityV1,
            children, families);
    if (parent.n_rows == 0 ||
        parent.n_columns == 0 ||
        parent.constraints.empty()) {
        return Fail(why, "parent_cs");
    }

    out.version =
        kUniversalTwoChildParentVersionV1;
    out.arity =
        kUniversalTwoChildParentArityV1;
    out.shape = shape;
    out.registry_program_root =
        registry.program_root;
    out.shape_commitment =
        CommitPublicShapeV1(shape);
    out.callback_schedule_commitment =
        CommitConstraintScheduleV1(parent);
    out.child_cs = std::move(child_cs);
    out.parent_cs = std::move(parent);
    out.registry_program_reconstructed = true;
    out.shape_only_parent_reconstructed = true;
    out.proof_tape_independent = true;
    out.proof_specific_constants_lifted_to_fixed_trace =
        false;
    out.full_child_acceptance_constrained = false;
    out.authority = false;
    out.note =
        "stage3:universal_two_child_parent:"
        "verifier_cs_rebuilt_from_shape_and_registry;"
        "proof_constants_fixed_trace_lift_pending";
    if (out.shape_commitment.IsNull() ||
        out.callback_schedule_commitment.IsNull()) {
        return Fail(why, "commitment");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool VerifyProofTapeNoninterferenceV1(
    const PublicShapeV1& shape,
    const FrozenRegistryV1& registry,
    const std::vector<unsigned char>& first_tape,
    const std::vector<unsigned char>& second_tape,
    std::string* why)
{
    if (first_tape.empty() ||
        second_tape.empty() ||
        first_tape == second_tape) {
        return Fail(why, "distinct_tapes");
    }
    VerifierConstraintSystemV1 first;
    VerifierConstraintSystemV1 second;
    if (!BuildVerifierConstraintSystemV1(
            shape, registry, first, why) ||
        !BuildVerifierConstraintSystemV1(
            shape, registry, second, why)) {
        return false;
    }
    if (first.shape_commitment !=
            second.shape_commitment ||
        first.registry_program_root !=
            second.registry_program_root ||
        first.callback_schedule_commitment !=
            second.callback_schedule_commitment ||
        !SameConstraintDescriptors(
            first.parent_cs, second.parent_cs)) {
        return Fail(why, "tape_influenced_cs");
    }
    if (why != nullptr) {
        *why =
            "stage3:universal_two_child_parent:"
            "distinct_proof_tapes_same_verifier_cs";
    }
    return true;
}

} // namespace matmul::v4::rc::universal_two_child_parent
