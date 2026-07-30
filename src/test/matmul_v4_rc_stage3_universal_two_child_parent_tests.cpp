// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_universal_two_child_parent.h>

#include <matmul/matmul_v4_rc_air_quotient_alg.h>

#include <boost/test/unit_test.hpp>

#include <utility>

namespace {

namespace rc =
    matmul::v4::rc;
namespace u2 =
    matmul::v4::rc::universal_two_child_parent;
namespace ar =
    matmul::v4::rc::air_recurse;
namespace cb =
    matmul::v4::rc::constraint_bytecode;
namespace gf =
    matmul::v4::rc::gkr_field;
namespace aq =
    matmul::v4::rc::air_quotient;

cb::ProgramTable ChildProgram()
{
    cb::Program program;
    program.role =
        rc::RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal = 0;
    program.kind = aq::AirKind::kTransition;
    program.declared_degree = 1;
    program.current_width = 2;
    program.next_width = 2;
    program.instructions = {
        {cb::Opcode::Next, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Sub, 0, 1, gf::Fp3::Zero()},
    };
    cb::ProgramTable table;
    table.role =
        rc::RCStage3RelationRole::CompositionLink;
    table.current_width = 2;
    table.next_width = 2;
    table.programs.push_back(std::move(program));
    cb::Program second;
    second.role =
        rc::RCStage3RelationRole::CompositionLink;
    second.constraint_ordinal = 1;
    second.kind = aq::AirKind::kEverywhere;
    second.declared_degree = 1;
    second.current_width = 2;
    second.next_width = 2;
    second.instructions = {
        {cb::Opcode::Current, 1, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 1, 0, gf::Fp3::Zero()},
        {cb::Opcode::Sub, 0, 1, gf::Fp3::Zero()},
    };
    table.programs.push_back(std::move(second));
    return table;
}

cb::ProgramTable SecondChildProgram()
{
    cb::Program program;
    program.role =
        rc::RCStage3RelationRole::CompositionLink;
    program.constraint_ordinal = 0;
    program.kind = aq::AirKind::kTransition;
    program.declared_degree = 1;
    program.current_width = 2;
    program.next_width = 2;
    program.instructions = {
        {cb::Opcode::Next, 1, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 1, 0, gf::Fp3::Zero()},
        {cb::Opcode::Sub, 0, 1, gf::Fp3::Zero()},
    };
    cb::ProgramTable table;
    table.role =
        rc::RCStage3RelationRole::CompositionLink;
    table.current_width = 2;
    table.next_width = 2;
    table.programs.push_back(std::move(program));
    cb::Program second;
    second.role =
        rc::RCStage3RelationRole::CompositionLink;
    second.constraint_ordinal = 1;
    second.kind = aq::AirKind::kEverywhere;
    second.declared_degree = 1;
    second.current_width = 2;
    second.next_width = 2;
    second.instructions = {
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Sub, 0, 1, gf::Fp3::Zero()},
    };
    table.programs.push_back(std::move(second));
    return table;
}

u2::PublicShapeV1 Shape()
{
    u2::PublicShapeV1 out;
    out.child_rows = 2;
    out.child_columns = 2;
    out.child_quotient_len = 1;
    out.child_coefficients = 2;
    out.child_lde =
        out.child_coefficients * rc::kRCFriBlowup;
    out.merkle_depth = 5;
    out.folds = 1;
    out.queries = rc::kRCFri3AlgNumQueries;
    out.independent_fri_batching =
        rc::Fri3AlgQ192IndependentBatching();
    out.column_lengths = {2, 2, 1};
    return out;
}

u2::FrozenRegistryV1 Registry()
{
    u2::FrozenRegistryV1 out;
    out.child_relation_program = ChildProgram();
    out.program_root =
        cb::CommitProgramTable(
            out.child_relation_program);
    return out;
}

u2::FrozenRegistryV1 SecondRegistry()
{
    u2::FrozenRegistryV1 out;
    out.child_relation_program =
        SecondChildProgram();
    out.program_root =
        cb::CommitProgramTable(
            out.child_relation_program);
    return out;
}

uint256 Seed(unsigned char first)
{
    uint256 out;
    for (uint32_t index = 0; index < 32; ++index) {
        out.data()[index] =
            static_cast<unsigned char>(first + index);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_universal_two_child_parent_tests)

BOOST_AUTO_TEST_CASE(
    verifier_cs_is_shape_and_registry_owned_not_tape_owned)
{
    const auto shape = Shape();
    const auto registry = Registry();
    u2::VerifierConstraintSystemV1 rebuilt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        u2::BuildVerifierConstraintSystemV1(
            shape, registry, rebuilt, &why),
        why);
    BOOST_CHECK_EQUAL(rebuilt.arity, 2U);
    BOOST_CHECK(rebuilt.registry_program_reconstructed);
    BOOST_CHECK(rebuilt.shape_only_parent_reconstructed);
    BOOST_CHECK(rebuilt.proof_tape_independent);
    BOOST_CHECK(
        rebuilt
             .proof_specific_constants_lifted_to_fixed_trace);
    BOOST_CHECK(
        !rebuilt.full_child_acceptance_constrained);
    BOOST_CHECK(!rebuilt.authority);

    const std::vector<unsigned char> first_tape{
        0x01, 0x02, 0x03};
    const std::vector<unsigned char> second_tape{
        0xa1, 0xb2, 0xc3, 0xd4};
    BOOST_CHECK_MESSAGE(
        u2::VerifyProofTapeNoninterferenceV1(
            shape, registry,
            first_tape, second_tape, &why),
        why);

    auto substituted = registry;
    substituted.program_root.SetNull();
    BOOST_CHECK(
        !u2::BuildVerifierConstraintSystemV1(
            shape, substituted, rebuilt, &why));

    substituted = registry;
    substituted.child_relation_program
        .programs[0].declared_degree = 2;
    BOOST_CHECK(
        !u2::BuildVerifierConstraintSystemV1(
            shape, substituted, rebuilt, &why));

    auto downgraded = shape;
    --downgraded.queries;
    BOOST_CHECK(
        !u2::BuildVerifierConstraintSystemV1(
            downgraded, registry, rebuilt, &why));

    downgraded = shape;
    downgraded.child_lde /= 2;
    --downgraded.merkle_depth;
    BOOST_CHECK(
        !u2::BuildVerifierConstraintSystemV1(
            downgraded, registry, rebuilt, &why));

    downgraded = shape;
    downgraded.independent_fri_batching =
        !shape.independent_fri_batching;
    BOOST_CHECK(
        !u2::BuildVerifierConstraintSystemV1(
            downgraded, registry, rebuilt, &why));

    downgraded = shape;
    --downgraded.column_lengths[0];
    BOOST_CHECK(
        !u2::BuildVerifierConstraintSystemV1(
            downgraded, registry, rebuilt, &why));
}

BOOST_AUTO_TEST_CASE(
    fixed_trace_parent_executes_and_rejects_root_substitution)
{
    const auto shape = Shape();
    const auto registry = Registry();
    u2::VerifierConstraintSystemV1 rebuilt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        u2::BuildVerifierConstraintSystemV1(
            shape, registry, rebuilt, &why),
        why);

    const std::vector<std::vector<gf::Fp3>> child_columns{
        {gf::Fp3::Zero(), gf::Fp3::Zero()},
        {gf::Fp3::One(), gf::Fp3::One()},
    };
    const uint256 first_seed = Seed(31);
    auto first_proof =
        aq::AirQuotientProve<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
                rebuilt.child_cs, child_columns,
                first_seed, {});
    BOOST_REQUIRE_MESSAGE(
        first_proof.ok && first_proof.division_exact,
        first_proof.note);

    ar::VerifierAirFixedTraceLayoutV1 first_layout;
    auto first = ar::BuildAggregateWitnessFixedTraceV1(
        rebuilt.child_cs,
        {first_proof.proof, first_proof.proof},
        first_seed, first_layout, {});
    BOOST_REQUIRE_MESSAGE(first.ok, first.note);
    BOOST_CHECK(first.cs.preprocessed.empty());
    BOOST_CHECK_EQUAL(
        first_layout.ordered_columns.size(),
        static_cast<size_t>(
            first_layout.n_columns -
            first_layout.n_witness_columns));
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(
            first.cs, first.columns),
        0U);

    // Canonical query/domain helpers are derived constraints, not merely
    // values hidden under the FixedTrace commitment.
    auto wrong_index = first.columns;
    const auto& canonical_child =
        first_layout.children[0];
    wrong_index[canonical_child.query_index][0] =
        gf::Add(
            wrong_index[
                canonical_child.query_index][0],
            gf::Fp3::One());
    uint32_t canonical_bad_row = 0;
    std::string canonical_bad_constraint;
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            first.cs, wrong_index,
            &canonical_bad_row,
            &canonical_bad_constraint),
        0U);
    BOOST_CHECK(
        canonical_bad_constraint.find(
            "query.index.from_bits") !=
        std::string::npos);

    BOOST_REQUIRE(
        !canonical_child.z1_square_powers.empty());
    auto wrong_z_power = first.columns;
    wrong_z_power[
        canonical_child.z1_square_powers.front()][0] =
        gf::Add(
            wrong_z_power[
                canonical_child.z1_square_powers.front()][0],
            gf::Fp3::One());
    canonical_bad_constraint.clear();
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            first.cs, wrong_z_power,
            &canonical_bad_row,
            &canonical_bad_constraint),
        0U);
    BOOST_CHECK(
        canonical_bad_constraint.find(
            "z1_power") !=
        std::string::npos);

    BOOST_REQUIRE(
        canonical_child.y_square_powers.size() >= 2U);
    auto wrong_y_power = first.columns;
    wrong_y_power[
        canonical_child.y_square_powers.back()][0] =
        gf::Add(
            wrong_y_power[
                canonical_child.y_square_powers.back()][0],
            gf::Fp3::One());
    canonical_bad_constraint.clear();
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            first.cs, wrong_y_power,
            &canonical_bad_row,
            &canonical_bad_constraint),
        0U);
    BOOST_CHECK(
        canonical_bad_constraint.find(
            "y_power") !=
        std::string::npos);

    // A second transcript changes proof-owned challenges and query cells but
    // cannot change the registry/shape-selected callback schedule.
    const uint256 second_seed = Seed(77);
    auto second_proof =
        aq::AirQuotientProve<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
                rebuilt.child_cs, child_columns,
                second_seed, {});
    BOOST_REQUIRE_MESSAGE(
        second_proof.ok &&
            second_proof.division_exact,
        second_proof.note);
    ar::VerifierAirFixedTraceLayoutV1 second_layout;
    auto second = ar::BuildAggregateWitnessFixedTraceV1(
        rebuilt.child_cs,
        {second_proof.proof, second_proof.proof},
        second_seed, second_layout, {});
    BOOST_REQUIRE_MESSAGE(second.ok, second.note);
    BOOST_CHECK(
        first_layout.ordered_columns ==
        second_layout.ordered_columns);
    BOOST_CHECK(
        u2::CommitConstraintScheduleV1(first.cs) ==
        u2::CommitConstraintScheduleV1(second.cs));
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(
            second.cs, second.columns),
        0U);

    // The root is consumed from the exact R0 column, rather than from a
    // captured C++ value.  Substitution therefore breaks the AIR itself.
    auto substituted = first.columns;
    const uint32_t row_root_column =
        first_layout.children[0].row_commit_root[0];
    for (gf::Fp3& value :
         substituted[row_root_column]) {
        value = gf::Add(value, gf::Fp3::One());
    }
    uint32_t bad_row = 0;
    std::string bad_constraint;
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            first.cs, substituted,
            &bad_row, &bad_constraint),
        0U);
    BOOST_CHECK(
        bad_constraint.find("root.pin") !=
        std::string::npos);

    // The AIR batching challenge is no longer represented only by a vector
    // of prover-selected powers.  One raw challenge cell deterministically
    // generates the complete consumer vector.
    auto wrong_lambda = first.columns;
    const auto& fixed_child =
        first_layout.children[0];
    BOOST_REQUIRE_GE(
        fixed_child.air_lambda_powers.size(), 2U);
    for (gf::Fp3& value :
         wrong_lambda[
             fixed_child.air_lambda_powers[1]]) {
        value = gf::Add(value, gf::Fp3::One());
    }
    bad_constraint.clear();
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            first.cs, wrong_lambda,
            &bad_row, &bad_constraint),
        0U);
    BOOST_CHECK(
        bad_constraint.find(
            "air_lambda.recurrence") !=
        std::string::npos);

    // Native proof-level closure: SAFE V3 authenticates the complete ordered
    // FixedTrace group, and the verifier rebuilds `first.cs` without either
    // child proof.  Both a public R0-root transplant and a selected-query
    // transplant are rejected by the real recursive backend.
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            first.cs, first.columns,
            first_layout.ordered_columns);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
    const aq::AirQuotientFixedTracePinV3 fixed_pin{
        .version = 1,
        .ordered_columns =
            first_layout.ordered_columns,
        .row_root = r0.base_row_commitment,
    };
    const uint256 parent_seed = Seed(113);
    const auto parent =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            first.cs, first.columns, fixed_pin,
            parent_seed, {}, &r0);
    BOOST_REQUIRE_MESSAGE(
        parent.ok && parent.division_exact,
        parent.note);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            first.cs, parent.proof, fixed_pin,
            parent_seed, &why),
        why);

    auto wrong_pin = fixed_pin;
    wrong_pin.row_root.begin()[0] ^= 1U;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            first.cs, parent.proof, wrong_pin,
            parent_seed, &why));

    auto wrong_query = parent.proof;
    BOOST_REQUIRE(
        !wrong_query.batch.queries.empty());
    wrong_query.batch.queries[0].index ^= 1U;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            first.cs, wrong_query, fixed_pin,
            parent_seed, &why));
}

BOOST_AUTO_TEST_CASE(
    heterogeneous_leaf_receipts_share_one_canonical_binary_parent)
{
    const std::array<u2::PublicShapeV1, 2> shapes{
        Shape(), Shape()};
    const std::array<u2::FrozenRegistryV1, 2> registries{
        Registry(), SecondRegistry()};
    u2::HeterogeneousVerifierConstraintSystemV1 rebuilt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        u2::BuildHeterogeneousVerifierConstraintSystemV1(
            shapes, registries, rebuilt, &why),
        why);
    BOOST_CHECK(
        rebuilt.both_registry_programs_reconstructed);
    BOOST_CHECK(
        rebuilt.heterogeneous_children_supported);
    BOOST_CHECK(rebuilt.proof_tape_independent);
    BOOST_CHECK(
        rebuilt
            .proof_specific_constants_lifted_to_fixed_trace);
    BOOST_CHECK(
        rebuilt.registry_program_root[0] !=
        rebuilt.registry_program_root[1]);
    BOOST_CHECK(!rebuilt.authority);

    const std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::Zero()},
        {gf::Fp3::One(), gf::Fp3::One()},
    };
    const std::array<uint256, 2> seeds{
        Seed(141), Seed(177)};
    auto left =
        aq::AirQuotientProve<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
                rebuilt.child_cs[0], columns,
                seeds[0], {});
    auto right =
        aq::AirQuotientProve<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
                rebuilt.child_cs[1], columns,
                seeds[1], {});
    BOOST_REQUIRE_MESSAGE(
        left.ok && left.division_exact, left.note);
    BOOST_REQUIRE_MESSAGE(
        right.ok && right.division_exact, right.note);

    ar::VerifierAirFixedTraceLayoutV1 layout;
    const auto parent =
        ar::BuildAggregateWitnessHeterogeneousFixedTraceV1(
            {rebuilt.child_cs[0],
             rebuilt.child_cs[1]},
            {left.proof, right.proof},
            {seeds[0], seeds[1]},
            layout, {});
    BOOST_REQUIRE_MESSAGE(parent.ok, parent.note);
    BOOST_CHECK_EQUAL(layout.arity, 2U);
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(
            parent.cs, parent.columns),
        0U);
    BOOST_CHECK(
        u2::CommitConstraintScheduleV1(parent.cs) ==
        rebuilt.callback_schedule_commitment);

    // The attached final-root proof carries no callback graph.  Consensus
    // rebuilds it from both frozen registries and shapes, binds that schedule
    // into the parent Fiat-Shamir seed, and verifies the FixedTrace root.
    u2::CanonicalBinaryParentProofV1 attached;
    const uint256 parent_seed = Seed(213);
    BOOST_REQUIRE_MESSAGE(
        u2::ProveCanonicalBinaryParentV1(
            shapes, registries,
            {left.proof, right.proof},
            seeds, parent_seed, attached, &why),
        why);
    BOOST_CHECK(
        attached.verifier_cs_rebuilt_without_proof_tape);
    BOOST_CHECK(attached.fixed_trace_root_bound);
    BOOST_CHECK(
        !attached.same_parent_fiat_shamir_bound);
    BOOST_CHECK(!attached.authority);
    BOOST_CHECK_MESSAGE(
        u2::VerifyCanonicalBinaryParentV1(
            shapes, registries, attached,
            parent_seed, &why),
        why);

    auto wrong_root = attached;
    wrong_root.statement.fixed_trace_root.begin()[0] ^= 1U;
    BOOST_CHECK(
        !u2::VerifyCanonicalBinaryParentV1(
            shapes, registries, wrong_root,
            parent_seed, &why));

    auto wrong_query = attached;
    BOOST_REQUIRE(
        !wrong_query.proof.batch.queries.empty());
    wrong_query.proof.batch.queries.front().index ^= 1U;
    BOOST_CHECK(
        !u2::VerifyCanonicalBinaryParentV1(
            shapes, registries, wrong_query,
            parent_seed, &why));

    auto substituted_registries = registries;
    substituted_registries[1] = Registry();
    BOOST_CHECK(
        !u2::VerifyCanonicalBinaryParentV1(
            shapes, substituted_registries,
            attached, parent_seed, &why));

    auto substituted_shapes = shapes;
    --substituted_shapes[1].column_lengths[0];
    BOOST_CHECK(
        !u2::VerifyCanonicalBinaryParentV1(
            substituted_shapes, registries,
            attached, parent_seed, &why));
}

BOOST_AUTO_TEST_SUITE_END()
