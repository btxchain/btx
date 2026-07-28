// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_universal_two_child_parent.h>

#include <boost/test/unit_test.hpp>

#include <utility>

namespace {

namespace rc =
    matmul::v4::rc;
namespace u2 =
    matmul::v4::rc::universal_two_child_parent;
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
    return table;
}

u2::PublicShapeV1 Shape()
{
    u2::PublicShapeV1 out;
    out.child_rows = 2;
    out.child_columns = 2;
    out.child_quotient_len = 2;
    out.child_coefficients = 2;
    out.child_lde = 8;
    out.merkle_depth = 3;
    out.folds = 1;
    out.queries = 2;
    out.column_lengths = {2, 2, 2};
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
        !rebuilt
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
}

BOOST_AUTO_TEST_SUITE_END()
