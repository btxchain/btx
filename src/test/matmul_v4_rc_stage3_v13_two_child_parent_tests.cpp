// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_two_child_parent.h>

#include <cstdlib>
#include <string>
#include <utility>

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace cb = rc::constraint_bytecode;
namespace gf = rc::gkr_field;
namespace two =
    rc::stage3_v13_two_child_parent;

namespace {

uint256 Seed(uint8_t tag)
{
    uint256 out;
    for (uint32_t index = 0;
         index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                tag + 19 * index);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

cb::Instruction Load(
    cb::Opcode opcode, uint32_t column)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = column;
    return out;
}

cb::Instruction Constant(uint64_t value)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Constant;
    out.constant = gf::Fp3::FromFp(value);
    return out;
}

cb::Instruction Binary(
    cb::Opcode opcode,
    uint32_t lhs,
    uint32_t rhs)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = lhs;
    out.rhs = rhs;
    return out;
}

cb::ProgramTable Programs()
{
    cb::Program transition;
    transition.role =
        rc::RCStage3RelationRole::EpisodeGemm;
    transition.constraint_ordinal = 0;
    transition.kind =
        aq::AirKind::kTransition;
    transition.declared_degree = 1;
    transition.current_width = 2;
    transition.next_width = 2;
    transition.instructions = {
        Load(cb::Opcode::Next, 0),
        Load(cb::Opcode::Current, 0),
        Binary(cb::Opcode::Sub, 0, 1),
        Constant(1),
        Binary(cb::Opcode::Sub, 2, 3),
    };

    cb::Program everywhere;
    everywhere.role =
        rc::RCStage3RelationRole::EpisodeGemm;
    everywhere.constraint_ordinal = 1;
    everywhere.kind =
        aq::AirKind::kEverywhere;
    everywhere.declared_degree = 1;
    everywhere.current_width = 2;
    everywhere.next_width = 2;
    everywhere.instructions = {
        Load(cb::Opcode::Current, 1),
        Load(cb::Opcode::Current, 0),
        Constant(2),
        Binary(cb::Opcode::Mul, 1, 2),
        Binary(cb::Opcode::Sub, 0, 3),
    };
    cb::ProgramTable out;
    out.role =
        rc::RCStage3RelationRole::EpisodeGemm;
    out.current_width = 2;
    out.next_width = 2;
    out.programs = {transition, everywhere};
    return out;
}

two::PublicStatementV1 Statement()
{
    two::PublicStatementV1 out;
    out.parent_public_seed = Seed(0x61);
    for (uint32_t child = 0;
         child < two::kArityV1; ++child) {
        auto& statement = out.children[child];
        statement.tape_shape.trace_rows = 256;
        statement.tape_shape.trace_columns = 2;
        statement.tape_shape.quotient_len = 256;
        statement.tape_shape.n_coeffs = 256;
        statement.tape_shape
            .base_column_indices = {0};
        statement.tape_binding.program_root =
            Seed(0x51);
        statement.tape_binding.statement_root =
            Seed(0x52);
        statement.tape_binding.public_fs_seed =
            Seed(0x53);
        statement.tape_binding.proof_wire_root =
            Seed(0x54);
        statement.tape_binding.tape_root =
            {1, 2, 3, 4};
        statement.range = {
            .ordinal = child,
            .first_query = child,
            .query_count = 1,
        };
        statement.child_program = Programs();
        statement.child_program_root =
            cb::CommitProgramTableAlgHash(
                statement.child_program);
        statement.public_seed =
            Seed(0x55 + child);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_two_child_parent_tests)

BOOST_AUTO_TEST_CASE(
    ordered_sibling_statement_and_seed_substitutions_are_bound)
{
    const auto statement = Statement();
    const auto root =
        two::CommitStatementV1(statement);
    const auto seed0 =
        two::DeriveChildFinalizationSeedV1(
            statement, 0);
    const auto seed1 =
        two::DeriveChildFinalizationSeedV1(
            statement, 1);
    BOOST_REQUIRE(!root.IsNull());
    BOOST_REQUIRE(!seed0.IsNull());
    BOOST_REQUIRE(!seed1.IsNull());
    BOOST_CHECK(seed0 != seed1);

    auto swapped = statement;
    std::swap(
        swapped.children[0],
        swapped.children[1]);
    BOOST_CHECK(
        two::CommitStatementV1(swapped) !=
        root);
    BOOST_CHECK(
        two::DeriveChildFinalizationSeedV1(
            swapped, 0) != seed0);

    auto changed_seed = statement;
    changed_seed.parent_public_seed.begin()[0] ^=
        1U;
    BOOST_CHECK(
        two::CommitStatementV1(
            changed_seed) != root);
    BOOST_CHECK(
        two::DeriveChildFinalizationSeedV1(
            changed_seed, 0) != seed0);

    auto omitted = statement;
    omitted.children[1] = {};
    two::DeterministicParentV1 rejected;
    std::string why;
    BOOST_CHECK(
        !two::BuildDeterministicConstraintSystemV1(
            omitted, rejected, &why));

    auto duplicate = statement;
    duplicate.children[1] =
        duplicate.children[0];
    BOOST_CHECK(
        !two::BuildDeterministicConstraintSystemV1(
            duplicate, rejected, &why));

    // A child-local seed is not work identity.  It cannot be changed to
    // disguise the same range/proof/program as a second sibling.
    duplicate.children[1].public_seed =
        Seed(0x99);
    BOOST_CHECK(
        two::CommitChildStatementV1(
            duplicate.children[0]) !=
        two::CommitChildStatementV1(
            duplicate.children[1]));
    BOOST_CHECK(
        two::CommitChildIdentityV1(
            duplicate.children[0]) ==
        two::CommitChildIdentityV1(
            duplicate.children[1]));
    BOOST_CHECK(
        !two::BuildDeterministicConstraintSystemV1(
            duplicate, rejected, &why));
}

BOOST_AUTO_TEST_CASE(
    public_two_child_parent_uses_one_r0_and_parent_acceptance)
{
    if (std::getenv(
            "BTX_RUN_V13_TWO_CHILD_PARENT") ==
        nullptr) {
        return;
    }
    const auto statement = Statement();
    const uint256 r0_root = Seed(0x71);
    two::VerifierConstraintSystemV1
        rebuilt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        two::BuildConstraintSystemV1(
            statement, r0_root,
            rebuilt, &why),
        why);
    BOOST_CHECK(rebuilt.valid);
    BOOST_CHECK(rebuilt.single_shared_r0);
    BOOST_CHECK(
        rebuilt.both_children_finalized);
    BOOST_CHECK(
        rebuilt.proof_values_excluded);
    BOOST_REQUIRE_EQUAL(
        rebuilt.cs
            .preprocessed_row_group_roots
            .size(),
        1U);
    BOOST_CHECK(
        rebuilt.cs
            .preprocessed_row_group_roots[0]
            .root == r0_root);
    BOOST_CHECK_EQUAL(
        rebuilt.r0_base_column_indices
            .size(),
        rebuilt.deterministic
            .parent_acceptance_column + 1);
    BOOST_CHECK(
        rebuilt.child_finalizations[0]
            .deep.r0_row_root ==
        rebuilt.child_finalizations[1]
            .deep.r0_row_root);
    BOOST_CHECK(
        rebuilt.deterministic
            .child_finalization_seeds[0] !=
        rebuilt.deterministic
            .child_finalization_seeds[1]);
}

BOOST_AUTO_TEST_SUITE_END()
