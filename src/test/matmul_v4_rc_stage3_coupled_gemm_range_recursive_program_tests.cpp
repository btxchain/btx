// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_range_recursive_program.h>

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_range_ctl_v3.h>
#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_gated_ctl_alias.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_deep_vm.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <string>

namespace {

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace cb = rc::constraint_bytecode;
namespace gated = rc::gated_ctl_alias;
namespace gf = rc::gkr_field;
namespace program =
    rc::coupled_gemm_range_recursive_program;
namespace deep =
    rc::stage3_multirow_v11_deep_vm;
namespace v3 = rc::coupled_gemm_range_ctl_v3;

using gf::Fp3;
using CS = aq::AirConstraintSystem<Fp3>;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

rc::RCStage3CtlChallenges Challenges()
{
    return {
        gf::FromU64_3(11),
        gf::FromU64_3(13),
        gf::FromU64_3(17),
        gf::FromU64_3(19),
    };
}

rc::RCStage3CtlTerminal Terminal()
{
    return {
        gf::FromU64_3(23),
        gf::FromU64_3(29),
    };
}

rc::RCStage3CoupledGemmDotPin DotPin()
{
    rc::RCStage3CoupledGemmDotPin pin;
    pin.statement_commitment = H(0x11);
    pin.shape_commitment = H(0x22);
    pin.schedule_commitment = H(0x33);
    pin.schedule_index = 2;
    pin.output_tile_index = 3;
    pin.contraction_size = 2;
    pin.logical_rows =
        pin.contraction_size * rc::kRCMxBlockLen;
    pin.n_rows = 64;
    pin.n_coeffs = pin.n_rows;
    pin.column_roots.resize(
        rc::kRCStage3CoupledGemmColumns);
    for (uint32_t i = 0;
         i < pin.column_roots.size();
         ++i) {
        pin.column_roots[i] = {i, H(0x40 + i)};
    }
    pin.pin_commitment =
        rc::ComputeRCStage3CoupledGemmDotPinCommitment(
            pin);
    return pin;
}

rc::RCStage3SignedRangePin RangePin()
{
    rc::RCStage3SignedRangePin pin;
    pin.statement_commitment = H(0x51);
    pin.manifest_commitment = H(0x52);
    pin.layer_ordinal = 1;
    pin.shard_index = 0;
    pin.shard_count = 1;
    pin.cell_begin = 96;
    pin.logical_rows = 35;
    pin.n_rows = 64;
    pin.max_abs = 1234567;
    pin.column_roots.resize(
        rc::kRCStage3SignedRangeColumns);
    for (uint32_t i = 0;
         i < pin.column_roots.size();
         ++i) {
        pin.column_roots[i] = {i, H(0x60 + i)};
    }
    return pin;
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 700;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.coupled_profile = 2;
    out.public_inputs.transcript_version = 4;
    out.public_inputs.header_commitment = H(0x11);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.target = H(0xff);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.coupled_digest = H(0x44);
    out.public_inputs.final_digest = H(0x44);
    return out;
}

rc::RCStage3CoupledShape Shape()
{
    rc::RCStage3CoupledShape out;
    out.barriers = 4;
    out.lobes = 1;
    out.lobe_width = 32;
    out.bank_pages = 1;
    out.rows_per_lobe = 1;
    out.pages_per_barrier_lobe = 1;
    out.transcript_version = 4;
    out.full_bank_schedule = true;
    return out;
}

std::vector<rc::RCStage3CoupledGemmOpening> Openings()
{
    std::vector<rc::RCStage3CoupledGemmOpening> out(4);
    for (auto& opening : out) {
        opening.operand_a.assign(32, 1);
        opening.operand_b.assign(32 * 32, 1);
        opening.output_y.assign(32, 32);
    }
    return out;
}

std::vector<Fp3> Row(uint32_t width, uint64_t salt)
{
    std::vector<Fp3> out(width);
    for (uint32_t i = 0; i < width; ++i) {
        const uint64_t x =
            (salt + 17) * (i + 23) +
            uint64_t{i} * i * 31;
        out[i] = {
            gf::FromU64(x + 1),
            gf::FromU64(3 * x + 5),
            gf::FromU64(7 * x + 9),
        };
    }
    return out;
}

void RequireSameConstraints(
    const CS& native,
    const CS& recursive,
    uint32_t trials)
{
    BOOST_REQUIRE_EQUAL(
        native.n_columns, recursive.n_columns);
    BOOST_REQUIRE_EQUAL(
        native.constraints.size(),
        recursive.constraints.size());
    BOOST_REQUIRE_EQUAL(
        native.QuotientLen(),
        recursive.QuotientLen());
    for (uint32_t constraint = 0;
         constraint < native.constraints.size();
         ++constraint) {
        BOOST_REQUIRE(
            native.constraints[constraint].kind ==
            recursive.constraints[constraint].kind);
        // QuotientLen is proof-visible, so the recursive table must retain
        // the native raw degree metadata exactly as well as the expression.
        BOOST_REQUIRE_EQUAL(
            recursive.constraints[constraint].alg_degree,
            native.constraints[constraint].alg_degree);
        for (uint32_t trial = 0; trial < trials; ++trial) {
            const auto current =
                Row(native.n_columns, 2 * trial);
            const auto next =
                Row(native.n_columns, 2 * trial + 1);
            const Fp3 a =
                native.constraints[constraint].eval(
                    current, next);
            const Fp3 b =
                recursive.constraints[constraint].eval(
                    current, next);
            BOOST_REQUIRE_MESSAGE(
                gf::Eq(a, b),
                "constraint=" << constraint <<
                " trial=" << trial);
        }
    }
}

CS NativeGemm(
    const rc::RCStage3CoupledGemmDotPin& pin,
    const rc::RCStage3CtlChallenges& challenges,
    const rc::RCStage3CtlTerminal& terminal)
{
    CS relation;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmDotConstraintSystem(
            pin, relation, &why),
        why);
    relation.preprocessed_roots.clear();
    gated::SpecV1 spec;
    spec.namespace_id = 0x47594f55U;
    spec.stage = 33;
    spec.sign = 1;
    spec.source_column =
        rc::kRCStage3CoupledGemmY;
    spec.selector_column =
        rc::kRCStage3CoupledGemmEnd;
    spec.addresses.resize(pin.n_rows);
    for (uint32_t row = 0; row < pin.n_rows; ++row) {
        spec.addresses[row] = row;
    }
    spec.challenges = challenges;
    spec.expected_terminal = terminal;
    CS out;
    gated::LayoutV1 layout;
    BOOST_REQUIRE_MESSAGE(
        gated::BuildConstraintSystemV1(
            relation, spec, out, layout, &why),
        why);
    return out;
}

CS NativeRange(
    const rc::RCStage3SignedRangePin& pin,
    const rc::RCStage3CtlChallenges& challenges,
    const rc::RCStage3CtlTerminal& terminal)
{
    CS relation;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveRCStage3SignedRangeKernelConstraintSystem(
            pin, relation, &why),
        why);
    relation.preprocessed_roots.clear();
    gated::SpecV1 spec;
    spec.namespace_id = 0x47594f55U;
    spec.stage = 33;
    spec.sign = -1;
    spec.source_column = rc::kRCStage3RangeValue;
    spec.selector_column = rc::kRCStage3RangeActive;
    spec.addresses.resize(pin.n_rows);
    for (uint32_t row = 0; row < pin.n_rows; ++row) {
        spec.addresses[row] =
            static_cast<uint32_t>(
                pin.cell_begin + row);
    }
    spec.challenges = challenges;
    spec.expected_terminal = terminal;
    CS out;
    gated::LayoutV1 layout;
    BOOST_REQUIRE_MESSAGE(
        gated::BuildConstraintSystemV1(
            relation, spec, out, layout, &why),
        why);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_gemm_range_recursive_program_tests)

BOOST_AUTO_TEST_CASE(
    exact_challenge_independent_bytecode_matches_every_native_constraint)
{
    const auto challenges = Challenges();
    const auto terminal = Terminal();
    const auto dot_pin = DotPin();
    const auto range_pin = RangePin();
    BOOST_REQUIRE(!dot_pin.pin_commitment.IsNull());

    cb::ProgramTable gemm_table;
    cb::ProgramTable range_table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        program::BuildGemmProgramV1(
            gemm_table, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        program::BuildRangeProgramV1(
            range_table, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        gemm_table.programs.size(), 28U);
    BOOST_REQUIRE_EQUAL(
        range_table.programs.size(), 157U);
    BOOST_CHECK(
        cb::ProgramTableIsChallengeIndependent(
            gemm_table));
    BOOST_CHECK(
        cb::ProgramTableIsChallengeIndependent(
            range_table));

    CS gemm_recursive;
    CS range_recursive;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            gemm_table, dot_pin.n_rows,
            program::BuildGemmChallengesV1(
                challenges, terminal),
            gemm_recursive, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            range_table, range_pin.n_rows,
            program::BuildRangeChallengesV1(
                challenges, terminal,
                range_pin.max_abs,
                range_pin.logical_rows),
            range_recursive, &why),
        why);

    RequireSameConstraints(
        NativeGemm(
            dot_pin, challenges, terminal),
        gemm_recursive, 9);
    RequireSameConstraints(
        NativeRange(
            range_pin, challenges, terminal),
        range_recursive, 9);
}

BOOST_AUTO_TEST_CASE(
    public_values_change_evaluation_but_not_program_commitment)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        program::BuildRangeProgramV1(table, &why),
        why);
    const uint256 sha_root =
        cb::CommitProgramTable(table);
    const auto alg_root =
        cb::CommitProgramTableAlgHash(table);

    const auto challenges = Challenges();
    const auto terminal = Terminal();
    auto honest =
        program::BuildRangeChallengesV1(
            challenges, terminal, 1234567, 35);
    auto forged = honest;
    forged[program::MAX_ABS_BITS + 7] =
        gf::Sub(
            Fp3::One(),
            forged[program::MAX_ABS_BITS + 7]);

    CS honest_cs;
    CS forged_cs;
    BOOST_REQUIRE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 64, honest, honest_cs, &why));
    BOOST_REQUIRE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 64, forged, forged_cs, &why));
    const auto current =
        Row(table.current_width, 4);
    const auto next =
        Row(table.current_width, 5);
    bool differs = false;
    for (uint32_t i = 0;
         i < honest_cs.constraints.size();
         ++i) {
        differs =
            differs ||
            !gf::Eq(
                honest_cs.constraints[i].eval(
                    current, next),
                forged_cs.constraints[i].eval(
                    current, next));
    }
    BOOST_CHECK(differs);
    BOOST_CHECK(
        cb::CommitProgramTable(table) ==
        sha_root);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(table) ==
        alg_root);
}

BOOST_AUTO_TEST_CASE(
    scalar_challenge_degree_version_is_additive_and_fail_closed)
{
    cb::Program v2;
    v2.version = cb::kConstraintBytecodeVersion;
    v2.role = rc::RCStage3RelationRole::CoupledGemm;
    v2.current_width = 1;
    v2.next_width = 1;
    v2.challenge_width = 1;
    v2.declared_degree = 2;
    v2.instructions = {
        {cb::Opcode::Challenge, 0, 0, Fp3::Zero()},
        {cb::Opcode::Current, 0, 0, Fp3::Zero()},
        {cb::Opcode::Mul, 0, 1, Fp3::Zero()},
    };
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgram(v2, &why), why);
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_MESSAGE(
        cb::SerializeProgram(v2, encoded, &why),
        why);
    cb::Program v2_roundtrip;
    BOOST_REQUIRE_MESSAGE(
        cb::DeserializeProgram(
            encoded, v2_roundtrip, &why),
        why);
    BOOST_CHECK(v2_roundtrip == v2);
    BOOST_CHECK(
        cb::CommitProgram(v2_roundtrip) ==
        cb::CommitProgram(v2));

    auto v3 = v2;
    v3.version =
        cb::kConstraintBytecodeScalarChallengeVersion;
    v3.declared_degree = 1;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgram(v3, &why), why);
    auto mislabeled = v3;
    mislabeled.declared_degree = 2;
    BOOST_CHECK(
        !cb::ValidateProgram(mislabeled, nullptr));
}

BOOST_AUTO_TEST_CASE(
    genuine_safe_v13_child_enters_challenge_aware_deep_vm)
{
    const auto statement = Statement();
    const auto shape = Shape();
    v3::ProductV3 product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v3::ProveV3(
            statement, shape, Openings(),
            product, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        v3::VerifyV3(
            statement, shape, product, &why),
        why);
    v3::ParentReceiptBundleV3 receipts;
    BOOST_REQUIRE_MESSAGE(
        v3::BuildVerifiedParentReceiptsV3(
            statement, shape, product,
            receipts, &why),
        why);
    BOOST_REQUIRE_EQUAL(receipts.shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(
        receipts.shards[0].role[0].nodes.size(),
        product.shards[0].gemm_children.size());

    cb::ProgramTable table;
    BOOST_REQUIRE_MESSAGE(
        program::BuildGemmProgramV1(table, &why),
        why);
    const auto root =
        cb::CommitProgramTableAlgHash(table);
    const auto challenges =
        program::BuildGemmChallengesV1(
            product.shards[0].challenges,
            product.shards[0]
                .gemm_children[0].terminal);
    const auto& node =
        receipts.shards[0].role[0].nodes[0];
    auto honest = deep::BuildProductSafeV13(
        node.proof, node.fs_seed,
        table, root, challenges, 0, 1);
    BOOST_REQUIRE_MESSAGE(
        honest.valid, honest.note);
    BOOST_CHECK(honest.backend_proof_verified);
    BOOST_CHECK(honest.safe_v13_native_verified);
    BOOST_CHECK(honest.transcript_receipt_verified);
    BOOST_CHECK(honest.canonical_bytecode_vm_air_constrained);
    BOOST_CHECK(honest.verifier_owned_challenge_bound);
    BOOST_CHECK_EQUAL(honest.violations, 0U);

    auto proof_attack = node.proof;
    BOOST_REQUIRE(
        !proof_attack.batch.queries[0]
             .group_rows[0].values.empty());
    proof_attack.batch.queries[0]
        .group_rows[0].values[0] =
        gf::Add(
            proof_attack.batch.queries[0]
                .group_rows[0].values[0],
            Fp3::One());
    BOOST_CHECK(!deep::BuildProductSafeV13(
        proof_attack, node.fs_seed,
        table, root, challenges, 0, 1).valid);

    auto challenge_attack = challenges;
    challenge_attack[program::ALPHA1] =
        gf::Add(
            challenge_attack[program::ALPHA1],
            Fp3::One());
    BOOST_CHECK(!deep::BuildProductSafeV13(
        node.proof, node.fs_seed,
        table, root,
        challenge_attack, 0, 1).valid);

    auto seed_attack = node.fs_seed;
    seed_attack.begin()[0] ^= 1U;
    BOOST_CHECK(!deep::BuildProductSafeV13(
        node.proof, seed_attack,
        table, root, challenges, 0, 1).valid);
}

BOOST_AUTO_TEST_SUITE_END()
