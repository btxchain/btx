// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_receipt_intake.h>

#include <algorithm>
#include <cstdlib>
#include <vector>

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace fp = rc::recursive_fixedpoint;
namespace gf = rc::gkr_field;
namespace intake =
    rc::stage3_semantic_endpoint_receipt_intake;

namespace {

uint256 Seed(uint8_t tag)
{
    uint256 out;
    for (uint32_t i = 0; i < out.size(); ++i) {
        out.begin()[i] =
            static_cast<unsigned char>(
                tag + 17U * i);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

const rc::RCStage3RoleAirProduct& WiringRole()
{
    static const rc::RCStage3RoleAirProduct role = [] {
        std::string why;
        const gf::Fp3 copy =
            gf::Fp3::FromFp(
                gf::FromU64(0x7621ab39U));
        auto out =
            rc::BuildRCStage3EpisodeWiringRoleAir(
                &why, &copy);
        BOOST_REQUIRE_MESSAGE(out.ok, why);
        return out;
    }();
    return role;
}

struct IntakeNode {
    intake::ProofV1 intake_proof;
    std::vector<aq::AirConstraintSystem<gf::Fp3>>
        child_css;
    std::vector<fp::AlgAirProof> child_proofs;
    std::vector<uint256> child_seeds;
    fp::FoldBusComposition node;
};

const intake::ProofV1& SharedIntakeProof()
{
    static const intake::ProofV1 proof =
        intake::ProveV1({WiringRole()}, {}, false);
    BOOST_REQUIRE_MESSAGE(
        proof.construction_valid, proof.note);
    return proof;
}

IntakeNode BuildIntakeNode()
{
    IntakeNode out;
    out.intake_proof = SharedIntakeProof();
    for (const auto& receipt :
         out.intake_proof.role_receipts) {
        out.child_css.push_back(
            receipt.ordinary_proof
                .receipt.constraint_system);
        out.child_proofs.push_back(
            receipt.ordinary_proof.receipt.proof);
        out.child_seeds.push_back(
            receipt.ordinary_proof.receipt.fs_seed);
    }
    out.child_css.push_back(
        out.intake_proof.equality_link
            .ordinary_proof.receipt
            .constraint_system);
    out.child_proofs.push_back(
        out.intake_proof.equality_link
            .ordinary_proof.receipt.proof);
    out.child_seeds.push_back(
        out.intake_proof.equality_link
            .ordinary_proof.receipt.fs_seed);
    out.node =
        fp::BuildFoldBusCompositionMulti(
            out.child_css, out.child_proofs,
            out.child_seeds);
    BOOST_REQUIRE_MESSAGE(
        out.node.valid, out.node.note);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_semantic_endpoint_parent_tests)

BOOST_AUTO_TEST_CASE(
    concrete_role_and_link_terminals_join_in_same_parent)
{
    IntakeNode fixture = BuildIntakeNode();
    const uint256 context = Seed(0x31);
    const uint256 before =
        fp::ComputeNarrowMultiChildParentFsSeedV1(
            fixture.node, fixture.child_seeds,
            context);
    BOOST_REQUIRE(!before.IsNull());

    const auto attached =
        fp::AttachSemanticEndpointReceiptTerminalsV1(
            fixture.node, {WiringRole()}, {},
            fixture.intake_proof);
    BOOST_REQUIRE_MESSAGE(
        attached.valid, attached.note);
    BOOST_CHECK(attached.intake_reverified);
    BOOST_CHECK(
        attached.exact_statement_and_context);
    BOOST_CHECK(attached.exact_child_order);
    BOOST_CHECK(attached.exact_endpoint_order);
    BOOST_CHECK(
        attached.root_words_equality_constrained);
    BOOST_CHECK(
        attached.dual_fp3_logup_recomputed);
    BOOST_CHECK(
        attached.role_terminals_proof_aliased);
    BOOST_CHECK(
        attached.link_terminal_proof_aliased);
    BOOST_CHECK(
        attached.every_concrete_role_joined);
    BOOST_CHECK_EQUAL(attached.concrete_roles, 1U);
    BOOST_CHECK_EQUAL(attached.concrete_endpoints, 4U);
    BOOST_CHECK_EQUAL(attached.residual_endpoints, 48U);
    BOOST_CHECK(
        !attached
             .all_52_endpoints_and_14_roles_joined);
    BOOST_CHECK(
        attached
             .canonical_terminal_constraint_bytecode);
    BOOST_CHECK(attached.canonical_program_table_valid);
    BOOST_CHECK(attached.canonical_program_interpreted);
    BOOST_CHECK(
        !attached
             .canonical_program_table_commitment
             .IsNull());
    BOOST_CHECK_EQUAL(
        attached.canonical_constraints, 48U);
    BOOST_CHECK_EQUAL(
        attached.opaque_callback_constraints_eliminated,
        32U);
    BOOST_CHECK_GT(
        attached.remaining_noncanonical_constraints,
        0U);
    BOOST_CHECK(
        fixture.node
            .concrete_semantic_endpoint_terminal_join);
    BOOST_CHECK(
        !fixture.node
             .every_semantic_endpoint_role_joined);
    BOOST_CHECK(
        !fixture.node
             .deep_per_point_transition_join);
    BOOST_CHECK_EQUAL(
        fixture.node
            .semantic_endpoint_roles_joined,
        1U);
    BOOST_CHECK_EQUAL(
        fixture.node
            .semantic_endpoint_roles_expected,
        rc::kRCStage3RelationClosureRoleCount);
    BOOST_CHECK(
        fixture.node
            .semantic_endpoint_receipt_commitment ==
        attached.statement_commitment);
    BOOST_CHECK_EQUAL(attached.violations, 0U);

    const uint256 after =
        fp::ComputeNarrowMultiChildParentFsSeedV1(
            fixture.node, fixture.child_seeds,
            context);
    BOOST_REQUIRE(!after.IsNull());
    BOOST_CHECK(after != before);

    auto bad_root = fixture.node.columns;
    bad_root[
        attached.layout.root_value][0] =
        gf::Add(
            bad_root[
                attached.layout.root_value][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            fixture.node.combined, bad_root),
        0U);

    const uint32_t terminal_column =
        fixture.intake_proof.role_receipts[0]
            .terminal_columns[0];
    const uint32_t terminal_coordinate =
        3 * terminal_column;
    uint32_t selected_row =
        fixture.node.combined.n_rows;
    uint32_t port = UINT32_MAX;
    for (uint32_t row = 0;
         row < fixture.node.hash.program.rows.size();
         ++row) {
        const auto& meta =
            fixture.node.hash.program.rows[row];
        if (meta.child == 0 &&
            meta.current_row_sponge &&
            terminal_coordinate >=
                meta.current_word_offset &&
            terminal_coordinate <
                meta.current_word_offset +
                    rc::alg_hash::kAlgHashRate) {
            selected_row = row;
            port =
                terminal_coordinate -
                meta.current_word_offset;
            break;
        }
    }
    BOOST_REQUIRE_LT(
        selected_row, fixture.node.combined.n_rows);
    BOOST_REQUIRE_LT(port, rc::alg_hash::kAlgHashRate);
    BOOST_REQUIRE(
        gf::Eq(
            fixture.node.columns[
                attached.layout.AliasPortSelector(port)]
                [selected_row],
            gf::Fp3::One()));
    auto bad_opening = fixture.node.columns;
    const fp::HashOpeningLayout hash_layout =
        fp::HashOpeningLayoutAt(
            fixture.node.hash.column_base);
    bad_opening[
        hash_layout.absorbed_pin_base +
        port][selected_row] =
        gf::Add(
            bad_opening[
                hash_layout.absorbed_pin_base +
                port][selected_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            fixture.node.combined,
            bad_opening),
        0U);
}

BOOST_AUTO_TEST_CASE(
    endpoint_root_context_terminal_and_omission_attacks_fail_closed)
{
    IntakeNode fixture = BuildIntakeNode();
    const std::string honest_note = fixture.node.note;
    const uint32_t honest_columns =
        fixture.node.combined.n_columns;
    auto attach =
        [&fixture](
           const intake::ProofV1& proof) {
            return fp::
                AttachSemanticEndpointReceiptTerminalsV1(
                    fixture.node, {WiringRole()}, {},
                    proof);
        };
    auto reset_fail_closed_node =
        [&fixture, &honest_note, honest_columns] {
            BOOST_CHECK_EQUAL(
                fixture.node.combined.n_columns,
                honest_columns);
            BOOST_CHECK(
                fixture.node
                    .semantic_endpoint_receipt_commitment
                    .IsNull());
            fixture.node.valid = true;
            fixture.node.note = honest_note;
        };
    {
        auto attack = fixture.intake_proof;
        const auto found = std::find_if(
            attack.manifest.endpoints.begin(),
            attack.manifest.endpoints.end(),
            [](const auto& endpoint) {
                return endpoint.present;
            });
        BOOST_REQUIRE(
            found != attack.manifest.endpoints.end());
        found->root_words[0] ^= 1U;
        const auto rejected = attach(attack);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!fixture.node.valid);
        reset_fail_closed_node();
    }
    {
        auto attack = fixture.intake_proof;
        attack.role_receipts[0]
            .binding.proof_context_binding =
            Seed(0x51);
        const auto rejected = attach(attack);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!fixture.node.valid);
        reset_fail_closed_node();
    }
    {
        auto attack = fixture.intake_proof;
        attack.role_receipts[0].terminal[0] =
            gf::Add(
                attack.role_receipts[0].terminal[0],
                gf::Fp3::One());
        const auto rejected = attach(attack);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!fixture.node.valid);
        reset_fail_closed_node();
    }
    {
        auto attack = fixture.intake_proof;
        attack.role_receipts[0]
            .ordinary_proof.receipt.proof
            .trace_commit.begin()[0] ^= 1U;
        const auto rejected = attach(attack);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!fixture.node.valid);
        reset_fail_closed_node();
    }
    {
        auto attack = fixture.intake_proof;
        attack.role_receipts.clear();
        const auto rejected = attach(attack);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!fixture.node.valid);
        reset_fail_closed_node();
    }
    {
        std::swap(fixture.child_css[0],
                  fixture.child_css[1]);
        std::swap(fixture.child_proofs[0],
                  fixture.child_proofs[1]);
        std::swap(fixture.child_seeds[0],
                  fixture.child_seeds[1]);
        fixture.node =
            fp::BuildFoldBusCompositionMulti(
                fixture.child_css,
                fixture.child_proofs,
                fixture.child_seeds);
        BOOST_REQUIRE_MESSAGE(
            fixture.node.valid,
            fixture.node.note);
        const auto rejected =
            attach(fixture.intake_proof);
        BOOST_CHECK(!rejected.valid);
        BOOST_CHECK(!fixture.node.valid);
    }
}

BOOST_AUTO_TEST_CASE(
    concrete_terminal_parent_proof_rejects_statement_substitution)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_SEMANTIC_ENDPOINT_PARENT_PROOF") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_SEMANTIC_ENDPOINT_PARENT_PROOF=1 "
            "for the proof-level semantic-terminal parent test");
        return;
    }
    IntakeNode fixture = BuildIntakeNode();
    const auto attached =
        fp::AttachSemanticEndpointReceiptTerminalsV1(
            fixture.node, {WiringRole()}, {},
            fixture.intake_proof);
    BOOST_REQUIRE_MESSAGE(
        attached.valid, attached.note);
    const uint256 context = Seed(0x71);
    const uint256 seed =
        fp::ComputeNarrowMultiChildParentFsSeedV1(
            fixture.node, fixture.child_seeds,
            context);
    BOOST_REQUIRE(!seed.IsNull());
    const auto proved =
        aq::AirQuotientProveRows(
            fixture.node.combined,
            fixture.node.columns,
            seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            fixture.node.combined,
            proved.proof, seed, &why),
        why);

    auto substituted = fixture.node;
    substituted
        .semantic_endpoint_receipt_commitment =
        Seed(0x72);
    const uint256 substituted_seed =
        fp::ComputeNarrowMultiChildParentFsSeedV1(
            substituted, fixture.child_seeds,
            context);
    BOOST_REQUIRE(!substituted_seed.IsNull());
    BOOST_REQUIRE(substituted_seed != seed);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            fixture.node.combined,
            proved.proof, substituted_seed,
            &why));
}

BOOST_AUTO_TEST_SUITE_END()
