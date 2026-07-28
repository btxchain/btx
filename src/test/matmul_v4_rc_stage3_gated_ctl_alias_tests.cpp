// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_gated_ctl_alias.h>
#include <matmul/matmul_v4_rc_air_recurse.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

namespace {

namespace rc = matmul::v4::rc;
namespace gated = rc::gated_ctl_alias;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
using gf::Fp3;

aq::AirConstraintSystem<Fp3> Relation()
{
    aq::AirConstraintSystem<Fp3> cs;
    cs.n_rows = 8;
    cs.n_columns = 2;
    aq::AirConstraint<Fp3> selector;
    selector.name = "test.selector";
    selector.kind = aq::AirKind::kEverywhere;
    selector.alg_degree = 2;
    selector.eval =
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[1],
                gf::Sub(row[1], Fp3::One()));
        };
    cs.constraints.push_back(std::move(selector));
    return cs;
}

rc::RCStage3CtlChallenges Challenges()
{
    return {
        gf::FromU64_3(3),
        gf::FromU64_3(5),
        gf::FromU64_3(97),
        gf::FromU64_3(193)};
}

gated::SpecV1 Spec(int8_t sign)
{
    gated::SpecV1 spec;
    spec.namespace_id = 17;
    spec.stage = 9;
    spec.sign = sign;
    spec.source_column = 0;
    spec.selector_column = 1;
    spec.addresses = {0, 0, 12, 0, 0, 15, 0, 0};
    spec.challenges = Challenges();
    return spec;
}

std::vector<std::vector<Fp3>> RelationColumns()
{
    std::vector<std::vector<Fp3>> columns(
        2, std::vector<Fp3>(8, Fp3::Zero()));
    columns[0][2] = gf::FromSigned3(-11);
    columns[0][5] = gf::FromSigned3(23);
    columns[1][2] = Fp3::One();
    columns[1][5] = Fp3::One();
    return columns;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_gated_ctl_alias_tests)

BOOST_AUTO_TEST_CASE(sparse_send_receive_cancel_and_prove)
{
    const auto relation = Relation();
    const auto relation_columns = RelationColumns();
    gated::LayoutV1 send_layout;
    aq::AirConstraintSystem<Fp3> placeholder_cs;
    auto placeholder = Spec(1);
    std::string why;
    BOOST_REQUIRE(gated::BuildConstraintSystemV1(
        relation, placeholder, placeholder_cs,
        send_layout, &why));
    auto send = gated::BuildWitnessV1(
        relation_columns, placeholder, send_layout);
    BOOST_REQUIRE_MESSAGE(send.valid, send.note);

    gated::LayoutV1 recv_layout;
    aq::AirConstraintSystem<Fp3> recv_placeholder_cs;
    auto receive = Spec(-1);
    BOOST_REQUIRE(gated::BuildConstraintSystemV1(
        relation, receive, recv_placeholder_cs,
        recv_layout, &why));
    auto recv = gated::BuildWitnessV1(
        relation_columns, receive, recv_layout);
    BOOST_REQUIRE_MESSAGE(recv.valid, recv.note);
    BOOST_CHECK(gf::IsZero(gf::Add(
        send.terminal.alpha1_sum,
        recv.terminal.alpha1_sum)));
    BOOST_CHECK(gf::IsZero(gf::Add(
        send.terminal.alpha2_sum,
        recv.terminal.alpha2_sum)));

    placeholder.expected_terminal = send.terminal;
    aq::AirConstraintSystem<Fp3> send_cs;
    BOOST_REQUIRE(gated::BuildConstraintSystemV1(
        relation, placeholder, send_cs, send_layout, &why));
    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x42);
    const auto proof =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            send_cs, send.columns,
            send_layout.base_column_indices, seed);
    BOOST_REQUIRE_MESSAGE(proof.ok, proof.note);
    BOOST_REQUIRE(proof.division_exact);
    BOOST_CHECK(aq::AirQuotientVerifyRowsSplitRapSafeV2(
        send_cs, proof.proof,
        send_layout.base_column_indices, seed, &why));

    auto value_attack = proof.proof;
    BOOST_REQUIRE(!value_attack.batch.queries.empty());
    BOOST_REQUIRE(
        !value_attack.batch.queries[0].group_rows.empty());
    BOOST_REQUIRE(
        !value_attack.batch.queries[0].group_rows[0].values.empty());
    value_attack.batch.queries[0].group_rows[0].values[0] =
        gf::Add(
            value_attack.batch.queries[0].group_rows[0].values[0],
            Fp3::One());
    BOOST_CHECK(!aq::AirQuotientVerifyRowsSplitRapSafeV2(
        send_cs, value_attack,
        send_layout.base_column_indices, seed, nullptr));
}

BOOST_AUTO_TEST_CASE(rejects_selector_address_terminal_and_challenge_attacks)
{
    const auto relation = Relation();
    auto columns = RelationColumns();
    auto spec = Spec(1);
    gated::LayoutV1 layout;
    aq::AirConstraintSystem<Fp3> cs;
    std::string why;
    BOOST_REQUIRE(gated::BuildConstraintSystemV1(
        relation, spec, cs, layout, &why));
    auto witness = gated::BuildWitnessV1(columns, spec, layout);
    BOOST_REQUIRE(witness.valid);

    columns[1][3] = gf::FromU64_3(2);
    BOOST_CHECK(!gated::BuildWitnessV1(
        columns, spec, layout).valid);

    auto address_attack = spec;
    ++address_attack.addresses[2];
    const auto changed =
        gated::BuildWitnessV1(
            RelationColumns(), address_attack, layout);
    BOOST_REQUIRE(changed.valid);
    BOOST_CHECK(!gf::Eq(
        changed.terminal.alpha1_sum,
        witness.terminal.alpha1_sum));

    auto challenge_attack = spec;
    challenge_attack.challenges.alpha1 =
        gf::Add(
            challenge_attack.challenges.alpha1,
            Fp3::One());
    const auto challenged =
        gated::BuildWitnessV1(
            RelationColumns(), challenge_attack, layout);
    BOOST_REQUIRE(challenged.valid);
    BOOST_CHECK(!gf::Eq(
        challenged.terminal.alpha1_sum,
        witness.terminal.alpha1_sum));

    spec.expected_terminal = {
        gf::Add(witness.terminal.alpha1_sum, Fp3::One()),
        witness.terminal.alpha2_sum};
    BOOST_REQUIRE(gated::BuildConstraintSystemV1(
        relation, spec, cs, layout, &why));
    BOOST_CHECK_GT(
        matmul::v4::rc::air_recurse::
            CountWitnessViolationsOnH(cs, witness.columns),
        0U);
}

BOOST_AUTO_TEST_SUITE_END()
