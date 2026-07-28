// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>

namespace composer =
    matmul::v4::rc::stage3_air_parent_composer;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_air_parent_composer_tests)

namespace {

using Cs = aq::AirConstraintSystem<gf::Fp3>;
using Columns = std::vector<std::vector<gf::Fp3>>;

gf::Fp3 U(uint64_t value)
{
    return gf::Fp3::FromFp(gf::FromU64(value));
}

std::pair<Cs, Columns> FirstChild()
{
    Cs cs;
    cs.n_rows = 8;
    cs.n_columns = 2;
    Columns columns(2, std::vector<gf::Fp3>(8, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < 8; ++row) {
        columns[0][row] = U(row);
        columns[1][row] = U(row + 1);
    }
    cs.preprocessed.push_back({0, columns[0]});
    aq::AirConstraint<gf::Fp3> relation;
    relation.name = "first.successor";
    relation.kind = aq::AirKind::kEverywhere;
    relation.alg_degree = 1;
    relation.eval =
        [](const auto& current, const auto&) {
            return gf::Sub(
                current[1], gf::Add(current[0], gf::Fp3::One()));
        };
    cs.constraints.push_back(std::move(relation));
    return {std::move(cs), std::move(columns)};
}

std::pair<Cs, Columns> SecondChild()
{
    Cs cs;
    cs.n_rows = 8;
    cs.n_columns = 1;
    Columns columns(1, std::vector<gf::Fp3>(8, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < 8; ++row) {
        columns[0][row] = U(10 + row);
    }
    aq::AirConstraint<gf::Fp3> relation;
    relation.name = "second.transition";
    relation.kind = aq::AirKind::kTransition;
    relation.alg_degree = 1;
    relation.eval =
        [](const auto& current, const auto& next) {
            return gf::Sub(
                next[0], gf::Add(current[0], gf::Fp3::One()));
        };
    cs.constraints.push_back(std::move(relation));
    return {std::move(cs), std::move(columns)};
}

uint256 Seed()
{
    uint256 out;
    out.begin()[0] = 0x91;
    out.begin()[31] = 0x37;
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(horizontal_parent_proves_and_maps_literal_columns)
{
    auto [a_cs, a_columns] = FirstChild();
    auto [b_cs, b_columns] = SecondChild();
    Cs parent;
    Columns columns;
    composer::ChildAttachmentV1 a;
    composer::ChildAttachmentV1 b;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        composer::AppendChildV1(
            parent, columns, a_cs, a_columns, 0, a, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        composer::AppendChildV1(
            parent, columns, b_cs, b_columns, 1, b, &why),
        why);
    BOOST_CHECK_EQUAL(a.column_base, 0U);
    BOOST_CHECK_EQUAL(a.ParentColumn(1), 1U);
    BOOST_CHECK_EQUAL(b.column_base, 2U);
    BOOST_CHECK_EQUAL(b.ParentColumn(0), 2U);
    BOOST_REQUIRE_EQUAL(parent.n_columns, 3U);
    BOOST_REQUIRE_EQUAL(columns.size(), 3U);
    BOOST_REQUIRE_EQUAL(parent.preprocessed.size(), 1U);
    BOOST_CHECK_EQUAL(parent.preprocessed[0].first, 0U);

    const auto proof =
        aq::AirQuotientProve<gf::Fp3>(parent, columns, Seed());
    BOOST_REQUIRE_MESSAGE(proof.ok, proof.note);
    BOOST_REQUIRE(proof.division_exact);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerify<gf::Fp3>(
            parent, proof.proof, Seed(), &why),
        why);

    auto forged = columns;
    forged[b.ParentColumn(0)][3] =
        gf::Add(forged[b.ParentColumn(0)][3], gf::Fp3::One());
    aq::AirProveOptions force;
    force.force_commit_on_inexact = true;
    const auto forged_proof =
        aq::AirQuotientProve<gf::Fp3>(
            parent, forged, Seed(), force);
    BOOST_REQUIRE_MESSAGE(forged_proof.ok, forged_proof.note);
    BOOST_REQUIRE(!forged_proof.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerify<gf::Fp3>(
            parent, forged_proof.proof, Seed(), &why));
}

BOOST_AUTO_TEST_CASE(rejects_stale_row_group_roots_and_row_mismatch)
{
    auto [a_cs, a_columns] = FirstChild();
    auto [b_cs, b_columns] = SecondChild();
    aq::AirPreprocessedRowGroupRoot stale;
    stale.ordered_columns = {0};
    stale.root = Seed();
    b_cs.preprocessed_row_group_roots.push_back(stale);

    Cs parent;
    Columns columns;
    composer::ChildAttachmentV1 attachment;
    std::string why;
    BOOST_REQUIRE(
        composer::AppendChildV1(
            parent, columns, a_cs, a_columns, 0,
            attachment, &why));
    BOOST_CHECK(
        !composer::AppendChildV1(
            parent, columns, b_cs, b_columns, 1,
            attachment, &why));
    BOOST_CHECK_EQUAL(
        why,
        "stage3:air_parent_composer_v1:"
        "row_group_root_requires_global_rebuild");

    b_cs.preprocessed_row_group_roots.clear();
    b_cs.n_rows = 4;
    b_columns[0].resize(4);
    BOOST_CHECK(
        !composer::AppendChildV1(
            parent, columns, b_cs, b_columns, 1,
            attachment, &why));
    BOOST_CHECK_EQUAL(
        why,
        "stage3:air_parent_composer_v1:row_count_mismatch");
}

BOOST_AUTO_TEST_CASE(exact_row_lift_preserves_boundaries_and_rejects_padding)
{
    auto [child_cs, child_columns] = FirstChild();
    child_cs.n_rows = 4;
    for (auto& column : child_columns) column.resize(4);
    child_cs.preprocessed[0].second.resize(4);

    Cs parent;
    Columns columns;
    composer::ChildAttachmentV1 attachment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        composer::AppendChildLiftedV1(
            parent, columns, child_cs, child_columns,
            16, 0, attachment, &why),
        why);
    BOOST_CHECK(attachment.row_lifted);
    BOOST_CHECK(attachment.padding_zero_constrained);
    BOOST_CHECK_EQUAL(attachment.semantic_child_columns, 2U);
    BOOST_CHECK_EQUAL(attachment.column_count, 9U);
    BOOST_CHECK_EQUAL(parent.n_rows, 16U);

    const auto honest =
        aq::AirQuotientProve<gf::Fp3>(parent, columns, Seed());
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    BOOST_REQUIRE(honest.division_exact);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerify<gf::Fp3>(
            parent, honest.proof, Seed(), &why),
        why);

    auto forged = columns;
    forged[attachment.ParentColumn(1)][9] = U(123);
    aq::AirProveOptions force;
    force.force_commit_on_inexact = true;
    const auto forged_proof =
        aq::AirQuotientProve<gf::Fp3>(
            parent, forged, Seed(), force);
    BOOST_REQUIRE_MESSAGE(forged_proof.ok, forged_proof.note);
    BOOST_REQUIRE(!forged_proof.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerify<gf::Fp3>(
            parent, forged_proof.proof, Seed(), &why));
}

BOOST_AUTO_TEST_CASE(row_lift_preserves_cyclic_next_on_child_last_row)
{
    Cs child;
    child.n_rows = 4;
    child.n_columns = 1;
    Columns child_columns(
        1, std::vector<gf::Fp3>(4, U(5)));
    aq::AirConstraint<gf::Fp3> cyclic;
    cyclic.name = "cyclic.next";
    cyclic.kind = aq::AirKind::kEverywhere;
    cyclic.alg_degree = 1;
    cyclic.eval =
        [](const auto& current, const auto& next) {
            return gf::Sub(next[0], current[0]);
        };
    child.constraints.push_back(std::move(cyclic));

    Cs parent;
    Columns columns;
    composer::ChildAttachmentV1 attachment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        composer::AppendChildLiftedV1(
            parent, columns, child, child_columns,
            16, 0, attachment, &why),
        why);
    const auto proof =
        aq::AirQuotientProve<gf::Fp3>(
            parent, columns, Seed());
    BOOST_REQUIRE_MESSAGE(proof.ok, proof.note);
    BOOST_REQUIRE(proof.division_exact);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerify<gf::Fp3>(
            parent, proof.proof, Seed(), &why),
        why);
}

BOOST_AUTO_TEST_SUITE_END()
