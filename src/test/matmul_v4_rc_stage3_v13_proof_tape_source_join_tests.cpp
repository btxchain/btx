// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_proof_tape_source_join.h>

namespace join =
    matmul::v4::rc::stage3_v13_proof_tape_source_join;
namespace derived =
    matmul::v4::rc::stage3_v13_derived_hash_air;
namespace selection =
    matmul::v4::rc::stage3_v13_selection_query_air;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_proof_tape_source_join_tests)

namespace {

uint256 Seed(uint32_t tag)
{
    uint256 out;
    for (uint32_t index = 0;
         index < out.size(); ++index) {
        out.data()[index] =
            static_cast<unsigned char>(
                (tag + 29U * index) & 0xffU);
    }
    if (out.IsNull()) out.data()[0] = 1;
    return out;
}

tape::PublicBindingV1 Binding()
{
    tape::PublicBindingV1 out;
    out.program_root = Seed(0x10);
    out.statement_root = Seed(0x20);
    out.public_fs_seed = Seed(0x30);
    out.proof_wire_root = Seed(0x40);
    out.tape_root = {
        gf::FromU64(11), gf::FromU64(13),
        gf::FromU64(17), gf::FromU64(19)};
    return out;
}

join::ProofV1 Prove(
    const join::BoundedCanaryProductV1& product,
    const uint256& seed,
    const aq::AirProveOptions& options = {})
{
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            product.cs, product.columns,
            product.r0_base_column_indices,
            seed, options,
            options.force_commit_on_inexact
                ? nullptr
                : &product.r0_session);
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    join::ProofV1 out;
    out.plan_root = product.plan.plan_root;
    out.r0_row_root =
        rc::Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root);
    out.proof = proved.proof;
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    verifier_rebuild_maps_every_derived_and_q2_selection_source)
{
    tape::PublicShapeV1 shape;
    shape.trace_rows = 8;
    shape.trace_columns = 4;
    shape.quotient_len = 8;
    shape.n_coeffs = 8;
    shape.base_column_indices = {0, 1};
    const auto binding = Binding();
    const auto tape_schedule =
        tape::BuildScheduleV1(shape, binding);
    BOOST_REQUIRE_MESSAGE(
        tape_schedule.valid,
        tape_schedule.note);
    const uint32_t tape_columns =
        tape::CanonicalLayoutV1().End();
    const uint32_t derived_columns =
        derived::CanonicalLayoutV1().End();
    const uint32_t selection_columns =
        selection::LayoutV1{}.End();
    join::PlanV1 plan;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::BuildCanonicalPlanV1(
            shape, binding,
            shape.n_coeffs *
                rc::kRCFriBlowup,
            2,
            tape_schedule.trace_rows,
            0,
            tape_columns,
            tape_columns + derived_columns,
            plan, &why),
        why);
    BOOST_CHECK(plan.valid);
    BOOST_CHECK(plan.exact_tape_schedule);
    BOOST_CHECK(plan.exact_derived_schedule);
    BOOST_CHECK(plan.exact_selection_schedule);
    BOOST_CHECK(plan.all_tape_addresses_mapped);
    BOOST_CHECK(plan.exact_multiset_cardinality);
    BOOST_CHECK_GT(
        plan.derived_limb_relations, 0U);
    BOOST_CHECK_EQUAL(
        plan.selected_z_relations, 6U);
    BOOST_CHECK_EQUAL(
        plan.query_index_relations, 2U);
    BOOST_CHECK_EQUAL(
        plan.sources.size(),
        plan.consumers.size());
    BOOST_CHECK_EQUAL(
        plan.selection_column_offset +
            selection_columns,
        tape_columns +
            derived_columns +
            selection_columns);
    BOOST_CHECK(
        join::ValidateCanonicalPlanV1(
            shape, binding,
            plan.n_lde,
            plan.query_count,
            plan, &why));

    auto changed = plan;
    ++changed.consumers.front().address;
    BOOST_CHECK(
        !join::ValidateCanonicalPlanV1(
            shape, binding,
            plan.n_lde,
            plan.query_count,
            changed, &why));
}

BOOST_AUTO_TEST_CASE(
    bounded_relation_proves_and_forged_source_cell_rejects)
{
    const uint256 seed = Seed(0x7413);
    const join::BoundedCanaryStatementV1 statement;
    join::BoundedCanaryProductV1 product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::BuildBoundedCanaryProductV1(
            statement,
            {UINT32_C(0x12345678),
             UINT32_C(0x90abcdef)},
            seed, product, &why),
        why);
    BOOST_REQUIRE(product.valid);
    BOOST_CHECK(product.exact_production_equations);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_EQUAL(
        product.plan.sources.size(), 2U);
    BOOST_CHECK_EQUAL(
        product.plan.consumers.size(), 2U);

    const join::ProofV1 honest =
        Prove(product, seed);
    BOOST_REQUIRE_MESSAGE(
        join::VerifyBoundedCanaryV1(
            statement, seed,
            honest, &why),
        why);

    auto forged_columns = product.columns;
    const auto& source =
        product.plan.sources.front();
    forged_columns[source.value_cell.column]
        [source.value_cell.row] =
            gf::Add(
                forged_columns[
                    source.value_cell.column]
                    [source.value_cell.row],
                gf::Fp3::One());
    BOOST_REQUIRE_GT(
        join::CountViolationsV1(
            product.cs, forged_columns),
        0U);
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    auto forged_product = product;
    forged_product.columns =
        std::move(forged_columns);
    const join::ProofV1 forged =
        Prove(
            forged_product, seed,
            adversarial);
    BOOST_CHECK_MESSAGE(
        !join::VerifyBoundedCanaryV1(
            statement, seed,
            forged, &why),
        why);
}

BOOST_AUTO_TEST_SUITE_END()
