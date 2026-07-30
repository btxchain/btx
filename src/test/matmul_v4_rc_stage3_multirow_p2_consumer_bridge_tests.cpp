// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_p2_consumer_bridge.h>

#include <algorithm>
#include <array>
#include <set>

namespace matmul::v4::rc::stage3_multirow_p2_consumer_bridge {
namespace {

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

Fri3AlgDigest D(uint64_t base)
{
    return {
        gf::FromU64(base), gf::FromU64(base + 1),
        gf::FromU64(base + 2), gf::FromU64(base + 3)};
}

tp::StatementV1 Statement()
{
    tp::StatementV1 statement;
    statement.public_fs_seed =
        *uint256::FromHex(
            "1123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef");
    statement.trace_rows = 512;
    statement.trace_columns = 5;
    statement.quotient_len = 1024;
    statement.n_coeffs = 1024;
    statement.blowup = 4;
    statement.base_column_indices = {0, 1};
    statement.groups = {{
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 2, 4096, D(10)},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 2, 3, 4096, D(20)},
        {Fri3AlgMultiRowGroupRole::Quotient, 5, 1, 4096, D(30)}}};
    statement.column_len = {1024, 1000, 900, 800, 1024, 1024};
    for (uint32_t column = 0; column < statement.column_len.size();
         ++column) {
        statement.evals_z1.push_back(U(100 + column));
        statement.evals_z2.push_back(U(200 + column));
    }
    uint32_t leaves = 4096;
    for (uint32_t fold = 0; fold < 11; ++fold) {
        statement.folds.push_back({leaves, D(1000 + 10 * fold)});
        leaves >>= 1;
    }
    statement.final_value = U(9999);
    return statement;
}

ProductV1 Product()
{
    const auto transcript = tp::BuildProductV1(Statement());
    BOOST_REQUIRE_MESSAGE(transcript.valid, transcript.note);
    return BuildProductV1(transcript);
}

std::vector<uint32_t> RowsWith(
    const ProductV1& product, uint32_t selector)
{
    std::vector<uint32_t> out;
    for (uint32_t row = 0; row < product.trace_rows; ++row) {
        if (gf::Eq(product.columns[selector][row], Fp3::One())) {
            out.push_back(row);
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_p2_consumer_bridge_tests)

BOOST_AUTO_TEST_CASE(
    exact_transcript_selection_and_consumers_close_quadratically)
{
    const auto product = Product();
    BOOST_TEST_MESSAGE(
        "bridge initial valid=" << product.valid
        << " violations=" << product.violations
        << " note=" << product.note);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_EQUAL(product.real_rows, 394U);
    BOOST_CHECK_EQUAL(product.trace_rows, 512U);
    BOOST_CHECK_LE(product.max_constraint_degree, 2U);
    BOOST_CHECK(product.transcript_receipt_verified);
    BOOST_CHECK(product.transcript_event_cells_schedule_bound);
    BOOST_CHECK(product.k2_ood_first_valid_air_constrained);
    BOOST_CHECK(product.q192_first_valid_air_constrained);
    BOOST_CHECK(product.q192_index_decomposition_canonical);
    BOOST_CHECK(product.q192_selected_index_consumer_equal);
    BOOST_CHECK(product.duplicate_queries_permitted);
    BOOST_CHECK(product.independent_coefficient_consumer_equal);
    BOOST_CHECK(product.coefficient_labels_bound);
    BOOST_CHECK(product.proof_owned_consumer_cells);
    BOOST_CHECK(!product.same_parent_event_cell_aliases);
    BOOST_CHECK(!product.backend_v11_codec_executable);
    BOOST_CHECK(!product.production_authority_ready);
    BOOST_CHECK(!product.preprocessed_row_group_root.IsNull());
    BOOST_TEST_MESSAGE(
        "multirow-consumer rows=" << product.trace_rows
        << " columns=" << product.layout.n_columns
        << " constraints=" << product.constraints
        << " duplicate_queries=" << product.duplicate_query_count);
}

BOOST_AUTO_TEST_CASE(
    free_selectors_swapped_queries_and_all_invalid_candidates_reject)
{
    const auto product = Product();
    BOOST_REQUIRE(product.valid);
    const auto first_rows =
        RowsWith(product, product.layout.candidate_first);
    BOOST_REQUIRE_EQUAL(first_rows.size(), 194U);
    {
        auto forged = product.columns;
        const uint32_t row = first_rows.front();
        forged[product.layout.candidate_selected][row] = Fp3::Zero();
        forged[product.layout.candidate_selected][row + 1] = Fp3::Zero();
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
    {
        auto forged = product.columns;
        const auto query_rows =
            RowsWith(product, product.layout.query_active);
        BOOST_REQUIRE_EQUAL(query_rows.size(), 384U);
        for (uint32_t offset = 0; offset < 2; ++offset) {
            std::swap(
                forged[product.layout.consumer_index][query_rows[offset]],
                forged[product.layout.consumer_index][query_rows[2 + offset]]);
        }
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
    {
        auto forged = product.columns;
        const uint32_t row = first_rows.front();
        forged[product.layout.candidate_valid][row] = Fp3::Zero();
        forged[product.layout.candidate_valid][row + 1] = Fp3::Zero();
        forged[product.layout.candidate_selected][row] = Fp3::Zero();
        forged[product.layout.candidate_selected][row + 1] = Fp3::Zero();
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    duplicate_queries_are_valid_but_coefficient_relabel_is_not)
{
    const auto product = Product();
    BOOST_REQUIRE(product.valid);
    // With-replacement duplicates are neither rejected nor silently
    // deduplicated. This fixed transcript normally contains several.
    BOOST_CHECK(product.duplicate_queries_permitted);
    BOOST_CHECK_LE(product.duplicate_query_count, tp::kQueriesV1);
    {
        auto forged = product.columns;
        const auto coefficient_rows =
            RowsWith(product, product.layout.coefficient_active);
        BOOST_REQUIRE_GE(coefficient_rows.size(), 2U);
        std::swap(
            forged[product.layout.consumer_value][coefficient_rows[0]],
            forged[product.layout.consumer_value][coefficient_rows[1]]);
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
    {
        auto forged = product.columns;
        const auto coefficient_rows =
            RowsWith(product, product.layout.coefficient_active);
        std::swap(
            forged[product.layout.consumer_index][coefficient_rows[0]],
            forged[product.layout.consumer_index][coefficient_rows[1]]);
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    canonical_decomposition_rejects_goldilocks_x_plus_p_alias)
{
    constexpr uint64_t x = 5;
    const auto honest =
        AuditCanonicalRawV1(gf::FromU64(x), x);
    BOOST_REQUIRE(honest.valid);
    const auto aliased =
        AuditCanonicalRawV1(
            gf::FromU64(x), x + gf::kP);
    BOOST_CHECK(!aliased.valid);
    BOOST_CHECK_GT(aliased.violations, 0U);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_p2_consumer_bridge
