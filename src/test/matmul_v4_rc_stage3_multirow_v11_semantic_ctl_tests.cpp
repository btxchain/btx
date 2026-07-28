// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_ctl.h>

#include <hash.h>

#include <algorithm>

namespace {

namespace ctl =
    matmul::v4::rc::multirow_v11_semantic_ctl;
namespace gf = matmul::v4::rc::gkr_field;

uint256 StatementRoot(uint32_t tag = 1)
{
    HashWriter hash;
    hash << std::string(
        "BTX_RC_STAGE3_MULTIROW_V11_SEMANTIC_CTL_TEST");
    hash << tag;
    return hash.GetHash();
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_semantic_ctl_tests)

BOOST_AUTO_TEST_CASE(
    exact_inventory_and_fail_closed_coverage)
{
    const uint256 statement = StatementRoot();
    const auto cells =
        ctl::BuildDeterministicEndpointCellsV1();
    const auto product =
        ctl::BuildProductV1(statement, cells);
    BOOST_REQUIRE_MESSAGE(
        product.valid_foundation, product.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ctl::ValidateProductV1(
            product, statement, &why),
        why);

    BOOST_CHECK_EQUAL(
        product.canonical_program_families, 28U);
    BOOST_CHECK_EQUAL(
        product.represented_endpoints, 52U);
    BOOST_CHECK_EQUAL(
        product.exact_consumer_endpoints, 52U);
    BOOST_CHECK_EQUAL(
        product.selected_program_endpoints, 52U);
    BOOST_CHECK_EQUAL(
        product.proof_owned_export_endpoints, 28U);
    BOOST_CHECK_EQUAL(
        product.dual_logup_endpoint_pairs, 52U);
    BOOST_CHECK_EQUAL(
        product.recursively_consumed_endpoints, 0U);
    BOOST_CHECK_EQUAL(product.represented_roles, 14U);
    BOOST_CHECK_EQUAL(product.complete_roles, 0U);
    BOOST_CHECK_EQUAL(product.endpoints.size(), 52U);
    BOOST_CHECK_EQUAL(product.roles.size(), 14U);
    BOOST_CHECK_EQUAL(product.cs.n_rows, 128U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.commitments_before_challenges);
    BOOST_CHECK(product.canonical_ali_inventory);
    BOOST_CHECK(
        product.independent_domain_separated_lanes);
    BOOST_CHECK(
        product.all_endpoint_pairs_algebraically_constrained);
    BOOST_CHECK(
        !product.tuple_commitments_recursively_bound);
    BOOST_CHECK(!product.all_sources_proof_owned);
    BOOST_CHECK(!product.recursive_consumption_complete);
    BOOST_CHECK(!product.production_authority);

    uint32_t residuals = 0;
    uint32_t exact_aliases = 0;
    constexpr uint32_t kLocalAliasResiduals =
        ctl::ResidualNoCanonicalOutputV1 |
        ctl::ResidualNoRelationAirCellV1 |
        ctl::ResidualNoSameTraceCtlAliasV1;
    for (const auto& endpoint : product.endpoints) {
        BOOST_CHECK(endpoint.represented);
        BOOST_CHECK(endpoint.exact_consumer);
        BOOST_CHECK(endpoint.selected_program);
        BOOST_CHECK(endpoint.dual_logup_constrained);
        BOOST_CHECK(!endpoint.recursively_consumed);
        BOOST_CHECK(
            endpoint.residual_mask &
            ctl::ResidualNoRecursiveCtlConsumptionV1);
        BOOST_CHECK(!endpoint.residual.empty());
        if (endpoint.literal_proof_owned_export) {
            BOOST_CHECK_EQUAL(
                endpoint.residual_mask &
                    kLocalAliasResiduals,
                0U);
        } else {
            // A non-alias must retain a concrete local ownership blocker;
            // recursive-consumption absence alone cannot explain it.
            BOOST_CHECK_NE(
                endpoint.residual_mask &
                    kLocalAliasResiduals,
                0U);
        }
        residuals += !endpoint.literal_proof_owned_export;
        exact_aliases +=
            endpoint.literal_proof_owned_export;
    }
    BOOST_CHECK_EQUAL(residuals, 24U);
    BOOST_CHECK_EQUAL(exact_aliases, 28U);
}

BOOST_AUTO_TEST_CASE(
    omission_duplication_reorder_and_role_swap_reject)
{
    const uint256 statement = StatementRoot();
    const auto canonical =
        ctl::BuildDeterministicEndpointCellsV1();

    auto omitted = canonical;
    omitted.pop_back();
    BOOST_CHECK(
        !ctl::BuildProductV1(
             statement, omitted).valid_foundation);

    auto duplicate = canonical;
    duplicate[1] = duplicate[0];
    BOOST_CHECK(
        !ctl::BuildProductV1(
             statement, duplicate).valid_foundation);

    auto reordered = canonical;
    std::swap(reordered[0], reordered[1]);
    BOOST_CHECK(
        !ctl::BuildProductV1(
             statement, reordered).valid_foundation);

    auto role_swap = canonical;
    role_swap[0].role = canonical.back().role;
    BOOST_CHECK(
        !ctl::BuildProductV1(
             statement, role_swap).valid_foundation);
}

BOOST_AUTO_TEST_CASE(
    consumer_value_and_temporal_reorder_break_dual_logup)
{
    const uint256 statement = StatementRoot();
    auto cells =
        ctl::BuildDeterministicEndpointCellsV1();
    cells[7].consumer_words[3] ^= 1U;
    const auto mismatch =
        ctl::BuildProductV1(statement, cells);
    BOOST_CHECK(!mismatch.valid_foundation);
    BOOST_CHECK_GT(mismatch.violations, 0U);

    const auto canonical = ctl::BuildProductV1(
        statement,
        ctl::BuildDeterministicEndpointCellsV1());
    BOOST_REQUIRE(canonical.valid_foundation);
    auto reordered = canonical;
    std::swap(
        reordered.columns[reordered.layout.value_base][2],
        reordered.columns[reordered.layout.value_base][4]);
    BOOST_CHECK_GT(
        ctl::CountAirViolationsV1(
            reordered.cs, reordered.columns),
        0U);
}

BOOST_AUTO_TEST_CASE(
    statement_and_program_root_substitution_reject)
{
    const uint256 statement = StatementRoot(1);
    const auto product = ctl::BuildProductV1(
        statement,
        ctl::BuildDeterministicEndpointCellsV1());
    BOOST_REQUIRE(product.valid_foundation);
    std::string why;
    BOOST_CHECK(
        !ctl::ValidateProductV1(
            product, StatementRoot(2), &why));

    auto program_root = product;
    program_root.columns[
        program_root.layout.program_external_base][0] =
        gf::Add(
            program_root.columns[
                program_root.layout
                    .program_external_base][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        ctl::CountAirViolationsV1(
            program_root.cs, program_root.columns),
        0U);
    BOOST_CHECK(
        !ctl::ValidateProductV1(
            program_root, statement, &why));

    auto ali_root = product;
    ali_root.columns[
        ali_root.layout.ali_compiled_program_base][0] =
        gf::Add(
            ali_root.columns[
                ali_root.layout
                    .ali_compiled_program_base][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        ctl::CountAirViolationsV1(
            ali_root.cs, ali_root.columns),
        0U);
    BOOST_CHECK(
        !ctl::ValidateProductV1(
            ali_root, statement, &why));
}

BOOST_AUTO_TEST_CASE(
    raw_x_plus_p_and_non_u32_values_reject_before_field_reduction)
{
    const uint256 statement = StatementRoot();
    auto source =
        ctl::BuildDeterministicEndpointCellsV1();
    source[0].source_words[0] = gf::kP + 1U;
    const auto source_product =
        ctl::BuildProductV1(statement, source);
    BOOST_CHECK(!source_product.valid_foundation);
    BOOST_CHECK(
        source_product.note.find(
            "source_noncanonical_u32") !=
        std::string::npos);

    auto consumer =
        ctl::BuildDeterministicEndpointCellsV1();
    consumer[0].consumer_words[0] =
        uint64_t{UINT32_MAX} + 1U;
    const auto consumer_product =
        ctl::BuildProductV1(statement, consumer);
    BOOST_CHECK(!consumer_product.valid_foundation);
    BOOST_CHECK(
        consumer_product.note.find(
            "consumer_noncanonical_u32") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    bit_decomposition_blocks_extension_or_limb_forgery)
{
    const uint256 statement = StatementRoot();
    const auto canonical = ctl::BuildProductV1(
        statement,
        ctl::BuildDeterministicEndpointCellsV1());
    BOOST_REQUIRE(canonical.valid_foundation);

    auto limb = canonical;
    limb.columns[limb.layout.value_base][0] =
        gf::Add(
            limb.columns[limb.layout.value_base][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        ctl::CountAirViolationsV1(
            limb.cs, limb.columns),
        0U);

    auto bit = canonical;
    bit.columns[bit.layout.value_bits_base][0] =
        gf::Fp3::FromFp(2);
    BOOST_CHECK_GT(
        ctl::CountAirViolationsV1(
            bit.cs, bit.columns),
        0U);

    auto extension = canonical;
    extension.columns[extension.layout.value_base][0].c1 =
        1;
    BOOST_CHECK_GT(
        ctl::CountAirViolationsV1(
            extension.cs, extension.columns),
        0U);
}

BOOST_AUTO_TEST_SUITE_END()
