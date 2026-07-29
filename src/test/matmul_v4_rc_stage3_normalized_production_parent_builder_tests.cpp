// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_normalized_parent_external_producer_equality.h>
#include <matmul/matmul_v4_rc_stage3_normalized_production_parent_builder.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <test/util/setup_common.h>

#include <string>

namespace {

namespace rc = matmul::v4::rc;
namespace builder =
    rc::normalized_production_parent_builder;
namespace eq =
    rc::normalized_parent_external_producer_equality;
namespace fp = rc::recursive_fixedpoint;

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_normalized_production_parent_builder_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(
    status_names_include_built_and_fail_closed_variants)
{
    BOOST_CHECK_EQUAL(
        builder::ProductionParentBuildStatusNameV1(
            builder::ProductionParentBuildStatusV1::Built),
        "built");
    BOOST_CHECK_EQUAL(
        builder::ProductionParentBuildStatusNameV1(
            builder::ProductionParentBuildStatusV1::
                CompleteRelationParentUnavailable),
        "complete_relation_parent_unavailable");
    BOOST_CHECK_EQUAL(
        builder::ProductionParentBuildStatusNameV1(
            builder::ProductionParentBuildStatusV1::
                InvalidRequest),
        "invalid_request");
}

BOOST_AUTO_TEST_CASE(
    living_role_audit_measures_complete_under_recursive_children)
{
    BOOST_REQUIRE(
        rc::kRCStage3RelationClosureRecursiveChildrenExecutable);
    BOOST_REQUIRE(fp::kCompleteRecursiveFixedPointExecutable);
    BOOST_CHECK(!rc::kRCStage3RelationClosureAuthorityReady);
    BOOST_CHECK(!fp::kRecursiveFixedPointConsensusAuthority);

    const auto audit =
        rc::CurrentRCStage3RelationClosureRoleAudit();
    BOOST_REQUIRE_EQUAL(audit.size(), 14U);
    for (const auto& role : audit) {
        BOOST_CHECK(role.recursive_ctl_consumption);
        BOOST_CHECK(role.role_complete);
        BOOST_CHECK_EQUAL(
            role.proof_derived_ctl_endpoints,
            role.required_endpoints);
    }

    const auto cells =
        rc::CurrentRCStage3RelationEndpointCellAudit();
    BOOST_REQUIRE_EQUAL(cells.size(), 52U);
    uint16_t consumed = 0;
    for (const auto& cell : cells) {
        consumed += cell.recursive_child_consumed ? 1 : 0;
    }
    BOOST_CHECK_EQUAL(consumed, 52U);
}

BOOST_AUTO_TEST_CASE(
    build_for_solved_block_rejects_invalid_request_fail_closed)
{
    builder::ProductionParentBuildInputV1 input;
    builder::consumer::CanonicalRelationParentProductV1 product;
    std::string why;
    const auto status =
        builder::BuildForSolvedBlockV1(
            input, product, &why);
    BOOST_CHECK(
        status ==
        builder::ProductionParentBuildStatusV1::
            InvalidRequest);
    BOOST_CHECK(
        why.find("request") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    built_requires_equality_certificate_premises_after_role_audit)
{
    // Built is the conjunction of RoleAudit (closed above) + streaming
    // role-export equality certificate + NAV3 conversion.  Without a
    // streaming receipt, Assess stays fail-closed — the same residual that
    // keeps production_authority false on the candidate path.
    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            nullptr, nullptr, &why);
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_CHECK(!assessment.residuals.empty());
    BOOST_CHECK(
        assessment.residuals.front().find(
            "streaming_episode_closure_receipt_missing") !=
        std::string::npos);
    BOOST_CHECK(
        why.find("streaming_receipt_missing") !=
        std::string::npos);

    // Authority / ExactReplay stay fail-closed independently of Built.
    BOOST_CHECK(!rc::kRCStage3RelationClosureAuthorityReady);
    BOOST_CHECK(!fp::kRecursiveFixedPointConsensusAuthority);
}

BOOST_AUTO_TEST_SUITE_END()
