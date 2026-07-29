// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_verify.h>

#include <consensus/params.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>
#include <matmul/matmul_v4_rc_stage3_coupled.h>
#include <matmul/matmul_v4_rc_stage3_episode.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_recursive_consumption.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>
#include <matmul/matmul_v4_rc_stage3_unified_root.h>
#include <matmul/matmul_v4_rc_stage3_v5_v6_bus.h>
#include <matmul/matmul_v4_rc_stage3_v6_fs.h>
#include <matmul/matmul_v4_rc_stage3_verifier_air.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_verify_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(complete_authority_readiness_episode_and_coupled_engines)
{
    BOOST_CHECK(rc::kRCStage3MathematicalVerifierReady);
    BOOST_CHECK(rc::RCStage3EpisodeRelationsReady());
    std::string why;
    BOOST_CHECK(rc::RCStage3CoupledRelationEnginesReady(&why));
    BOOST_CHECK_EQUAL(why, "stage3:coupled:engines_ready");
    BOOST_CHECK(!rc::kRCStage3SuccinctAuthorityReady);
    BOOST_CHECK(!rc::kRCStage3RecursiveAggregationReady);
}

BOOST_AUTO_TEST_CASE(global_succinct_authority_hypotheses_are_auditable)
{
    namespace fp = rc::recursive_fixedpoint;
    namespace scheduler = rc::aggregation_scheduler;
    namespace ss = rc::soundness_scenarios;
    namespace v5v6 = rc::stage3_v5_v6_bus;
    namespace v6 = rc::stage3_v6_fs;

    const auto endpoint_audit =
        rc::CurrentRCStage3RelationEndpointCellAudit();
    BOOST_REQUIRE_EQUAL(endpoint_audit.size(), 52U);
    uint32_t relation_cells{0};
    uint32_t same_trace_aliases{0};
    uint32_t semantic_complete{0};
    uint32_t recursively_consumed{0};
    for (const auto& endpoint : endpoint_audit) {
        relation_cells += endpoint.relation_air_cell;
        same_trace_aliases += endpoint.same_trace_ctl_alias;
        semantic_complete += endpoint.semantic_relation_complete;
        recursively_consumed += endpoint.recursive_child_consumed;
    }
    BOOST_CHECK_EQUAL(relation_cells, 28U);
    BOOST_CHECK_EQUAL(same_trace_aliases, 28U);
    // Every endpoint has a local semantic proof path, but only 28 currently
    // expose proof-owned relation cells/same-trace aliases. Recursive child
    // consumption remains the authority-critical zero below.
    BOOST_CHECK_EQUAL(semantic_complete, 52U);
    BOOST_CHECK_EQUAL(recursively_consumed, 0U);

    const auto role_audit =
        rc::CurrentRCStage3RelationClosureRoleAudit();
    BOOST_REQUIRE_EQUAL(role_audit.size(), 14U);
    BOOST_CHECK_EQUAL(
        std::count_if(
            role_audit.begin(), role_audit.end(),
            [](const auto& role) { return role.role_complete; }),
        0U);

    const auto fixed_point = fp::SelectCompleteFixedPointV1();
    BOOST_REQUIRE(fixed_point.selected_v1_topology);
    BOOST_CHECK_EQUAL(fixed_point.leaf.parent_width, 2184U);
    BOOST_CHECK(fixed_point.width_fixed_point);
    BOOST_CHECK(fixed_point.trace_fixed_point);
    BOOST_CHECK(!fixed_point.complete_recursive_parent);
    BOOST_CHECK(!fp::kCompleteRecursiveFixedPointExecutable);

    BOOST_CHECK(v5v6::kNormalizedV5EightLaneExportBusExecutable);
    BOOST_CHECK(v5v6::kV5V6LiteralSameTraceAliasExecutable);
    BOOST_CHECK(!v5v6::kV6ChallengesDriveNormalizedV5Equations);
    BOOST_CHECK(!v5v6::kV5ShaTranscriptEquationsInCombinedAir);
    BOOST_CHECK(!v5v6::kV5V6CombinedAuthorityReady);
    BOOST_CHECK(v6::kV6AlgebraicTranscriptAirExecutable);
    BOOST_CHECK(v6::kV6ChildProofSourceIntegrationExecutable);
    BOOST_CHECK(!v6::kV6RecursiveAuthorityReady);

    BOOST_CHECK(
        rc::stage3_hash_air::kHashInternalSsaProvenanceExecutable);
    BOOST_CHECK(!rc::stage3_hash_air::kHashRelationsComplete);
    BOOST_CHECK(!rc::stage3_hash_air::kHashConsensusAuthority);
    BOOST_CHECK(!rc::kRCStage3GemmExtractManifestComplete);
    BOOST_CHECK(!rc::kRCStage3GemmSignedRangeAuthorityReady);
    BOOST_CHECK(!rc::kRCStage3ExtractAllTileAuthorityReady);

    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(!manifest.commitment.IsNull());
    BOOST_CHECK_EQUAL(manifest.entries.size(), 28U);
    BOOST_CHECK_EQUAL(
        manifest.relation_leaf_sites, 44'639'077'288ULL);
    BOOST_CHECK_EQUAL(
        manifest.below_root_aggregation_sites, 14'879'692'506ULL);
    BOOST_CHECK_EQUAL(
        manifest.total_proof_sites,
        ss::kSelectedProductionProofSitesV1);
    BOOST_CHECK_EQUAL(manifest.union_bound_cap, 1ULL << 36);
    BOOST_CHECK(manifest.complete_global_upper_bound_manifest_derived);
    BOOST_CHECK(!manifest.recursive_scheduler_consumes_manifest);
    BOOST_CHECK(!manifest.executable_backend_enforces_policy);
    BOOST_CHECK(
        scheduler::kProductionAggregationStructuralSchedulerExecutable);
    BOOST_CHECK(
        !scheduler::kProductionAggregationCryptographicChildConsumptionReady);
    BOOST_CHECK(
        rc::recursive_consumption::kBoundedProofAwareReceiptExecutable);
    BOOST_CHECK(
        !rc::recursive_consumption::kProductionRecursiveChildConsumptionReady);

    BOOST_CHECK(!rc::kRCFri3AlgDualFullOracleDomainSeparated);
    BOOST_CHECK(!rc::kRCFri3AlgDualIndependenceReductionReady);
    BOOST_CHECK(!rc::kRCFri3AlgDualFormalSoundnessReady);
    BOOST_CHECK(!rc::kRCStage3UnifiedCtlRelationWitnessBindingReady);
    BOOST_CHECK(!rc::kRCStage3UnifiedCtlRecursiveConsumptionReady);
    BOOST_CHECK(!rc::kRCStage3UnifiedRootExecutable);
    BOOST_CHECK(!rc::kRCStage3UnifiedRootAuthorityReady);
    BOOST_CHECK(
        !rc::stage3_verifier_air::kVerifierFiatShamirAirExecutable);
    BOOST_CHECK(
        rc::stage3_verifier_air::kVerifierProofRowsBoundInAir);
    BOOST_CHECK(
        !rc::stage3_verifier_air::kWholeVerifierWitnessExecutable);
    BOOST_CHECK(!rc::kRCStage3SuccinctAuthorityReady);
}

BOOST_AUTO_TEST_CASE(mathematical_entry_rejects_unbound_envelope)
{
    rc::RCStage3SuccinctProof proof;
    CBlockHeader header;
    Consensus::Params params;
    arith_uint256 target{1};
    std::string why;
    BOOST_CHECK(!rc::VerifyRCStage3MathematicalProof(
        proof, header, params, 0, target, &why));
    BOOST_CHECK(why.find("binding:") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
