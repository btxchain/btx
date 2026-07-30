// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_production_vertical_canary.h>
#include <test/util/setup_common.h>

#include <consensus/params.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3_canonical_parent_production_verifier.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_coupled_winner_capture.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_universal_topology.h>
#include <pow.h>
#include <primitives/block.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>

namespace {

namespace rc = matmul::v4::rc;
namespace canary = rc::production_vertical_canary;
namespace ut = rc::universal_topology;

CBlock BaseBlock()
{
    CBlock out;
    out.nVersion = 4;
    out.nTime = 1;
    // Canonical maximum-width compact target. The vertical lifecycle is not a
    // stochastic mining test, so its deterministic winner must always satisfy
    // the target predicate without repeating the expensive workloads.
    out.nBits = 0x2100ffffU;
    out.nNonce = 7;
    out.nNonce64 = 7;
    out.matmul_dim = 256;
    out.seed_a = uint256{
        "00000000000000000000000000000000"
        "00000000000000000000000000000011"};
    out.seed_b = uint256{
        "00000000000000000000000000000000"
        "00000000000000000000000000000022"};
    return out;
}

Consensus::Params Params()
{
    Consensus::Params out;
    out.fMatMulPOW = true;
    out.nMatMulV4Height = 1;
    out.nMatMulRCHeight = 1;
    out.nMatMulRCProfile = 2;
    out.fMatMulRCUseToyDims = true;
    out.nMatMulV4Dimension = 256;
    out.nMatMulRCCoupledHeight = 1;
    out.nMatMulRCCoupledProfile = 3;
    out.fMatMulRCCoupledUseToyDims = true;
    out.powLimit = uint256{
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"};

    return out;
}

void PinDiagnosticRegistry(
    const CBlock& block,
    int32_t height,
    Consensus::Params& params)
{
    const auto assessment =
        rc::canonical_parent_production_verifier::
            AssessFrozenBinaryParentSpecV1(
                block, params, height);
    const auto pin =
        ut::BuildProductionProgramConsensusPinV1(
            assessment.registry.diagnostic_registry);
    params.hashMatMulRCStage3ProgramRegistryAlgRoot =
        pin.recursive_alg_hash_root;
    params.hashMatMulRCStage3ProgramRegistryShaAuditRoot =
        pin.external_sha256d_audit_root;
    params.hashMatMulRCStage3ProgramRegistryBinding =
        pin.registry_binding;
}

struct CapturedWinner {
    CBlock block;
    std::shared_ptr<rc::RCStage3EpisodeWitnessCapture>
        episode;
    std::shared_ptr<rc::RCStage3CoupledWinnerCaptureV1>
        coupled;
    uint32_t episode_workload_calls{0};
    uint32_t coupled_workload_calls{0};
};

CapturedWinner CaptureWinner(
    const Consensus::Params& params,
    int32_t height)
{
    CapturedWinner out;
    out.block = BaseBlock();
    const auto episode_params =
        rc::ResolveRCEpisodeParams(params, height);
    const auto coupled_params =
        rc::ResolveRCCoupParams(params);
    const auto coupled_options =
        rc::ResolveRCCoupOptions(params);

    // The proof-aware mining calls below ARE the primary computations.  There
    // is no preliminary Mine/Recompute call and no post-winner exact replay.
    out.episode = std::make_shared<
        rc::RCStage3EpisodeWitnessCapture>(
            episode_params);
    ++out.episode_workload_calls;
    const uint256 episode_digest =
        rc::MineRCEpisodeWithProofWitness(
            out.block, episode_params, height,
            *out.episode);
    BOOST_REQUIRE(!episode_digest.IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        out.episode->Complete(&why), why);

    out.coupled = std::make_shared<
        rc::RCStage3CoupledWinnerCaptureV1>(
            out.block, height, coupled_params,
            coupled_options);
    ++out.coupled_workload_calls;
    const uint256 coupled_digest =
        rc::MineCoupledPuzzleWithProofWitness(
            out.block, height, coupled_params,
            *out.coupled, {}, coupled_options);
    BOOST_REQUIRE(!coupled_digest.IsNull());
    out.block.matmul_digest =
        rc::ComputeRCStage3ComposedWorkDigest(
            out.block, params, height,
            episode_digest, coupled_digest);
    BOOST_REQUIRE(!out.block.matmul_digest.IsNull());
    BOOST_REQUIRE_MESSAGE(
        out.coupled->FinalizeHeaderBindingV2(
            out.block, coupled_digest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        out.coupled->Complete(&why), why);
    return out;
}

uint256 Target(
    const CBlock& block,
    const Consensus::Params& params)
{
    const auto target =
        DeriveTarget(block.nBits, params.powLimit);
    BOOST_REQUIRE(target.has_value());
    return ArithToUint256(*target);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_production_vertical_canary_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(
    missing_callback_inventory_fails_before_any_proof_attachment)
{
    constexpr int32_t height = 1;
    auto params = Params();
    const CBlock block = BaseBlock();
    PinDiagnosticRegistry(block, height, params);
    const uint256 target = Target(block, params);
    rc::InitializeRCStage3ProductionProofProvider();
    rc::RCStage3EpisodeWitnessStoreClearForTest();
    rc::RCStage3CoupledWinnerStoreClearForTestV1();

    canary::ReportV1 report;
    std::string why;
    BOOST_CHECK(
        !canary::ExecuteV1(
            block, params, height, target,
            report, &why));
    BOOST_CHECK(
        report.reached ==
        canary::StageV1::RequestChecked);
    BOOST_CHECK(
        report.failure ==
        canary::FailureV1::EpisodeCaptureMissing);
    BOOST_CHECK(block.matrix_c_data.empty());
    BOOST_CHECK(
        why.find("episode_capture_missing") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    winner_callbacks_reach_the_first_real_parent_closure_blocker)
{
    constexpr int32_t height = 1;
    auto params = Params();
    PinDiagnosticRegistry(BaseBlock(), height, params);
    rc::InitializeRCStage3ProductionProofProvider();
    rc::RCStage3EpisodeWitnessStoreClearForTest();
    rc::RCStage3CoupledWinnerStoreClearForTestV1();

    const CapturedWinner winner =
        CaptureWinner(params, height);
    BOOST_CHECK_EQUAL(
        winner.episode_workload_calls, 1U);
    BOOST_CHECK_EQUAL(
        winner.coupled_workload_calls, 1U);
    const uint256 target =
        Target(winner.block, params);
    const uint256 winner_key =
        winner.block.GetHash();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::RCStage3EpisodeWitnessStorePut(
            winner_key, winner.episode, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::RCStage3CoupledWinnerStorePutV1(
            winner_key, winner.coupled, &why),
        why);

    canary::ReportV1 report;
    BOOST_CHECK(
        !canary::ExecuteV1(
            winner.block, params, height,
            target, report, &why));
    BOOST_CHECK_MESSAGE(
        report.reached ==
            canary::StageV1::HeaderStatementRebuilt,
        why);
    BOOST_CHECK(report.episode_capture_complete);
    BOOST_CHECK(report.coupled_capture_complete);
    BOOST_CHECK_MESSAGE(
        report.header_statement_rebuilt, why);
    BOOST_CHECK_MESSAGE(
        report.failure ==
            canary::FailureV1::ReceiptBuildOrAttach,
        why);
    BOOST_CHECK_MESSAGE(
        report.produce_status ==
            rc::RCStage3ProduceStatus::ProverFailed,
        why);
    BOOST_CHECK_MESSAGE(
        why.find(
            "recursive_semantic_child_consumption_open") !=
            std::string::npos,
        why);
    BOOST_CHECK(winner.block.matrix_c_data.empty());

    // A complete, valid capture is bound to the finalized header. Moving only
    // the lookup key to another header cannot advance the canary.
    CBlock changed = winner.block;
    ++changed.nNonce64;
    const uint256 changed_key = changed.GetHash();
    rc::RCStage3EpisodeWitnessStoreClearForTest();
    rc::RCStage3CoupledWinnerStoreClearForTestV1();
    BOOST_REQUIRE_MESSAGE(
        rc::RCStage3EpisodeWitnessStorePut(
            changed_key, winner.episode, &why),
        why);
    BOOST_CHECK(
        !rc::RCStage3CoupledWinnerStorePutV1(
            changed_key, winner.coupled, &why));
    BOOST_CHECK(
        why.find("winner_store_incomplete") !=
        std::string::npos);
    BOOST_CHECK(changed.matrix_c_data.empty());

    rc::RCStage3EpisodeWitnessStoreClearForTest();
    rc::RCStage3CoupledWinnerStoreClearForTestV1();
}

BOOST_AUTO_TEST_SUITE_END()
