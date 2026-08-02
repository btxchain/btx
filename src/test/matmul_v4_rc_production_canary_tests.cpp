// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_production_canary.h>

#include <chainparams.h>
#include <consensus/params.h>
#include <init.h>
#include <matmul/exact_gemm_resolve.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_production_canary_tests, BasicTestingSetup)

namespace {

uint256 NonNullDigest(unsigned char marker)
{
    uint256 out;
    out.data()[0] = marker;
    return out;
}

rc::RCProductionProviderIdentity Provider()
{
    rc::RCProductionProviderIdentity out;
    out.provider_family = "cuda";
    out.device_architecture = "sm_test";
    out.driver_identity = "12080";
    out.runtime_identity = "12080";
    out.complete = true;
    out.reason = "complete";
    return out;
}

rc::RCProductionEpochIdentity Epoch()
{
    rc::RCProductionEpochIdentity out;
    out.activation_height = 500'000;
    out.profile = 1;
    out.transcript_version = rc::kRCTranscriptVersion;
    out.matmul_dimension = 4096;
    out.params = rc::MakeToyRCEpisodeParams();
    return out;
}

rc::RCProductionGoldenManifestEntry Golden()
{
    rc::RCProductionGoldenManifestEntry out;
    out.id = "unit-test-only";
    out.provider_class = {
        .provider_family = "cuda",
        .device_architecture = "sm_test",
    };
    out.epoch = Epoch();
    out.header_nonce = 17;
    out.expected_digest = NonNullDigest(0x42);
    out.independently_reproduced = true;
    out.public_provenance = "doc/unit-test-fixture";
    return out;
}

std::vector<rc::RCProductionGoldenManifestEntry> GoldenCohort()
{
    auto cuda{Golden()};
    auto metal{Golden()};
    metal.id = "unit-test-metal";
    metal.provider_class = {
        .provider_family = "metal",
        .device_architecture = "m4_test",
    };
    return {cuda, metal};
}

} // namespace

BOOST_AUTO_TEST_CASE(committed_manifest_contains_reviewed_cuda_metal_goldens)
{
    const auto& manifest{rc::CommittedRCProductionGoldenManifest()};
    BOOST_REQUIRE_EQUAL(manifest.size(), 2U);
    BOOST_CHECK_EQUAL(manifest[0].provider_class.provider_family, "cuda");
    BOOST_CHECK_EQUAL(manifest[1].provider_class.provider_family, "metal");
    BOOST_CHECK_EQUAL(manifest[0].expected_digest.GetHex(),
                      manifest[1].expected_digest.GetHex());
    BOOST_CHECK(manifest[0].independently_reproduced);
    BOOST_CHECK(manifest[1].independently_reproduced);
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid(manifest));
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) == nullptr);
}

BOOST_AUTO_TEST_CASE(parameter_interaction_is_accelerator_runtime_probe_free)
{
    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    rc::ResetRCProductionCanaryForTest();
    BOOST_REQUIRE(AppInitParameterInteraction(*m_node.args));

    const auto resolution{
        matmul_v4::accel::ProbeLastRCExactGemmResolution()};
    const auto canary{rc::GetLastRCProductionCanaryStatus()};
    BOOST_CHECK(!resolution.resolved);
    BOOST_CHECK(canary.outcome == rc::RCProductionCanaryOutcome::NotRun);
    BOOST_CHECK(!canary.attempted);
    BOOST_CHECK(CheckMatMulAcceleratorPreForkInvariant());
}

BOOST_AUTO_TEST_CASE(prefork_guard_rejects_an_early_canary_attempt)
{
    rc::ResetRCProductionCanaryForTest();
    Consensus::Params consensus{Params().GetConsensus()};
    consensus.nMatMulRCHeight = 500'000;
    consensus.nMatMulRCProfile = 1;
    consensus.fMatMulRCUseToyDims = false;
    consensus.nMatMulV4Dimension = 4096;

    const auto status{rc::RunRCProductionStartupCanaryForTest(
        "test:unsupported_provider", {},
        consensus, consensus.nMatMulRCHeight)};
    BOOST_CHECK(status.outcome != rc::RCProductionCanaryOutcome::NotRun);
    BOOST_CHECK(!CheckMatMulAcceleratorPreForkInvariant());
    rc::ResetRCProductionCanaryForTest();
    BOOST_CHECK(CheckMatMulAcceleratorPreForkInvariant());
}

BOOST_AUTO_TEST_CASE(provider_identity_probe_is_public_and_fail_closed)
{
    const auto unknown{rc::ProbeRCProductionProviderIdentity("unsupported_provider")};
    BOOST_CHECK(!unknown.complete);
    BOOST_CHECK_EQUAL(unknown.reason, "provider_runtime_identity_unavailable");

    const auto metal{rc::ProbeRCProductionProviderIdentity("metal_int8_exact")};
#if defined(__APPLE__)
    BOOST_CHECK_MESSAGE(metal.complete, metal.reason);
    BOOST_CHECK_EQUAL(metal.provider_family, "metal");
    BOOST_CHECK(!metal.device_architecture.empty());
    BOOST_CHECK(!metal.driver_identity.empty());
    BOOST_CHECK(!metal.runtime_identity.empty());
#else
    BOOST_CHECK(!metal.complete);
    BOOST_CHECK_EQUAL(metal.reason, "provider_runtime_identity_unavailable");
#endif
}

BOOST_AUTO_TEST_CASE(manifest_match_binds_provider_class_and_workload)
{
    const auto manifest{GoldenCohort()};
    BOOST_REQUIRE(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) != nullptr);

    auto provider{Provider()};
    provider.runtime_identity = "12090";
    BOOST_CHECK(rc::FindRCProductionGolden(provider, Epoch(), manifest) != nullptr);
    BOOST_CHECK(!rc::RCProductionProviderIdentityMatches(Provider(), provider));
    provider = Provider();
    provider.device_architecture = "sm_other";
    BOOST_CHECK(!rc::RCProductionProviderIdentityMatches(Provider(), provider));
    BOOST_CHECK(rc::FindRCProductionGolden(provider, Epoch(), manifest) == nullptr);

    auto epoch{Epoch()};
    ++epoch.activation_height;
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), epoch, manifest) == nullptr);
    auto height_independent{GoldenCohort()};
    for (auto& entry : height_independent) {
        entry.epoch.activation_height =
            rc::RCProductionEpochIdentity::ANY_ACTIVATION_HEIGHT;
    }
    BOOST_CHECK(rc::FindRCProductionGolden(
        Provider(), epoch, height_independent) != nullptr);
    epoch = Epoch();
    ++epoch.matmul_dimension;
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), epoch, manifest) == nullptr);
    epoch = Epoch();
    ++epoch.params.b_seq;
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), epoch, manifest) == nullptr);
}

BOOST_AUTO_TEST_CASE(epoch_identity_copies_and_validates_consensus_dimension)
{
    Consensus::Params consensus{Params().GetConsensus()};
    consensus.nMatMulRCProfile = 1;
    consensus.fMatMulRCUseToyDims = false;
    consensus.nMatMulV4Dimension = 4096;
    const auto epoch{rc::MakeRCProductionEpochIdentity(consensus, 500'000)};
    BOOST_CHECK_EQUAL(epoch.matmul_dimension, 4096U);

    consensus.nMatMulV4Dimension =
        static_cast<uint32_t>(std::numeric_limits<uint16_t>::max()) + 1U;
    const auto status{rc::RunRCProductionStartupCanaryForTest(
        "test:unsupported_provider", {},
        consensus, 500'000)};
    BOOST_CHECK(status.outcome == rc::RCProductionCanaryOutcome::UnsupportedEpoch);
    BOOST_CHECK_EQUAL(status.reason,
                      "production_matmul_dimension_out_of_header_range");
    BOOST_CHECK(!status.attempted);
    BOOST_CHECK(!status.activation_ready);
    rc::ResetRCProductionCanaryForTest();
}

BOOST_AUTO_TEST_CASE(pending_or_unreviewed_manifest_entries_never_authorize)
{
    auto pending{Golden()};
    pending.expected_digest.SetNull();
    std::vector<rc::RCProductionGoldenManifestEntry> manifest{pending};
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) == nullptr);

    pending = Golden();
    pending.independently_reproduced = false;
    manifest = {pending};
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) == nullptr);

    pending = Golden();
    pending.public_provenance.clear();
    manifest = {pending};
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) == nullptr);

    pending = Golden();
    pending.public_provenance = "/local-only/private-result.json";
    manifest = {pending};
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) == nullptr);
}

BOOST_AUTO_TEST_CASE(duplicate_exact_manifest_authority_fails_closed)
{
    const auto golden{Golden()};
    const std::vector<rc::RCProductionGoldenManifestEntry> manifest{
        golden, golden};
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) == nullptr);
}

BOOST_AUTO_TEST_CASE(golden_cohort_rejects_missing_or_divergent_backend)
{
    auto cohort{GoldenCohort()};
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid(cohort));
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid({cohort[0]}));

    auto divergent{cohort};
    divergent[1].expected_digest = NonNullDigest(0x43);
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
    divergent = cohort;
    ++divergent[1].header_nonce;
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
    divergent = cohort;
    ++divergent[1].epoch.params.b_seq;
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
    divergent = cohort;
    divergent[1].provider_class = divergent[0].provider_class;
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
}

BOOST_AUTO_TEST_CASE(canary_result_requires_full_device_coverage_and_exact_digest)
{
    const auto golden{Golden()};
    rc::RCStrictDeviceEpisodeResult replay;
    replay.outcome = rc::RCStrictDeviceEpisodeOutcome::Complete;
    replay.digest = golden.expected_digest;
    replay.acceleration.require_device = true;
    replay.acceleration.fully_accelerated = true;
    replay.acceleration.device_backend_present = true;
    replay.acceleration.device_macs = rc::TotalRCEpisodeMacs(golden.epoch.params);
    BOOST_CHECK(rc::EvaluateRCProductionCanaryResult(golden, replay) ==
                rc::RCProductionCanaryOutcome::Passed);

    ++replay.acceleration.cpu_fallbacks;
    BOOST_CHECK(rc::EvaluateRCProductionCanaryResult(golden, replay) ==
                rc::RCProductionCanaryOutcome::LocalAcceleratorFailure);
    --replay.acceleration.cpu_fallbacks;
    replay.digest = NonNullDigest(0x43);
    BOOST_CHECK(rc::EvaluateRCProductionCanaryResult(golden, replay) ==
                rc::RCProductionCanaryOutcome::DigestMismatch);
}

BOOST_AUTO_TEST_CASE(canary_header_is_deterministic_and_nonce_bound)
{
    const auto epoch{Epoch()};
    const CBlockHeader a{rc::MakeRCProductionCanaryHeader(epoch, 11)};
    const CBlockHeader b{rc::MakeRCProductionCanaryHeader(epoch, 11)};
    const CBlockHeader c{rc::MakeRCProductionCanaryHeader(epoch, 12)};
    auto other_dimension{epoch};
    ++other_dimension.matmul_dimension;
    const CBlockHeader d{
        rc::MakeRCProductionCanaryHeader(other_dimension, 11)};
    BOOST_CHECK(a.GetHash() == b.GetHash());
    BOOST_CHECK(a.GetHash() != c.GetHash());
    BOOST_CHECK(a.GetHash() != d.GetHash());
    BOOST_CHECK_EQUAL(a.nNonce64, 11U);
    BOOST_CHECK_EQUAL(a.matmul_dim, epoch.matmul_dimension);
    BOOST_CHECK_EQUAL(d.matmul_dim, other_dimension.matmul_dimension);
    BOOST_CHECK(!a.seed_a.IsNull());
    BOOST_CHECK(!a.seed_b.IsNull());

    auto unsupported_epoch{epoch};
    unsupported_epoch.matmul_dimension =
        static_cast<uint32_t>(std::numeric_limits<uint16_t>::max()) + 1U;
    const CBlockHeader unsupported{
        rc::MakeRCProductionCanaryHeader(unsupported_epoch, 11)};
    BOOST_CHECK_EQUAL(unsupported.matmul_dim, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
