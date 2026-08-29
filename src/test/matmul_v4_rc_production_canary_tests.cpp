// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_production_canary.h>

#include <chainparams.h>
#include <consensus/params.h>
#include <init.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_selfqual.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>
#include <vector>

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
    out.device_architecture = "sm_120";
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
        .device_architecture = "sm_120",
    };
    out.epoch = Epoch();
    out.header_nonce = 17;
    out.expected_digest = NonNullDigest(0x42);
    out.independently_reproduced = true;
    out.public_provenance = "doc/unit-test-fixture";
    out.source_revision = std::string(40, '1');
    out.source_tree_fingerprint = std::string(64, '2');
    out.harness_sha256 = std::string(64, '3');
    return out;
}

std::vector<rc::RCProductionGoldenManifestEntry> GoldenCohort()
{
    auto cuda{Golden()};
    auto metal{Golden()};
    metal.id = "unit-test-metal";
    metal.provider_class = {
        .provider_family = "metal",
        .device_architecture = "m4_class",
    };
    return {cuda, metal};
}

} // namespace

BOOST_AUTO_TEST_CASE(committed_manifest_is_a_valid_single_freeze_cohort)
{
    // This tree currently ships CUDA (+ optional Metal). That is a property
    // of *our* committed data, not of the validator: a Metal-only cohort
    // must also be structurally valid (see golden_cohort_accepts_single_family).
    const auto& manifest{rc::CommittedRCProductionGoldenManifest()};
    BOOST_REQUIRE(!manifest.empty());
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid(manifest));

    const auto& reference{manifest.front()};
    for (const auto& entry : manifest) {
        BOOST_CHECK(entry.independently_reproduced);
        BOOST_CHECK_EQUAL(entry.source_revision, reference.source_revision);
        BOOST_CHECK_EQUAL(entry.source_tree_fingerprint, reference.source_tree_fingerprint);
        BOOST_CHECK_EQUAL(entry.header_nonce, reference.header_nonce);
        BOOST_CHECK(entry.expected_digest == reference.expected_digest);
    }
}

BOOST_AUTO_TEST_CASE(data_only_manifest_parser_is_strict_and_inert)
{
    const std::string valid{
        "BTX_RC_PRODUCTION_GOLDEN_V1\n"
        "cuda-entry|cuda|sm_120|1|" + std::string(64, '1') +
        "|1|doc/evidence/corpus|" + std::string(40, '2') + "|" +
        std::string(64, '3') + "|" + std::string(64, '4') + "\n"
        "metal-entry|metal|m4_class|1|" + std::string(64, '1') +
        "|1|doc/evidence/corpus|" + std::string(40, '2') + "|" +
        std::string(64, '3') + "|" + std::string(64, '5') + "\n"};
    const auto parsed{rc::ParseRCProductionGoldenManifestData(valid)};
    BOOST_REQUIRE_EQUAL(parsed.size(), 2U);
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid(parsed));

    const std::string cuda_only{
        "BTX_RC_PRODUCTION_GOLDEN_V1\n"
        "cuda-entry|cuda|sm_120|1|" + std::string(64, '1') +
        "|1|doc/evidence/corpus|" + std::string(40, '2') + "|" +
        std::string(64, '3') + "|" + std::string(64, '4') + "\n"};
    const auto cuda_parsed{rc::ParseRCProductionGoldenManifestData(cuda_only)};
    BOOST_REQUIRE_EQUAL(cuda_parsed.size(), 1U);
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid(cuda_parsed));

    // The excluded file is converted to byte literals before this parser sees
    // it. Code-like text, extra fields, and malformed hex must only produce an
    // empty fail-closed manifest; they can never become generated C++ syntax.
    BOOST_CHECK(rc::ParseRCProductionGoldenManifestData(
        valid + "}; std::abort(); //").empty());
    std::string extra_field{valid};
    extra_field.replace(extra_field.find("|1|doc/evidence"),
                        std::string{"|1|doc/evidence"}.size(),
                        "|1|unexpected|doc/evidence");
    BOOST_CHECK(rc::ParseRCProductionGoldenManifestData(extra_field).empty());
    std::string malformed_hex{valid};
    malformed_hex[malformed_hex.find(std::string(64, '1'))] = 'z';
    BOOST_CHECK(rc::ParseRCProductionGoldenManifestData(malformed_hex).empty());
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

    // Family classification must prefer an explicit provider prefix over the
    // shared Ozaki implementation suffix. An unqualified Ozaki label is
    // ambiguous and must remain ineligible until the resolver carries a typed
    // family.
    BOOST_CHECK_EQUAL(
        rc::ProbeRCProductionProviderIdentity("metal_ozaki_mxfp4").provider_family,
        "metal");
    BOOST_CHECK_EQUAL(
        rc::ProbeRCProductionProviderIdentity("hip_ozaki_mxfp4").provider_family,
        "hip");
    const auto unqualified_ozaki{
        rc::ProbeRCProductionProviderIdentity("rc_ozaki_mxfp4")};
    BOOST_CHECK(unqualified_ozaki.provider_family.empty());
    BOOST_CHECK(!unqualified_ozaki.complete);
    BOOST_CHECK_EQUAL(unqualified_ozaki.reason, "no_device_provider");
}

BOOST_AUTO_TEST_CASE(test_canary_cannot_impersonate_a_production_family)
{
    rc::ResetRCProductionCanaryForTest();
    Consensus::Params consensus{Params().GetConsensus()};
    consensus.nMatMulRCHeight = 500'000;
    consensus.nMatMulRCProfile = 1;
    consensus.fMatMulRCUseToyDims = false;
    consensus.nMatMulV4Dimension = 4096;

    for (const std::string provider : {
             "test:cuda", "test:cuda_shim", "test:metal_shim",
             "test:hip_shim"}) {
        const auto status{rc::RunRCProductionStartupCanaryForTest(
            provider, {}, consensus, consensus.nMatMulRCHeight)};
        BOOST_CHECK(status.outcome ==
                    rc::RCProductionCanaryOutcome::ProviderNotPolicyEligible);
        BOOST_CHECK_EQUAL(
            status.reason, "test_canary_provider_resolves_to_real_family");
        BOOST_CHECK(!status.attempted);
        BOOST_CHECK(!status.activation_ready);
        std::string capability_reason;
        BOOST_CHECK(!rc::GetRCProductionProviderCapability(
            provider, {}, consensus, consensus.nMatMulRCHeight,
            &capability_reason).has_value());
        BOOST_CHECK_EQUAL(
            capability_reason, "provider_has_no_current_capability");
    }
    rc::ResetRCProductionCanaryForTest();
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

    pending = Golden();
    pending.source_revision.clear();
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

BOOST_AUTO_TEST_CASE(golden_cohort_rejects_divergent_backend)
{
    auto cohort{GoldenCohort()};
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid(cohort));
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid({cohort[0]}));
    // Metal-only is a valid cohort. Requiring CUDA here is what blocked an
    // Apple-only fork from shipping a manifest measured on its own silicon.
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid({cohort[1]}));

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
    divergent = cohort;
    divergent[1].source_revision = std::string(40, '4');
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
    divergent = cohort;
    divergent[1].source_tree_fingerprint = std::string(64, '5');
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
    divergent = cohort;
    divergent[1].harness_sha256.clear();
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
    divergent = cohort;
    divergent[1].provider_class.device_architecture = "sm_120";
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
    divergent = cohort;
    divergent[0].provider_class.device_architecture = "m4_class";
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));

    // A valid CUDA+Metal pair must not make an undefined extra family
    // production-authoritative merely because its metadata is nonempty.
    divergent = cohort;
    auto unknown{Golden()};
    unknown.id = "unit-test-unknown-family";
    unknown.provider_class = {
        .provider_family = "future_accelerator",
        .device_architecture = "future_v1",
    };
    divergent.push_back(unknown);
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid(divergent));
}

BOOST_AUTO_TEST_CASE(golden_cohort_accepts_single_family)
{
    auto cohort{GoldenCohort()};
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid({cohort[0]}));
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid({cohort[1]}));

    auto hip{Golden()};
    hip.id = "unit-test-hip";
    hip.provider_class = {
        .provider_family = "hip",
        .device_architecture = "gfx1200",
    };
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid({hip}));
    BOOST_CHECK(!rc::RCProductionGoldenManifestCohortValid({}));
}

BOOST_AUTO_TEST_CASE(build_provenance_mismatch_does_not_hide_a_valid_golden)
{
    // Provenance is advisory: a fingerprint miss must not make FindGolden
    // return null or invalidate the cohort. Runtime ExactGemm still gates.
    auto cohort{GoldenCohort()};
    BOOST_REQUIRE(rc::RCProductionGoldenManifestCohortValid(cohort));
    BOOST_CHECK(!rc::RCProductionGoldenManifestMatchesBuild(
        cohort, std::string(64, '4'), /*build_source_dirty=*/false));
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), Epoch(), cohort) != nullptr);
}

BOOST_AUTO_TEST_CASE(golden_cohort_must_match_clean_running_implementation)
{
    const auto cohort{GoldenCohort()};
    BOOST_REQUIRE(rc::RCProductionGoldenManifestCohortValid(cohort));
    BOOST_CHECK(rc::RCProductionGoldenManifestMatchesBuild(
        cohort, std::string(64, '2'), /*build_source_dirty=*/false));
    BOOST_CHECK(!rc::RCProductionGoldenManifestMatchesBuild(
        cohort, std::string(64, '2'), /*build_source_dirty=*/true));
    BOOST_CHECK(!rc::RCProductionGoldenManifestMatchesBuild(
        cohort, std::string(64, '4'), /*build_source_dirty=*/false));
    BOOST_CHECK(!rc::RCProductionGoldenManifestMatchesBuild(
        cohort, "not-a-fingerprint", /*build_source_dirty=*/false));
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

// Self-qual digest/GEMM mismatch must surface as itself on the canary and
// getmatmulinfo-style resolution snapshot — not as a generic policy refusal.
BOOST_AUTO_TEST_CASE(selfqual_digest_mismatch_surfaces_distinct_canary_reason)
{
    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    rc::ResetRCProductionCanaryForTest();

    matmul_v4::accel::ResolvedRCExactGemm fake;
    fake.requested = "cuda";
    fake.provider = "cpu";
    fake.reason = "episode_digest_mismatch_backend_vs_cpu";
    fake.policy = "ProductionPreferred";
    fake.qualification_scope = "none";
    fake.device_requested = true;
    fake.self_qualified = false;
    fake.automatic_policy_eligible = false;
    matmul_v4::accel::SetLastRCExactGemmResolutionForTest(fake);

    Consensus::Params consensus{Params().GetConsensus()};
    consensus.nMatMulRCHeight = 500'000;
    consensus.nMatMulRCProfile = 1;
    consensus.fMatMulRCUseToyDims = false;
    consensus.nMatMulV4Dimension = 4096;

    const auto status{rc::RunRCProductionStartupCanary(
        "cpu", {}, consensus, consensus.nMatMulRCHeight)};
    BOOST_CHECK(status.outcome == rc::RCProductionCanaryOutcome::DigestMismatch);
    BOOST_CHECK_EQUAL(status.reason, "episode_digest_mismatch_backend_vs_cpu");
    BOOST_CHECK_EQUAL(
        rc::RCProductionCanaryOutcomeName(status.outcome), "digest_mismatch");
    BOOST_CHECK(!status.attempted);
    BOOST_CHECK(!status.passed);
    BOOST_CHECK(!status.activation_ready);

    const auto snapshot{matmul_v4::accel::ProbeLastRCExactGemmResolution()};
    BOOST_CHECK(snapshot.resolved);
    BOOST_CHECK_EQUAL(snapshot.reason, "episode_digest_mismatch_backend_vs_cpu");
    BOOST_CHECK(!snapshot.self_qualified);

    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
}

BOOST_AUTO_TEST_CASE(selfqual_gemm_mismatch_gate_preserves_deficit_reason)
{
    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();

    matmul::v4::lt::ExactGemmBackend bad;
    bad.gemm_s8s8 = +[](const std::vector<int8_t>& /*L*/,
                        const std::vector<int8_t>& /*R*/, uint32_t rows,
                        uint32_t inner, uint32_t cols,
                        std::vector<int32_t>& out) -> bool {
        out.assign(static_cast<size_t>(rows) * cols, 0x7fff0001);
        return true;
    };
    bad.gemm_s32s8 = +[](const std::vector<int32_t>& /*L*/,
                         const std::vector<int8_t>& /*R*/, uint32_t rows,
                         uint32_t inner, uint32_t cols,
                         std::vector<int32_t>& out) -> bool {
        out.assign(static_cast<size_t>(rows) * cols, 0x7fff0001);
        return true;
    };

    const auto gated{matmul_v4::accel::GateExactGemmWithRCSelfQualCached(
        bad, "unit_test_wrong_gemm", /*epoch=*/-1)};
    BOOST_CHECK(gated.gemm_s8s8 == nullptr);

    // Resolve path must prefer the concrete deficit over the generic label.
    matmul_v4::accel::ResolvedRCExactGemm fake;
    fake.requested = "cuda";
    fake.provider = "cpu";
    fake.reason = "gemm_s8s8_mismatch_vs_cpu_exactgemm";
    fake.policy = "ProductionPreferred";
    fake.self_qualified = false;
    fake.automatic_policy_eligible = false;
    matmul_v4::accel::SetLastRCExactGemmResolutionForTest(fake);

    Consensus::Params consensus{Params().GetConsensus()};
    consensus.nMatMulRCHeight = 500'000;
    consensus.nMatMulRCProfile = 1;
    consensus.fMatMulRCUseToyDims = false;
    consensus.nMatMulV4Dimension = 4096;
    const auto status{rc::RunRCProductionStartupCanary(
        "cpu", {}, consensus, consensus.nMatMulRCHeight)};
    BOOST_CHECK(status.outcome == rc::RCProductionCanaryOutcome::DigestMismatch);
    BOOST_CHECK_EQUAL(status.reason, "gemm_s8s8_mismatch_vs_cpu_exactgemm");

    // Confirm ProbeRCSelfQual itself names the GEMM mismatch (gate input).
    const auto st{rc::ProbeRCSelfQual(bad)};
    BOOST_CHECK(!st.mining_accelerator_ok);
    BOOST_CHECK_EQUAL(st.deficit_reason, "gemm_s8s8_mismatch_vs_cpu_exactgemm");

    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
}

BOOST_AUTO_TEST_CASE(lookup_treats_unknown_class_as_absence_not_duplicate)
{
    const auto manifest{GoldenCohort()};
    auto m5{Provider()};
    m5.provider_family = "metal";
    m5.device_architecture = "m5_class";
    const auto none{rc::LookupRCProductionGolden(m5, Epoch(), manifest)};
    BOOST_CHECK(none.status == rc::RCProductionGoldenLookupStatus::None);
    BOOST_CHECK(none.entry == nullptr);

    const auto unique{rc::LookupRCProductionGolden(Provider(), Epoch(), manifest)};
    BOOST_CHECK(unique.status == rc::RCProductionGoldenLookupStatus::Unique);
    BOOST_REQUIRE(unique.entry != nullptr);
    BOOST_CHECK_EQUAL(unique.entry->id, "unit-test-only");

    const std::vector<rc::RCProductionGoldenManifestEntry> dup{Golden(), Golden()};
    const auto duplicate{rc::LookupRCProductionGolden(Provider(), Epoch(), dup)};
    BOOST_CHECK(duplicate.status == rc::RCProductionGoldenLookupStatus::Duplicate);
    BOOST_CHECK(duplicate.entry == nullptr);
}

BOOST_AUTO_TEST_CASE(committed_manifest_has_no_m5_row)
{
    const auto& committed{rc::CommittedRCProductionGoldenManifest()};
    BOOST_REQUIRE(!committed.empty());
    auto m5{Provider()};
    m5.provider_family = "metal";
    m5.device_architecture = "m5_class";
    const auto none{rc::LookupRCProductionGolden(
        m5, committed.front().epoch, committed)};
    BOOST_CHECK(none.status == rc::RCProductionGoldenLookupStatus::None);

    auto m4{m5};
    m4.device_architecture = "m4_class";
    const auto matched{rc::LookupRCProductionGolden(
        m4, committed.front().epoch, committed)};
    BOOST_CHECK(matched.status == rc::RCProductionGoldenLookupStatus::Unique);
}

BOOST_AUTO_TEST_CASE(self_qual_without_golden_row_is_admissible)
{
    rc::RCProductionGoldenLookup none;
    const auto admitted{rc::DecideRCProductionMiningAdmission(
        /*self_qualified=*/true, none, /*replay=*/nullptr)};
    BOOST_CHECK(admitted.admissible);
    BOOST_CHECK(admitted.passed);
    BOOST_CHECK(admitted.activation_ready);
    BOOST_CHECK(admitted.path == rc::RCProductionAdmissionPath::SelfQualification);
    BOOST_CHECK(admitted.outcome == rc::RCProductionCanaryOutcome::MissingGolden);
    BOOST_CHECK_EQUAL(admitted.reason, "admitted_by_self_qualification");
    BOOST_CHECK(!admitted.exact_manifest_match);
    BOOST_CHECK_EQUAL(
        rc::RCProductionAdmissionPathName(admitted.path), "self_qualification");
}

BOOST_AUTO_TEST_CASE(matching_row_with_digest_mismatch_is_not_admissible)
{
    const auto golden{Golden()};
    rc::RCProductionGoldenLookup unique;
    unique.status = rc::RCProductionGoldenLookupStatus::Unique;
    unique.entry = &golden;

    rc::RCStrictDeviceEpisodeResult replay;
    replay.outcome = rc::RCStrictDeviceEpisodeOutcome::Complete;
    replay.digest = golden.expected_digest;
    replay.acceleration.require_device = true;
    replay.acceleration.fully_accelerated = true;
    replay.acceleration.device_backend_present = true;
    replay.acceleration.device_macs = rc::TotalRCEpisodeMacs(golden.epoch.params);

    const auto matched{rc::DecideRCProductionMiningAdmission(
        /*self_qualified=*/true, unique, &replay)};
    BOOST_CHECK(matched.admissible);
    BOOST_CHECK(matched.path == rc::RCProductionAdmissionPath::ReviewedGolden);
    BOOST_CHECK(matched.exact_manifest_match);

    replay.digest = NonNullDigest(0x43);
    const auto mismatch{rc::DecideRCProductionMiningAdmission(
        /*self_qualified=*/true, unique, &replay)};
    BOOST_CHECK(!mismatch.admissible);
    BOOST_CHECK(!mismatch.passed);
    BOOST_CHECK(!mismatch.activation_ready);
    BOOST_CHECK(mismatch.path == rc::RCProductionAdmissionPath::None);
    BOOST_CHECK(mismatch.outcome == rc::RCProductionCanaryOutcome::DigestMismatch);
    BOOST_CHECK(mismatch.exact_manifest_match);
}

BOOST_AUTO_TEST_CASE(failed_self_qual_is_not_admissible_even_without_a_row)
{
    rc::RCProductionGoldenLookup none;
    const auto refused{rc::DecideRCProductionMiningAdmission(
        /*self_qualified=*/false, none, /*replay=*/nullptr)};
    BOOST_CHECK(!refused.admissible);
    BOOST_CHECK(!refused.passed);
    BOOST_CHECK(!refused.activation_ready);
    BOOST_CHECK(refused.path == rc::RCProductionAdmissionPath::None);
    BOOST_CHECK_EQUAL(refused.reason, "self_qualification_failed");
}

BOOST_AUTO_TEST_CASE(canary_admits_m5_class_without_a_manifest_row)
{
    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    rc::ResetRCProductionCanaryForTest();

    rc::RCProductionProviderIdentity m5;
    m5.provider_family = "metal";
    m5.device_architecture = "m5_class";
    m5.driver_identity = "test-osversion";
    m5.runtime_identity = "test-osrelease";
    m5.complete = true;
    m5.reason = "complete";
    rc::SetRCProductionProviderIdentityOverrideForTest(m5);

    matmul::v4::lt::ExactGemmBackend dummy;
    dummy.gemm_s8s8 = +[](const std::vector<int8_t>& /*L*/,
                          const std::vector<int8_t>& /*R*/, uint32_t rows,
                          uint32_t inner, uint32_t cols,
                          std::vector<int32_t>& out) -> bool {
        out.assign(static_cast<size_t>(rows) * cols, 0);
        return true;
    };

    matmul_v4::accel::ResolvedRCExactGemm fake;
    fake.requested = "metal";
    fake.provider = "metal_int8_exact";
    fake.reason = "generic_exactgemm_and_rc_self_qualified";
    fake.policy = "ProductionPreferred";
    fake.qualification_scope = "toy_and_scaled_medium";
    fake.device_requested = true;
    fake.self_qualified = true;
    fake.automatic_policy_eligible = true;
    fake.backend = dummy;
    matmul_v4::accel::SetLastRCExactGemmResolutionForTest(fake);

    Consensus::Params consensus{Params().GetConsensus()};
    consensus.nMatMulRCHeight = 500'000;
    consensus.nMatMulRCProfile = 1;
    consensus.fMatMulRCUseToyDims = false;
    consensus.nMatMulV4Dimension = 4096;

    const auto status{rc::RunRCProductionStartupCanary(
        "metal_int8_exact", dummy, consensus, consensus.nMatMulRCHeight)};
    BOOST_CHECK(status.outcome == rc::RCProductionCanaryOutcome::MissingGolden);
    BOOST_CHECK(status.admission_path ==
                rc::RCProductionAdmissionPath::SelfQualification);
    BOOST_CHECK_EQUAL(status.reason, "admitted_by_self_qualification");
    BOOST_CHECK(status.passed);
    BOOST_CHECK(status.activation_ready);
    BOOST_CHECK(!status.exact_manifest_match);
    BOOST_CHECK(!status.attempted);
    BOOST_CHECK_EQUAL(status.provider_identity.device_architecture, "m5_class");

    std::string capability_reason;
    BOOST_CHECK(rc::GetRCProductionProviderCapability(
        "metal_int8_exact", dummy, consensus, consensus.nMatMulRCHeight,
        &capability_reason).has_value());
    BOOST_CHECK(capability_reason.empty());

    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    rc::ResetRCProductionCanaryForTest();
}

BOOST_AUTO_TEST_SUITE_END()
