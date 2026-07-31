// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_production_canary.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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
    out.driver_api_version = 12080;
    out.runtime_version = 12080;
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
    out.params = rc::MakeToyRCEpisodeParams();
    return out;
}

rc::RCProductionGoldenManifestEntry Golden()
{
    rc::RCProductionGoldenManifestEntry out;
    out.id = "unit-test-only";
    out.provider = Provider();
    out.epoch = Epoch();
    out.header_nonce = 17;
    out.expected_digest = NonNullDigest(0x42);
    out.independently_reproduced = true;
    out.public_provenance = "doc/unit-test-fixture";
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(committed_manifest_is_explicitly_fail_closed)
{
    const auto& manifest{rc::CommittedRCProductionGoldenManifest()};
    BOOST_CHECK(manifest.empty());
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) == nullptr);
}

BOOST_AUTO_TEST_CASE(manifest_match_binds_provider_runtime_and_epoch)
{
    const std::vector<rc::RCProductionGoldenManifestEntry> manifest{Golden()};
    BOOST_REQUIRE(rc::FindRCProductionGolden(Provider(), Epoch(), manifest) != nullptr);

    auto provider{Provider()};
    ++provider.runtime_version;
    BOOST_CHECK(rc::FindRCProductionGolden(provider, Epoch(), manifest) == nullptr);
    provider = Provider();
    provider.device_architecture = "sm_other";
    BOOST_CHECK(!rc::RCProductionProviderIdentityMatches(Provider(), provider));
    BOOST_CHECK(rc::FindRCProductionGolden(provider, Epoch(), manifest) == nullptr);

    auto epoch{Epoch()};
    ++epoch.activation_height;
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), epoch, manifest) == nullptr);
    epoch = Epoch();
    ++epoch.params.b_seq;
    BOOST_CHECK(rc::FindRCProductionGolden(Provider(), epoch, manifest) == nullptr);
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
    const CBlockHeader a{rc::MakeRCProductionCanaryHeader(11)};
    const CBlockHeader b{rc::MakeRCProductionCanaryHeader(11)};
    const CBlockHeader c{rc::MakeRCProductionCanaryHeader(12)};
    BOOST_CHECK(a.GetHash() == b.GetHash());
    BOOST_CHECK(a.GetHash() != c.GetHash());
    BOOST_CHECK_EQUAL(a.nNonce64, 11U);
    BOOST_CHECK(!a.seed_a.IsNull());
    BOOST_CHECK(!a.seed_b.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
