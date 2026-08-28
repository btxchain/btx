// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_rc_accel_policy.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <matmul/matmul_v4_rc_production_canary.h>

#include <chainparams.h>
#include <init.h>
#include <util/chaintype.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <cstdint>
#include <limits>
#include <string>

namespace rc = matmul::v4::rc;
namespace dc = matmul::v4::rc::dc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_accel_policy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rc_accel_policy_default_is_production_preferred)
{
    BOOST_CHECK(rc::RCAccelerationPolicy::NativeRequired !=
                rc::RCAccelerationPolicy::PortableExplicit);
    BOOST_CHECK(rc::RCAccelerationPolicy::ProductionPreferred !=
                rc::RCAccelerationPolicy::NativeRequired);
    // Default is the production-safe dense-INT8-first policy.
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(rc::kRCAccelerationPolicyDefault),
                      static_cast<uint8_t>(rc::RCAccelerationPolicy::ProductionPreferred));
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCAccelerationPolicy::NativeRequired)},
                      "NativeRequired");
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCAccelerationPolicy::PortableExplicit)},
                      "PortableExplicit");
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCAccelerationPolicy::ProductionPreferred)},
                      "ProductionPreferred");
}

BOOST_AUTO_TEST_CASE(rc_accel_policy_resolve_default_and_env_overrides)
{
    const char* prev = std::getenv("BTX_RC_ACCEL_POLICY");
    // Unset → ProductionPreferred (default).
    unsetenv("BTX_RC_ACCEL_POLICY");
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(rc::ResolveRCAccelerationPolicy()),
                      static_cast<uint8_t>(rc::RCAccelerationPolicy::ProductionPreferred));
    // Explicit opt-in overrides both directions.
    setenv("BTX_RC_ACCEL_POLICY", "native", /*overwrite=*/1);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(rc::ResolveRCAccelerationPolicy()),
                      static_cast<uint8_t>(rc::RCAccelerationPolicy::NativeRequired));
    setenv("BTX_RC_ACCEL_POLICY", "portable", /*overwrite=*/1);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(rc::ResolveRCAccelerationPolicy()),
                      static_cast<uint8_t>(rc::RCAccelerationPolicy::PortableExplicit));
    if (prev != nullptr) {
        setenv("BTX_RC_ACCEL_POLICY", prev, /*overwrite=*/1);
    } else {
        unsetenv("BTX_RC_ACCEL_POLICY");
    }
}

/** NativeRequired must not fall through to dense device INT8 when Ozaki MXFP4
 *  is unqualified. Empty gemm_s8s8 ⇒ CPU ExactGemm.
 *  A5/F12: resolver runs SelfQualify before consulting the latch, so a fresh
 *  process selects the qualified lane when silicon qualifies. */
BOOST_AUTO_TEST_CASE(rc_native_required_resolver_order_qual_before_latch)
{
    const char* prev = std::getenv("BTX_RC_ACCEL_POLICY");
    setenv("BTX_RC_ACCEL_POLICY", "native", /*overwrite=*/1); // NativeRequired is opt-in now
    BOOST_REQUIRE_EQUAL(static_cast<uint8_t>(rc::ResolveRCAccelerationPolicy()),
                        static_cast<uint8_t>(rc::RCAccelerationPolicy::NativeRequired));

    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    rc::ResetRcOzakiQualForTest();

    // Fresh latch (post-reset): unqualified until SelfQualify runs.
    BOOST_CHECK(!rc::IsRcOzakiMxfp4Qualified());

    const auto backend = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
    // Resolver must have consulted after qualification: backend tracks latch.
    const bool qualified = rc::IsRcOzakiMxfp4Qualified();
    if (qualified) {
        BOOST_CHECK_MESSAGE(backend.gemm_s8s8 != nullptr,
                            "fresh-process resolver must select qualified native lane");
    } else {
        BOOST_CHECK_MESSAGE(backend.gemm_s8s8 == nullptr,
                            "NativeRequired must decline dense INT8 when Ozaki unqualified");
    }

    if (prev != nullptr) {
        setenv("BTX_RC_ACCEL_POLICY", prev, /*overwrite=*/1);
    } else {
        unsetenv("BTX_RC_ACCEL_POLICY");
    }
}

/** Legacy name retained: CPU-only hosts stay empty; GPU hosts covered above. */
BOOST_AUTO_TEST_CASE(rc_native_required_empty_gemm_when_ozaki_unqualified)
{
    const char* prev = std::getenv("BTX_RC_ACCEL_POLICY");
    setenv("BTX_RC_ACCEL_POLICY", "native", /*overwrite=*/1); // NativeRequired is opt-in now
    BOOST_REQUIRE_EQUAL(static_cast<uint8_t>(rc::ResolveRCAccelerationPolicy()),
                        static_cast<uint8_t>(rc::RCAccelerationPolicy::NativeRequired));

    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    rc::ResetRcOzakiQualForTest();
    (void)rc::SelfQualifyRcOzakiMxfp4Once();

    if (rc::IsRcOzakiMxfp4Qualified()) {
        // GPU-BOX with linked SM120a: resolver selects native; covered by order test.
        const auto backend = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
        BOOST_CHECK(backend.gemm_s8s8 != nullptr);
    } else {
        BOOST_REQUIRE_MESSAGE(!rc::IsRcOzakiMxfp4Qualified(),
                              "expected Ozaki MXFP4 unqualified on this host");
        const auto backend = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
        BOOST_CHECK_MESSAGE(backend.gemm_s8s8 == nullptr,
                            "NativeRequired must decline dense INT8 inject when Ozaki "
                            "unqualified (empty ExactGemmBackend)");
    }

    if (prev != nullptr) {
        setenv("BTX_RC_ACCEL_POLICY", prev, /*overwrite=*/1);
    } else {
        unsetenv("BTX_RC_ACCEL_POLICY");
    }
}

/** DEFAULT (ProductionPreferred) follows the same exact-gated dense resolver as
 *  PortableExplicit and does not even qualify the correctness-only native lane.
 *  This assertion is hardware-independent, including on an SM120a-linked build. */
BOOST_AUTO_TEST_CASE(rc_production_preferred_default_admits_device_like_portable)
{
    const char* prev = std::getenv("BTX_RC_ACCEL_POLICY");
    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    rc::ResetRcOzakiQualForTest();
    unsetenv("BTX_RC_ACCEL_POLICY"); // ProductionPreferred (default)
    const auto def = matmul_v4::accel::ResolveExactGemmBackendForRC();
    BOOST_CHECK_MESSAGE(
        !rc::IsRcOzakiMxfp4Qualified(),
        "automatic production resolution must not run correctness-only native qual");

    setenv("BTX_RC_ACCEL_POLICY", "portable", /*overwrite=*/1); // PortableExplicit
    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    const auto portable = matmul_v4::accel::ResolveExactGemmBackendForRC();
    BOOST_CHECK_EQUAL(def.backend.gemm_s8s8 == nullptr,
                      portable.backend.gemm_s8s8 == nullptr);
    BOOST_CHECK_EQUAL(def.provider, portable.provider);
    BOOST_CHECK_EQUAL(def.automatic_policy_eligible, def.self_qualified);
    BOOST_CHECK(!portable.automatic_policy_eligible);
    BOOST_CHECK(!def.production_eligible);
    BOOST_CHECK(!portable.production_eligible);
    if (prev != nullptr) {
        setenv("BTX_RC_ACCEL_POLICY", prev, /*overwrite=*/1);
    } else {
        unsetenv("BTX_RC_ACCEL_POLICY");
    }
}

BOOST_AUTO_TEST_CASE(rc_production_policy_separates_correctness_from_eligibility)
{
    using Family = rc::RCBackendFamily;
    using Policy = rc::RCAccelerationPolicy;
    BOOST_CHECK(!rc::kRcOzakiMxfp4ProductionEligible);

    // Both implementations are mathematically correct. The automatic policy
    // still selects dense INT8 while native lacks reviewed production evidence.
    BOOST_CHECK(rc::SelectRCBackendFamily(
                    Policy::ProductionPreferred,
                    /*native_correct=*/true,
                    /*native_production_eligible=*/false,
                    /*dense_int8_correct=*/true) == Family::DenseInt8);

    // NativeRequired remains an explicit experimental/measurement opt-in.
    BOOST_CHECK(rc::SelectRCBackendFamily(
                    Policy::NativeRequired, true, false, true) ==
                Family::NativeMxfp4);

    // PortableExplicit remains a dense diagnostic and never selects native.
    BOOST_CHECK(rc::SelectRCBackendFamily(
                    Policy::PortableExplicit, true, true, true) ==
                Family::DenseInt8);
    BOOST_CHECK(rc::SelectRCBackendFamily(
                    Policy::PortableExplicit, true, true, false) ==
                Family::CpuReference);

    // A future reviewed eligibility decision is explicit in the policy input
    // and may make the competitive native lane the automatic choice.
    BOOST_CHECK(rc::SelectRCBackendFamily(
                    Policy::ProductionPreferred, true, true, true) ==
                Family::NativeMxfp4);
}

BOOST_AUTO_TEST_CASE(rc_coup_consensus_config_defaults_ai_production)
{
    const rc::RCCoupConsensusConfig cfg = rc::MakeDefaultRCCoupConsensusConfig();
    BOOST_CHECK(!rc::IsRCCoupConsensusConfigV1Compatible(cfg));
    BOOST_CHECK_EQUAL(cfg.config_version, rc::kRCCoupConsensusConfigVersionV3);
    const rc::RCCoupParams prod = rc::MakeProductionV3RCCoupParams();
    BOOST_CHECK_EQUAL(cfg.barriers, prod.barriers);
    BOOST_CHECK_EQUAL(cfg.lobes, prod.lobes);
    BOOST_CHECK_EQUAL(cfg.lobe_width, prod.lobe_width);
    BOOST_CHECK_EQUAL(cfg.bank_pages, prod.bank_pages);
    BOOST_CHECK_EQUAL(cfg.rows_per_lobe, prod.rows_per_lobe);
    BOOST_CHECK_EQUAL(cfg.pages_per_barrier_lobe, prod.pages_per_barrier_lobe);
    BOOST_CHECK_EQUAL(cfg.page_selection_version, rc::kRCCoupPageSelectionFullBankV3);
    BOOST_CHECK(cfg.full_bank_schedule_enabled);
    BOOST_CHECK(cfg.material_exchange_enabled);
    BOOST_CHECK_EQUAL(cfg.material_exchange_rows, rc::MakeV3RCCoupOptions().exchange_rows);
    BOOST_CHECK_EQUAL(cfg.material_exchange_rounds, rc::MakeV3RCCoupOptions().exchange_rounds);
    BOOST_CHECK(cfg.v3_profile_enabled);
    BOOST_CHECK_EQUAL(cfg.v3_activation_height, std::numeric_limits<int32_t>::max());
    // Aggregate default {} is fully V3, incl. the coupled domain family.
    BOOST_CHECK_EQUAL(cfg.transcript_version, rc::ENC_RC_V3);

    const rc::RCCoupParams mapped = rc::RCCoupParamsFromConsensusConfig(cfg);
    BOOST_CHECK(rc::ValidateRCCoupParams(mapped));
    BOOST_CHECK_EQUAL(mapped.rows_per_lobe, prod.rows_per_lobe);
    BOOST_CHECK_EQUAL(mapped.pages_per_barrier_lobe, prod.pages_per_barrier_lobe);

    const rc::RCCoupOptions options = rc::RCCoupOptionsFromConsensusConfig(cfg);
    BOOST_CHECK(options.full_bank_schedule);
    BOOST_CHECK(options.material_exchange);
    BOOST_CHECK_EQUAL(options.exchange_rows, 128u);
    BOOST_CHECK_EQUAL(options.exchange_rounds, 4u);
    // V3 config maps the V3 coupled domain tags (no V1/V2 field left behind).
    BOOST_CHECK_EQUAL(options.transcript_version, rc::ENC_RC_V3);
}

BOOST_AUTO_TEST_CASE(rc_coup_consensus_config_legacy_v1_compatible)
{
    const rc::RCCoupConsensusConfig cfg = rc::MakeLegacyV1RCCoupConsensusConfig();
    BOOST_CHECK(rc::IsRCCoupConsensusConfigV1Compatible(cfg));

    const rc::RCCoupParams toy = rc::MakeToyRCCoupParams();
    BOOST_CHECK_EQUAL(cfg.config_version, rc::kRCCoupConsensusConfigVersionV1);
    BOOST_CHECK_EQUAL(cfg.barriers, toy.barriers);
    BOOST_CHECK_EQUAL(cfg.lobes, toy.lobes);
    BOOST_CHECK_EQUAL(cfg.lobe_width, toy.lobe_width);
    BOOST_CHECK_EQUAL(cfg.bank_pages, toy.bank_pages);
    BOOST_CHECK_EQUAL(cfg.pages_per_barrier_lobe, 1u);
    BOOST_CHECK_EQUAL(cfg.page_selection_version, rc::kRCCoupPageSelectionLegacyV1);
    BOOST_CHECK(!cfg.material_exchange_enabled);
    BOOST_CHECK_EQUAL(cfg.material_exchange_rounds, 0u);
    BOOST_CHECK(!cfg.full_bank_schedule_enabled);
    BOOST_CHECK(!cfg.v3_profile_enabled);
}

BOOST_AUTO_TEST_CASE(rc_exactness_qual_cache_key_stable)
{
    const std::string key = rc::BuildExactnessQualCacheKey(
        "cuda", "sm_120", "12.8", "nvcc-12.8", "cublaslt-12.8", /*profile_version=*/1,
        "M8192xK8192xN8192", rc::kRCMxPackedLayoutVersionV1);
    BOOST_CHECK_EQUAL(key, "cuda|sm_120|12.8|nvcc-12.8|cublaslt-12.8|1|M8192xK8192xN8192|1");

    const std::string other = rc::BuildExactnessQualCacheKey(
        "cuda", "sm_100", "12.8", "nvcc-12.8", "cublaslt-12.8", 1, "M8192xK8192xN8192",
        rc::kRCMxPackedLayoutVersionV1);
    BOOST_CHECK(key != other);
}

BOOST_AUTO_TEST_CASE(rc_compute_lane_ids_distinct)
{
    BOOST_CHECK(rc::RCComputeLaneId::NativeMxfp4 != rc::RCComputeLaneId::DenseInt8Legacy);
    BOOST_CHECK(rc::RCComputeLaneId::NativeFp8 != rc::RCComputeLaneId::PortableReference);
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCComputeLaneId::NativeMxfp4)},
                      "NativeMxfp4");
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCComputeLaneId::DenseInt8Legacy)},
                      "DenseInt8Legacy");
}

BOOST_AUTO_TEST_CASE(rc_profile1_activation_readiness_requires_runtime_canary)
{
    // The committed corpus is now present, which is the point of this case:
    // a populated manifest is NECESSARY but NOT SUFFICIENT. No provider becomes
    // ready until the exact runtime identity also passes its startup canary on
    // the actual device. Previously this asserted the manifest was empty, which
    // made the case pass for the wrong reason -- readiness was false because
    // there were no goldens at all, not because the canary gates it.
    BOOST_CHECK(!rc::CommittedRCProductionGoldenManifest().empty());
    BOOST_CHECK(rc::RCProductionGoldenManifestCohortValid(
        rc::CommittedRCProductionGoldenManifest()));
    const auto canary{rc::GetLastRCProductionCanaryStatus()};
    // No canary has run in this process, so nothing is authorized regardless.
    BOOST_CHECK(!canary.manifest_has_reviewed_goldens);
    BOOST_CHECK(!canary.passed);
    BOOST_CHECK(!canary.activation_ready);

    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    const auto unresolved{
        matmul_v4::accel::ProbeLastRCExactGemmResolution()};
    BOOST_CHECK(!unresolved.resolved);
    BOOST_CHECK(!unresolved.production_goldens_available);
    BOOST_CHECK(!unresolved.startup_canary_passed);
    BOOST_CHECK(!unresolved.activation_ready);

    const auto resolved{
        matmul_v4::accel::ResolveExactGemmBackendForRC()};
    const auto snapshot{
        matmul_v4::accel::ProbeLastRCExactGemmResolution()};
    BOOST_CHECK(snapshot.resolved);
    BOOST_CHECK_EQUAL(snapshot.requested, resolved.requested);
    BOOST_CHECK_EQUAL(snapshot.provider, resolved.provider);
    BOOST_CHECK_EQUAL(snapshot.reason, resolved.reason);
    BOOST_CHECK_EQUAL(snapshot.self_qualified,
                      resolved.self_qualified);
    BOOST_CHECK(!snapshot.production_goldens_available);
    BOOST_CHECK(!snapshot.startup_canary_passed);
    BOOST_CHECK(!snapshot.activation_ready);
}

// The -matmulrcexecution default decides whether a node will quietly accept an
// unusable CPU ExactReplay path on an activated network. It is resolved inside
// AppInitParameterInteraction, which the unit and functional harnesses execute
// too, so an over-broad rule here is a process-wide policy change rather than a
// node policy change -- exactly how a first attempt at this turned every
// ExactReplay in the suite into a local-execution failure. Pin the table.
BOOST_AUTO_TEST_CASE(rc_execution_default_is_activation_aware_and_test_safe)
{
    ArgsManager empty;

    // Mainnet carries a finite RC activation height, so the default fails
    // closed: no silent CPU replay behind a live consensus rule.
    const auto main{CreateChainParams(empty, ChainType::MAIN)};
    BOOST_REQUIRE(main->GetConsensus().nMatMulRCHeight !=
                  std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(DefaultMatMulRCExecutionMode(*main), "strict-device");

    // Regtest is exempt even though it routinely sets a finite RC height: it
    // runs toy dimensions on hosts with no qualified accelerator, so strict
    // there fails closed against the harness, not against a real risk.
    const auto regtest{CreateChainParams(empty, ChainType::REGTEST)};
    BOOST_CHECK_EQUAL(DefaultMatMulRCExecutionMode(*regtest), "auto-fallback");

    // Chains with no RC activation keep the portable oracle.
    const auto testnet{CreateChainParams(empty, ChainType::TESTNET)};
    BOOST_REQUIRE_EQUAL(testnet->GetConsensus().nMatMulRCHeight,
                        std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(DefaultMatMulRCExecutionMode(*testnet), "auto-fallback");
}

BOOST_AUTO_TEST_CASE(unverifiable_production_consensus_startup_degrades_not_exits)
{
    ArgsManager empty;
    const auto main{CreateChainParams(empty, ChainType::MAIN)};
    const auto regtest{CreateChainParams(empty, ChainType::REGTEST)};
    const auto testnet{CreateChainParams(empty, ChainType::TESTNET)};

    // 0.34.5: a CPU tarball / moved-fingerprint source build must start.
    // Mining and NODE_MATMUL_CONSENSUS stay fail-closed elsewhere.
    BOOST_CHECK(!RefuseUnverifiableMatMulConsensusStartup(
        *main, "consensus", /*strict_device_ready=*/false,
        /*allow_unverifiable_startup=*/false));
    BOOST_CHECK(!RefuseUnverifiableMatMulConsensusStartup(
        *main, "consensus", /*strict_device_ready=*/true,
        /*allow_unverifiable_startup=*/false));
    BOOST_CHECK(!RefuseUnverifiableMatMulConsensusStartup(
        *main, "trusted", /*strict_device_ready=*/false,
        /*allow_unverifiable_startup=*/false));
    BOOST_CHECK(!RefuseUnverifiableMatMulConsensusStartup(
        *main, "consensus", /*strict_device_ready=*/false,
        /*allow_unverifiable_startup=*/true));

    BOOST_CHECK(!RefuseUnverifiableMatMulConsensusStartup(
        *regtest, "consensus", /*strict_device_ready=*/false,
        /*allow_unverifiable_startup=*/false));
    BOOST_CHECK(!RefuseUnverifiableMatMulConsensusStartup(
        *testnet, "consensus", /*strict_device_ready=*/false,
        /*allow_unverifiable_startup=*/false));
}

BOOST_AUTO_TEST_CASE(runtime_reprobe_is_bounded_and_unavailable_only)
{
    int calls{0};
    const auto probe = [&calls](const std::string& provider) {
        ++calls;
        BOOST_CHECK_EQUAL(provider, "cuda");
        return std::pair<bool, std::string>{true, "complete"};
    };

    // A healthy validator must never repeat even the cheap identity probe.
    const auto ready{RunUnavailableMatMulRCRuntimeReprobe(
        /*strict_device_ready=*/true, "cuda", probe)};
    BOOST_CHECK(!ready.attempted);
    BOOST_CHECK_EQUAL(calls, 0);

    // One scheduler firing performs exactly one injected probe. It observes a
    // candidate only; it cannot claim that self-qualification or the expensive
    // process/epoch-bound production canary passed.
    const auto unavailable{RunUnavailableMatMulRCRuntimeReprobe(
        /*strict_device_ready=*/false, "cuda", probe)};
    BOOST_CHECK(unavailable.attempted);
    BOOST_CHECK(unavailable.runtime_candidate_available);
    BOOST_CHECK_EQUAL(unavailable.provider, "cuda");
    BOOST_CHECK_EQUAL(unavailable.reason, "complete");
    BOOST_CHECK_EQUAL(calls, 1);

    // An absent candidate is a bounded no-op and does not invoke the callback.
    const auto absent{RunUnavailableMatMulRCRuntimeReprobe(
        /*strict_device_ready=*/false, "", probe)};
    BOOST_CHECK(!absent.attempted);
    BOOST_CHECK_EQUAL(absent.reason, "no_runtime_candidate");
    BOOST_CHECK_EQUAL(calls, 1);
}

BOOST_AUTO_TEST_SUITE_END()
