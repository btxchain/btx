// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_rc_accel_policy.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <cstdint>
#include <limits>
#include <string>

namespace rc = matmul::v4::rc;
namespace dc = matmul::v4::rc::dc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_accel_policy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rc_accel_policy_default_is_native_preferred)
{
    BOOST_CHECK(rc::RCAccelerationPolicy::NativeRequired !=
                rc::RCAccelerationPolicy::PortableExplicit);
    BOOST_CHECK(rc::RCAccelerationPolicy::NativePreferred !=
                rc::RCAccelerationPolicy::NativeRequired);
    // Default is best-available-exact (native preferred, exact device INT8 else,
    // CPU last) — mining is not blocked merely because the peak lane is unqualified.
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(rc::kRCAccelerationPolicyDefault),
                      static_cast<uint8_t>(rc::RCAccelerationPolicy::NativePreferred));
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCAccelerationPolicy::NativeRequired)},
                      "NativeRequired");
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCAccelerationPolicy::PortableExplicit)},
                      "PortableExplicit");
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCAccelerationPolicy::NativePreferred)},
                      "NativePreferred");
}

BOOST_AUTO_TEST_CASE(rc_accel_policy_resolve_default_and_env_overrides)
{
    const char* prev = std::getenv("BTX_RC_ACCEL_POLICY");
    // Unset → NativePreferred (default).
    unsetenv("BTX_RC_ACCEL_POLICY");
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(rc::ResolveRCAccelerationPolicy()),
                      static_cast<uint8_t>(rc::RCAccelerationPolicy::NativePreferred));
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

/** DEFAULT (NativePreferred): when the native lane is unqualified, admission goes
 *  through the SAME exact-gated device resolve as PortableExplicit — it does NOT
 *  hard-decline the device the way NativeRequired does. On a CPU-only host both
 *  yield an empty backend (→ CPU); on a GPU host both yield the exact device
 *  backend. The bit-exact self-qual (GateExactGemmWithRCSelfQualCached) still gates
 *  every device path, so a non-byte-identical device is never admitted. */
BOOST_AUTO_TEST_CASE(rc_native_preferred_default_admits_device_like_portable)
{
    const char* prev = std::getenv("BTX_RC_ACCEL_POLICY");
    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
    rc::ResetRcOzakiQualForTest();
    (void)rc::SelfQualifyRcOzakiMxfp4Once();
    if (!rc::IsRcOzakiMxfp4Qualified()) { // meaningful only when native is unqualified
        unsetenv("BTX_RC_ACCEL_POLICY"); // NativePreferred (default)
        matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
        const auto def = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
        setenv("BTX_RC_ACCEL_POLICY", "portable", /*overwrite=*/1); // PortableExplicit
        matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();
        const auto portable = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
        BOOST_CHECK_EQUAL(def.gemm_s8s8 == nullptr, portable.gemm_s8s8 == nullptr);
    }
    if (prev != nullptr) {
        setenv("BTX_RC_ACCEL_POLICY", prev, /*overwrite=*/1);
    } else {
        unsetenv("BTX_RC_ACCEL_POLICY");
    }
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

BOOST_AUTO_TEST_SUITE_END()
