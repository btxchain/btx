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

BOOST_AUTO_TEST_CASE(rc_accel_policy_native_required_neq_portable_explicit)
{
    BOOST_CHECK(rc::RCAccelerationPolicy::NativeRequired !=
                rc::RCAccelerationPolicy::PortableExplicit);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(rc::kRCAccelerationPolicyDefault),
                      static_cast<uint8_t>(rc::RCAccelerationPolicy::NativeRequired));
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCAccelerationPolicy::NativeRequired)},
                      "NativeRequired");
    BOOST_CHECK_EQUAL(std::string{rc::ToString(rc::RCAccelerationPolicy::PortableExplicit)},
                      "PortableExplicit");
}

BOOST_AUTO_TEST_CASE(rc_accel_policy_resolve_default_native_required)
{
    const char* prev = std::getenv("BTX_RC_ACCEL_POLICY");
    unsetenv("BTX_RC_ACCEL_POLICY");
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(rc::ResolveRCAccelerationPolicy()),
                      static_cast<uint8_t>(rc::RCAccelerationPolicy::NativeRequired));
    if (prev != nullptr) {
        setenv("BTX_RC_ACCEL_POLICY", prev, /*overwrite=*/1);
    }
}

/** NativeRequired must not fall through to dense device INT8 when Ozaki MXFP4
 *  is unqualified (typical on CPU-only boxes). Empty gemm_s8s8 ⇒ CPU ExactGemm. */
BOOST_AUTO_TEST_CASE(rc_native_required_empty_gemm_when_ozaki_unqualified)
{
    const char* prev = std::getenv("BTX_RC_ACCEL_POLICY");
    unsetenv("BTX_RC_ACCEL_POLICY");
    BOOST_REQUIRE_EQUAL(static_cast<uint8_t>(rc::ResolveRCAccelerationPolicy()),
                        static_cast<uint8_t>(rc::RCAccelerationPolicy::NativeRequired));

    matmul_v4::accel::ResetRCExactGemmResolveCacheForTest();

    // Default on this CPU box: Ozaki native MXFP4 is not qualified.
    BOOST_REQUIRE_MESSAGE(!rc::IsRcOzakiMxfp4Qualified(),
                          "expected Ozaki MXFP4 unqualified on CPU-only host");

    const auto backend = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
    BOOST_CHECK_MESSAGE(backend.gemm_s8s8 == nullptr,
                        "NativeRequired must decline dense INT8 inject when Ozaki "
                        "unqualified (empty ExactGemmBackend)");

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
    BOOST_CHECK_EQUAL(cfg.config_version, rc::kRCCoupConsensusConfigVersionV2);
    const rc::RCCoupParams prod = rc::MakeProductionRCCoupParams();
    BOOST_CHECK_EQUAL(cfg.barriers, prod.barriers);
    BOOST_CHECK_EQUAL(cfg.lobes, prod.lobes);
    BOOST_CHECK_EQUAL(cfg.lobe_width, prod.lobe_width);
    BOOST_CHECK_EQUAL(cfg.bank_pages, prod.bank_pages);
    BOOST_CHECK(cfg.full_bank_schedule_enabled);
    BOOST_CHECK(cfg.material_exchange_enabled);
    BOOST_CHECK(cfg.v2_profile_enabled);
    BOOST_CHECK_EQUAL(cfg.v2_activation_height, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(cfg.rows_per_lobe, 1u);
    BOOST_CHECK_EQUAL(cfg.pages_per_barrier_lobe, dc::kRCCoupPagesPerBarrierLobe);
    const rc::RCCoupParams from_cfg = rc::RCCoupParamsFromConsensusConfig(cfg);
    BOOST_CHECK(rc::ValidateRCCoupParams(from_cfg));
    BOOST_CHECK_EQUAL(from_cfg.rows_per_lobe, cfg.rows_per_lobe);
    BOOST_CHECK_EQUAL(from_cfg.pages_per_barrier_lobe, cfg.pages_per_barrier_lobe);
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
    BOOST_CHECK(!cfg.full_bank_schedule_enabled);
    BOOST_CHECK(!cfg.v2_profile_enabled);
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
