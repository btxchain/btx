// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_accel_policy.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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

BOOST_AUTO_TEST_CASE(rc_coup_consensus_config_defaults_v1_compatible)
{
    const rc::RCCoupConsensusConfig cfg = rc::MakeDefaultRCCoupConsensusConfig();
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
    BOOST_CHECK_EQUAL(cfg.material_exchange_rows, dc::kRCCoupExchangeRowsDefault);
    BOOST_CHECK_EQUAL(cfg.transcript_version, rc::kRCTranscriptVersion);
    BOOST_CHECK_EQUAL(cfg.extract_version, rc::kRCExtractVersionV1);
    BOOST_CHECK_EQUAL(cfg.seg_len, rc::kRCSegLen);
    BOOST_CHECK_EQUAL(cfg.wgrad_exact_chunk, rc::kRCWgradExactChunk);
    BOOST_CHECK_EQUAL(cfg.tile_leaf_bytes, rc::kRCTileLeafBytes);
    BOOST_CHECK_EQUAL(cfg.mx_block_len, rc::kRCMxBlockLen);
    BOOST_CHECK(!cfg.full_bank_schedule_enabled);
    BOOST_CHECK_EQUAL(cfg.v2_pages_per_barrier_lobe, dc::kRCCoupPagesPerBarrierLobe);
    BOOST_CHECK(!cfg.v2_profile_enabled);
    BOOST_CHECK_EQUAL(cfg.v2_activation_height, std::numeric_limits<int32_t>::max());

    const rc::RCCoupParams mapped = rc::RCCoupParamsFromConsensusConfig(cfg);
    BOOST_CHECK_EQUAL(mapped.barriers, toy.barriers);
    BOOST_CHECK_EQUAL(mapped.lobes, toy.lobes);
    BOOST_CHECK_EQUAL(mapped.lobe_width, toy.lobe_width);
    BOOST_CHECK_EQUAL(mapped.bank_pages, toy.bank_pages);
    BOOST_CHECK(rc::ValidateRCCoupParams(mapped));
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
