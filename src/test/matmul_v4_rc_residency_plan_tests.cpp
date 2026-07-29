// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/backend_capabilities_v4.h>
#include <matmul/matmul_v4_rc_accel_policy.h>
#include <matmul/matmul_v4_rc_residency_plan.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

// Pure, hardware-free coverage for the RTX PRO 6000 Blackwell resident-vs-
// streamed VRAM planner and the native-MXFP4-over-IMMA compute-lane preference.
// No CUDA device is required — these encode the §S.1-style classification rules.

namespace rc = matmul::v4::rc;
namespace bk = matmul_v4::backend;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_residency_plan_tests)

namespace {
constexpr uint64_t GiB = 1024ull * 1024ull * 1024ull;
} // namespace

BOOST_AUTO_TEST_CASE(rtx_pro_6000_holds_working_set_resident)
{
    // RTX PRO 6000 Blackwell: 96 GB total, ~94 GiB free, ~48 GiB V2 working set.
    const rc::RCResidencyPlan plan = rc::PlanRCResidency(48 * GiB, 94 * GiB, 96 * GiB);
    BOOST_CHECK(plan.resident_capable);
    BOOST_CHECK(plan.working_set_fits);
    BOOST_CHECK(plan.mode == rc::RCAccelResidencyMode::Resident);
    BOOST_CHECK_EQUAL(plan.reason, "resident:large_vram_fits");
}

BOOST_AUTO_TEST_CASE(rtx_5090_32gb_streams_even_when_toy_fits)
{
    // 32 GB RTX 5090: below the 64 GiB resident-class floor. Even a toy shape
    // that physically fits is labelled Streamed (card-class policy), matching
    // the datacenter-advantage economics.
    const rc::RCResidencyPlan plan = rc::PlanRCResidency(1 * GiB, 30 * GiB, 32 * GiB);
    BOOST_CHECK(!plan.resident_capable);
    BOOST_CHECK(plan.working_set_fits);
    BOOST_CHECK(plan.mode == rc::RCAccelResidencyMode::Streamed);
    BOOST_CHECK_EQUAL(plan.reason, "streamed:small_vram_card");
}

BOOST_AUTO_TEST_CASE(large_card_capacity_short_falls_back_to_streamed)
{
    // 96 GB card but a 90 GiB working set + headroom exceeds 92 GiB free.
    const rc::RCResidencyPlan plan = rc::PlanRCResidency(90 * GiB, 92 * GiB, 96 * GiB);
    BOOST_CHECK(plan.resident_capable);
    BOOST_CHECK(!plan.working_set_fits);
    BOOST_CHECK(plan.mode == rc::RCAccelResidencyMode::Streamed);
    BOOST_CHECK_EQUAL(plan.reason, "streamed:capacity_short");
}

BOOST_AUTO_TEST_CASE(unknown_vram_is_fail_closed_streamed)
{
    const rc::RCResidencyPlan p0 = rc::PlanRCResidency(48 * GiB, 0, 0);
    BOOST_CHECK(!p0.working_set_fits);
    BOOST_CHECK(p0.mode == rc::RCAccelResidencyMode::Streamed);
    BOOST_CHECK_EQUAL(p0.reason, "streamed:vram_unknown");

    const rc::RCResidencyPlan p1 = rc::PlanRCResidency(0, 94 * GiB, 96 * GiB);
    BOOST_CHECK(!p1.working_set_fits);
    BOOST_CHECK(p1.mode == rc::RCAccelResidencyMode::Streamed);
    BOOST_CHECK_EQUAL(p1.reason, "streamed:degenerate_working_set");
}

BOOST_AUTO_TEST_CASE(headroom_grows_with_total_vram)
{
    // 6% of 96 GiB (~5.76 GiB) exceeds the 4 GiB floor.
    BOOST_CHECK_GT(rc::RCResidentHeadroomBytes(96 * GiB), rc::kRCResidentHeadroomBytesFloor);
    // Small totals clamp to the floor.
    BOOST_CHECK_EQUAL(rc::RCResidentHeadroomBytes(8 * GiB), rc::kRCResidentHeadroomBytesFloor);
    // The 64 GiB floor is the resident-class boundary.
    BOOST_CHECK_EQUAL(rc::kRCResidentVramFloorBytes, 64ull * GiB);
}

BOOST_AUTO_TEST_CASE(resident_class_boundary_exact)
{
    // Exactly at the floor with a fitting working set: resident.
    const rc::RCResidencyPlan at = rc::PlanRCResidency(4 * GiB, 60 * GiB, 64 * GiB);
    BOOST_CHECK(at.resident_capable);
    BOOST_CHECK(at.mode == rc::RCAccelResidencyMode::Resident);
    // One byte under the floor: streamed class.
    const rc::RCResidencyPlan under = rc::PlanRCResidency(4 * GiB, 60 * GiB, 64 * GiB - 1);
    BOOST_CHECK(!under.resident_capable);
    BOOST_CHECK(under.mode == rc::RCAccelResidencyMode::Streamed);
}

// ---- native-MXFP4-over-IMMA preference (fail-closed) -----------------------

BOOST_AUTO_TEST_CASE(prefer_native_only_when_qualified)
{
    // sm_120 is IMMA-admissible via ClassifyCudaDevice.
    const bk::Eligibility imma = bk::ClassifyCudaDevice(12, 0);
    BOOST_REQUIRE(imma.admissible);

    // Native unqualified → keep the sub-peak IMMA lane (fail-closed).
    const bk::CudaComputePreference base = bk::PreferCudaNativeMxfp4OverImma(imma, false);
    BOOST_CHECK(base.imma_admissible);
    BOOST_CHECK(!base.prefer_native);
    BOOST_CHECK_EQUAL(base.lane, "imma_s8s8s32");

    // Native qualified → prefer the peak native MXFP4 lane.
    const bk::CudaComputePreference peak = bk::PreferCudaNativeMxfp4OverImma(imma, true);
    BOOST_CHECK(peak.prefer_native);
    BOOST_CHECK_EQUAL(peak.lane, "native_mxfp4");
}

BOOST_AUTO_TEST_CASE(inadmissible_base_never_prefers_native)
{
    // Pascal: not IMMA-admissible. Native MXFP4 cannot rescue it, and we never
    // advertise native on an inadmissible base — even if a stray qual flag is set.
    const bk::Eligibility no_tensor = bk::ClassifyCudaDevice(6, 1);
    BOOST_REQUIRE(!no_tensor.admissible);
    const bk::CudaComputePreference pref = bk::PreferCudaNativeMxfp4OverImma(no_tensor, true);
    BOOST_CHECK(!pref.prefer_native);
    BOOST_CHECK_EQUAL(pref.lane, "inadmissible");
}

BOOST_AUTO_TEST_SUITE_END()
