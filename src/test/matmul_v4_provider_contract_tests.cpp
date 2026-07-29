// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <ascend/matmul_v4_rc_accel.h>
#include <hip/matmul_v4_rc_mx_ozaki_native.h>
#include <matmul/matmul_v4_provider_claims.h>
#include <metal/matmul_v4_rc_ozaki_accel.h>
#include <tpu/matmul_v4_rc_accel.h>
#include <trainium/matmul_v4_rc_accel.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

// Compile-only / provider-contract tests (Workstream E).
// Runnable on the main machine with no special silicon.
//
// Future physical qualification commands (leave HW unqualified until run):
//
// HIP gfx950 / MI355X (ROCm + hipBLASLt MXFP4 types):
//   cmake -B build-hip -DBTX_ENABLE_HIP=ON \
//     -DBTX_HIP_ARCHITECTURES="gfx950" \
//     -DCMAKE_HIP_COMPILER=/opt/rocm/bin/hipcc
//   cmake --build build-hip -j --target test_btx
//   HIP_VISIBLE_DEVICES=0 build-hip/bin/test_btx \
//     --run_test=matmul_v4_rc_vendor_accel_tests/rc_hip_ozaki_mxfp4_device_qualify
//   HIP_VISIBLE_DEVICES=0 build-hip/bin/test_btx \
//     --run_test=matmul_v4_lt_tests
//
// Metal (Darwin Apple silicon):
//   cmake -B build-metal -DBTX_ENABLE_METAL=ON
//   cmake --build build-metal -j --target test_btx
//   build-metal/bin/test_btx \
//     --run_test=matmul_v4_rc_vendor_accel_tests/rc_metal_ozaki_exact_panels_device_qualify
//   # Expect ExactPanels may qualify; metal_rc_mxfp4 must stay unqualified.
//
// TPU (PJRT + libtpu bridge registered at runtime):
//   cmake -B build-tpu -DBTX_HAVE_TPU_PJRT=ON  # plus vendor bridge link flags
//   build-tpu/bin/test_btx \
//     --run_test=matmul_v4_rc_vendor_accel_tests/rc_tpu_episode_device_qualify
//
// Trainium (Neuron NRT bridge):
//   cmake -B build-neuron -DBTX_HAVE_NEURON_NRT=ON
//   build-neuron/bin/test_btx \
//     --run_test=matmul_v4_rc_vendor_accel_tests/rc_trainium_episode_device_qualify
//
// Ascend (CANN + AscendCL):
//   cmake -B build-ascend -DBTX_ENABLE_ASCEND=ON
//   ASCEND_DEVICE_ID=0 build-ascend/bin/test_btx \
//     --run_test=matmul_v4_rc_vendor_accel_tests/rc_ascend_episode_device_qualify

BOOST_FIXTURE_TEST_SUITE(matmul_v4_provider_contract_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(provider_claims_internally_consistent)
{
    matmul_v4::hip::ResetRcOzakiHipQualForTest();
    matmul_v4::metal::ResetRcOzakiMetalQualForTest();
    matmul_v4::tpu::ResetTpuPjrtRcEpisodeProviderForTesting();
    matmul_v4::trainium::ResetTrainiumNeuronRcEpisodeProviderForTesting();

    const auto claims = matmul::v4::ProbeAllProviderClaims();
    BOOST_REQUIRE(!claims.empty());
    for (const auto& c : claims) {
        BOOST_CHECK_MESSAGE(matmul::v4::ProviderClaimIsInternallyConsistent(c),
                            std::string("inconsistent claim: ") +
                                (c.provider ? c.provider : "?") + " backend=" + c.backend);
        if (c.qualified) {
            BOOST_CHECK(c.compiled);
            BOOST_CHECK(c.attempted);
            BOOST_CHECK(c.deficit.empty());
        }
        if (c.backend.find("scalar-decode") != std::string::npos) {
            BOOST_CHECK(!c.qualified);
        }
    }
}

BOOST_AUTO_TEST_CASE(unavailable_silicon_stays_unqualified_on_main_machine)
{
    // Default CPU / HIP-off / Metal-off / no PJRT / no Neuron / no CANN build.
    matmul_v4::hip::ResetRcOzakiHipQualForTest();
    matmul_v4::metal::ResetRcOzakiMetalQualForTest();
    matmul_v4::tpu::ResetTpuPjrtRcEpisodeProviderForTesting();
    matmul_v4::trainium::ResetTrainiumNeuronRcEpisodeProviderForTesting();

    const auto claims = matmul::v4::ProbeAllProviderClaims();
    for (const auto& c : claims) {
        if (std::string(c.provider) == "hip_rc_mxfp4" ||
            std::string(c.provider) == "hip_lt_mxfp4" ||
            std::string(c.provider) == "hip_lt_mxfp8") {
            if (!matmul_v4::hip::IsRcOzakiHipCompiled()) {
                BOOST_CHECK(!c.qualified);
                BOOST_CHECK(c.deficit.find("gfx950") != std::string::npos ||
                            c.deficit.find("gfx942") != std::string::npos ||
                            c.deficit.find("BTX_HIP") != std::string::npos);
            }
        }
        if (std::string(c.provider) == "metal_rc_mxfp4") {
            BOOST_CHECK(!c.qualified);
            BOOST_CHECK(c.format && std::string(c.format).find("unavailable") != std::string::npos);
        }
        if (std::string(c.provider) == "metal_rc_exact") {
            // Never OCP MXFP4 label on Apple INT8 path.
            BOOST_CHECK(std::string(c.format).find("INT8") != std::string::npos);
            BOOST_CHECK(c.backend.find("OCP") == std::string::npos);
            BOOST_CHECK(c.backend.find("MXFP4") == std::string::npos);
            if (!matmul_v4::metal::IsRcOzakiMetalCompiled()) {
                BOOST_CHECK(!c.qualified);
                BOOST_CHECK_EQUAL(c.deficit, "requires Apple silicon + Metal");
            }
        }
        if (std::string(c.provider) == "tpu_rc_episode") {
            if (!matmul_v4::tpu::IsRcTpuCompiled()) {
                BOOST_CHECK(!c.qualified);
                BOOST_CHECK_EQUAL(c.deficit, "requires PJRT+TPU");
            }
        }
        if (std::string(c.provider) == "trainium_rc_episode") {
            if (!matmul_v4::trainium::IsRcTrainiumCompiled()) {
                BOOST_CHECK(!c.qualified);
                BOOST_CHECK_EQUAL(c.deficit, "requires Neuron+Trainium");
            }
        }
        if (std::string(c.provider) == "ascend_rc_episode") {
            if (!matmul_v4::ascend::IsRcAscendCompiled()) {
                BOOST_CHECK(!c.qualified);
                BOOST_CHECK_EQUAL(c.deficit, "requires CANN+Ascend");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(hip_scalar_decode_never_qualifies)
{
    matmul_v4::hip::ResetRcOzakiHipQualForTest();
    (void)matmul_v4::hip::SelfQualifyRcOzakiHipMxfp4Once();
    const std::string backend = matmul_v4::hip::RcOzakiHipMxfp4Backend();
    if (backend.find("scalar-decode") != std::string::npos) {
        BOOST_CHECK(!matmul_v4::hip::IsRcOzakiHipMxfp4Qualified());
        BOOST_CHECK(matmul_v4::hip::RcOzakiHipMxfp4Deficit().find("scalar-decode") !=
                        std::string::npos ||
                    matmul_v4::hip::RcOzakiHipMxfp4Deficit().find("not_native") !=
                        std::string::npos);
    }
    // Host pack unit path remains usable without native claim.
    if (!matmul_v4::hip::IsRcOzakiHipCompiled()) {
        BOOST_CHECK(!matmul_v4::hip::IsRcOzakiHipMxfp4Qualified());
        BOOST_CHECK(!matmul_v4::hip::IsRcOzakiHipMxfp4Attempted());
        BOOST_CHECK_EQUAL(matmul_v4::hip::RcOzakiHipDeficit(), "requires gfx950 silicon");
    }
}

BOOST_AUTO_TEST_CASE(metal_never_labels_int8_as_ocp_mxfp4)
{
    matmul_v4::metal::ResetRcOzakiMetalQualForTest();
    BOOST_CHECK(!matmul_v4::metal::IsRcOzakiMetalMxfp4Qualified());
    BOOST_CHECK(matmul_v4::metal::RcOzakiMetalMxfp4Backend().empty() ||
                matmul_v4::metal::RcOzakiMetalMxfp4Backend().find("MXFP4") == std::string::npos ||
                !matmul_v4::metal::IsRcOzakiMetalMxfp4Qualified());
    (void)matmul_v4::metal::SelfQualifyRcOzakiMetalExactPanelsOnce();
    const std::string be = matmul_v4::metal::RcOzakiMetalExactPanelsBackend();
    BOOST_CHECK(be.find("OCP") == std::string::npos);
    if (!be.empty()) {
        BOOST_CHECK(be.find("metal_int8_") == 0);
    }
}

BOOST_AUTO_TEST_CASE(vendor_deficits_are_hard_blockers)
{
    BOOST_CHECK_EQUAL(matmul_v4::tpu::RcTpuDeficit(), "requires PJRT+TPU");
    BOOST_CHECK_EQUAL(matmul_v4::trainium::RcTrainiumDeficit(), "requires Neuron+Trainium");
    if (!matmul_v4::ascend::IsRcAscendCompiled()) {
        BOOST_CHECK_EQUAL(matmul_v4::ascend::RcAscendDeficit(), "requires CANN+Ascend");
    }
    if (!matmul_v4::hip::IsRcOzakiHipCompiled()) {
        BOOST_CHECK_EQUAL(matmul_v4::hip::RcOzakiHipDeficit(), "requires gfx950 silicon");
    }
    if (!matmul_v4::metal::IsRcOzakiMetalCompiled()) {
        BOOST_CHECK_EQUAL(matmul_v4::metal::RcOzakiMetalDeficit(),
                          "requires Apple silicon + Metal");
    }
}

BOOST_AUTO_TEST_SUITE_END()
