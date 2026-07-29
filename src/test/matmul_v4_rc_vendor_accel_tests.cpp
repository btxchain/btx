// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <ascend/matmul_v4_rc_accel.h>
#include <hip/matmul_v4_rc_mx_ozaki_native.h>
#include <metal/matmul_v4_rc_ozaki_accel.h>
#include <tpu/matmul_v4_rc_accel.h>
#include <trainium/matmul_v4_rc_accel.h>

#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_vendor_accel_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Item 6 — Metal RC Ozaki
// Host unit-exact: rc_metal_ozaki_exact_panels_host_byte_exact
// Device qualify (Darwin+Metal): rc_metal_ozaki_exact_panels_device_qualify
// HARD BLOCKER on this Linux host: "requires Apple silicon + Metal"
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(rc_metal_ozaki_exact_panels_host_byte_exact)
{
    matmul_v4::metal::ResetRcOzakiMetalQualForTest();
    constexpr uint32_t rows = 8, cols = 8;
    for (uint32_t inner : {8u, 64u, 4096u}) {
        std::vector<int8_t> L(static_cast<size_t>(rows) * inner);
        std::vector<int8_t> R(static_cast<size_t>(inner) * cols);
        for (size_t i = 0; i < L.size(); ++i) {
            L[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 13) - 6);
        }
        for (size_t i = 0; i < R.size(); ++i) {
            R[i] = static_cast<int8_t>((static_cast<int32_t>(i * 5) % 11) - 5);
        }
        std::vector<int64_t> out;
        std::string err;
        BOOST_REQUIRE(matmul_v4::metal::HostReferenceRcOzakiExactPanelsGemmS8S8Int64(
            L, R, rows, inner, cols, out, &err));
        std::vector<int64_t> dense(static_cast<size_t>(rows) * cols, 0);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t c = 0; c < cols; ++c) {
                int64_t acc = 0;
                for (uint32_t k = 0; k < inner; ++k) {
                    acc += static_cast<int64_t>(L[static_cast<size_t>(r) * inner + k]) *
                           static_cast<int64_t>(R[static_cast<size_t>(k) * cols + c]);
                }
                dense[static_cast<size_t>(r) * cols + c] = acc;
            }
        }
        BOOST_CHECK(out == dense);
    }
}

BOOST_AUTO_TEST_CASE(rc_metal_ozaki_exact_panels_device_qualify)
{
    // On Linux / Metal-off: HARD BLOCKER — requires Apple silicon + Metal.
    matmul_v4::metal::ResetRcOzakiMetalQualForTest();
    if (!matmul_v4::metal::IsRcOzakiMetalCompiled()) {
        BOOST_CHECK_EQUAL(matmul_v4::metal::RcOzakiMetalDeficit(),
                          "requires Apple silicon + Metal");
        BOOST_CHECK(!matmul_v4::metal::SelfQualifyRcOzakiMetalExactPanelsOnce());
        BOOST_CHECK(!matmul_v4::metal::IsRcOzakiMetalExactPanelsQualified());
        BOOST_CHECK(!matmul_v4::metal::IsRcOzakiMetalMxfp4Qualified());
        std::vector<int8_t> L(64, 1), R(64, 1);
        std::vector<int64_t> out;
        std::string err;
        BOOST_CHECK(!matmul_v4::metal::TryLaunchRcOzakiMetalExactPanelsGemmS8S8Int64(
            L, R, 8, 8, 8, out, &err));
        BOOST_CHECK(err.find("Apple silicon") != std::string::npos ||
                    err.find("Metal") != std::string::npos);
        // Native MX never from INT8.
        BOOST_CHECK(!matmul_v4::metal::TryLaunchRcOzakiMetalMxfp4GemmS8S8Int64(
            L, R, 8, 8, 8, out, &err));
        return;
    }
    // Darwin + Metal: ExactPanels may qualify; MXFP4 must stay false.
    BOOST_CHECK(matmul_v4::metal::SelfQualifyRcOzakiMetalExactPanelsOnce());
    BOOST_CHECK(matmul_v4::metal::IsRcOzakiMetalExactPanelsQualified());
    BOOST_CHECK(!matmul_v4::metal::IsRcOzakiMetalMxfp4Qualified());
}

// ---------------------------------------------------------------------------
// Item 7 — HIP RC Ozaki
// Host pack: rc_hip_ozaki_mxfp4_pack_unit_exact
// Device: rc_hip_ozaki_mxfp4_device_qualify — HARD BLOCKER "requires gfx950 silicon"
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(rc_hip_ozaki_mxfp4_pack_unit_exact)
{
    matmul_v4::hip::ResetRcOzakiHipQualForTest();
    constexpr uint32_t rows = 4, cols = 4, K = 64;
    std::vector<int8_t> L(static_cast<size_t>(rows) * K);
    std::vector<int8_t> R(static_cast<size_t>(K) * cols);
    static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t k = 0; k < K; ++k) {
            const uint8_t e = static_cast<uint8_t>((k / 32u) % 4);
            L[static_cast<size_t>(r) * K + k] =
                static_cast<int8_t>(kM11[(r + k) % 11] * (1 << e));
        }
    }
    for (uint32_t k = 0; k < K; ++k) {
        for (uint32_t c = 0; c < cols; ++c) {
            const uint8_t e = static_cast<uint8_t>((k / 32u + 1) % 4);
            R[static_cast<size_t>(k) * cols + c] =
                static_cast<int8_t>(kM11[(c + k) % 11] * (1 << e));
        }
    }
    matmul_v4::hip::RcOzakiHipMxPack pack;
    std::string err;
    BOOST_REQUIRE(matmul_v4::hip::PackRcOzakiHipMxfp4OpATOpBN(L, R, rows, K, cols, pack, &err));
    BOOST_CHECK_EQUAL(pack.kblocks, 2u);
    std::vector<int64_t> from_pack;
    BOOST_REQUIRE(matmul_v4::hip::HostReferenceRcOzakiHipMxfp4GemmFromPack(pack, rows, K, cols,
                                                                            from_pack, &err));
    std::vector<int64_t> dense(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            int64_t acc = 0;
            for (uint32_t k = 0; k < K; ++k) {
                acc += static_cast<int64_t>(L[static_cast<size_t>(r) * K + k]) *
                       static_cast<int64_t>(R[static_cast<size_t>(k) * cols + c]);
            }
            dense[static_cast<size_t>(r) * cols + c] = acc;
        }
    }
    BOOST_CHECK(from_pack == dense);
}

BOOST_AUTO_TEST_CASE(rc_hip_ozaki_mxfp4_device_qualify)
{
    matmul_v4::hip::ResetRcOzakiHipQualForTest();
    if (!matmul_v4::hip::IsRcOzakiHipCompiled() ||
        !matmul_v4::hip::IsRcOzakiHipMxfp4Qualified()) {
        BOOST_CHECK(matmul_v4::hip::RcOzakiHipDeficit().find("gfx950") != std::string::npos ||
                    matmul_v4::hip::RcOzakiHipDeficit().find("gfx942") != std::string::npos);
        BOOST_CHECK(!matmul_v4::hip::SelfQualifyRcOzakiHipMxfp4Once());
        BOOST_CHECK(!matmul_v4::hip::IsRcOzakiHipMxfp4Qualified());
        std::vector<int8_t> L(64, 6), R(64, -6);
        std::vector<int64_t> out;
        std::string err;
        BOOST_CHECK(!matmul_v4::hip::TryLaunchRcOzakiHipMxfp4GemmS8S8Int64(L, R, 8, 8, 8, out,
                                                                            &err));
        // INT8 ExactPanels ≠ native MX.
        BOOST_CHECK(err.find("gfx9") != std::string::npos ||
                    err.find("BTX_HIP_MXFP4") != std::string::npos ||
                    err.find("silicon") != std::string::npos);
        return;
    }
    BOOST_CHECK(matmul_v4::hip::RcOzakiHipMxfp4Backend().find("mxfp4") != std::string::npos);
    BOOST_CHECK(matmul_v4::hip::RcOzakiHipMxfp4Backend().find("exactgemm") == std::string::npos);
}

// ---------------------------------------------------------------------------
// Item 8 — TPU / Trainium / Ascend RC episodes
// Host: rc_*_episode_host_byte_exact
// Device: rc_*_episode_device_qualify — HARD BLOCKER named SDK+silicon
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(rc_tpu_episode_host_byte_exact)
{
    matmul_v4::tpu::ResetTpuPjrtRcEpisodeProviderForTesting();
    CBlockHeader header;
    header.nTime = 1;
    header.nNonce = 7;
    const auto params = matmul::v4::rc::MakeToyRCCoupParams();
    uint256 d1, d2;
    matmul::v4::rc::RCEpisodeTiming t{};
    BOOST_REQUIRE(matmul_v4::tpu::HostReferenceRcTpuCoupledEpisode(header, 0, params, d1, &t));
    d2 = matmul::v4::rc::MineCoupledPuzzle(header, 0, params);
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK(!matmul_v4::tpu::IsTpuPjrtRcEpisodeAvailable());
    BOOST_CHECK_EQUAL(matmul_v4::tpu::RcTpuDeficit(), "requires PJRT+TPU");

    matmul_v4::tpu::RCTpuEpisodeContext ctx;
    BOOST_REQUIRE(ctx.Init(params, /*batch_q=*/4));
    auto pages = matmul::v4::rc::DeriveCoupledBankPages(header, 0, params);
    BOOST_REQUIRE(ctx.LoadBank(pages));
    std::string err;
    BOOST_CHECK(!ctx.RunBarriers(&err));
    BOOST_CHECK(err.find("PJRT") != std::string::npos || err.find("TPU") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rc_trainium_episode_host_byte_exact)
{
    matmul_v4::trainium::ResetTrainiumNeuronRcEpisodeProviderForTesting();
    CBlockHeader header;
    header.nTime = 2;
    header.nNonce = 9;
    const auto params = matmul::v4::rc::MakeToyRCCoupParams();
    uint256 d1, d2;
    BOOST_REQUIRE(
        matmul_v4::trainium::HostReferenceRcTrainiumCoupledEpisode(header, 0, params, d1));
    d2 = matmul::v4::rc::MineCoupledPuzzle(header, 0, params);
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK(!matmul_v4::trainium::IsTrainiumNeuronRcEpisodeAvailable());
    BOOST_CHECK_EQUAL(matmul_v4::trainium::RcTrainiumDeficit(), "requires Neuron+Trainium");

    matmul_v4::trainium::RCTrainiumEpisodeContext ctx;
    BOOST_REQUIRE(ctx.Init(params));
    auto pages = matmul::v4::rc::DeriveCoupledBankPages(header, 0, params);
    BOOST_REQUIRE(ctx.LoadBank(pages));
    std::string err;
    BOOST_CHECK(!ctx.RunBarriers(&err));
    BOOST_CHECK(err.find("Neuron") != std::string::npos ||
                err.find("Trainium") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rc_ascend_episode_host_byte_exact)
{
    CBlockHeader header;
    header.nTime = 3;
    header.nNonce = 11;
    const auto params = matmul::v4::rc::MakeToyRCCoupParams();
    uint256 d1, d2;
    BOOST_REQUIRE(matmul_v4::ascend::HostReferenceRcAscendCoupledEpisode(header, 0, params, d1));
    d2 = matmul::v4::rc::MineCoupledPuzzle(header, 0, params);
    BOOST_CHECK(d1 == d2);
    if (!matmul_v4::ascend::IsAscendRcEpisodeAvailable()) {
        BOOST_CHECK_EQUAL(matmul_v4::ascend::RcAscendDeficit(), "requires CANN+Ascend");
    }
    matmul_v4::ascend::RCAscendEpisodeContext ctx;
    BOOST_REQUIRE(ctx.Init(params));
    auto pages = matmul::v4::rc::DeriveCoupledBankPages(header, 0, params);
    BOOST_REQUIRE(ctx.LoadBank(pages));
    std::string err;
    if (!matmul_v4::ascend::IsAscendRcEpisodeAvailable()) {
        BOOST_CHECK(!ctx.RunBarriers(&err));
        BOOST_CHECK(err.find("CANN") != std::string::npos ||
                    err.find("Ascend") != std::string::npos);
    }
    // Extract host path works without SDK.
    uint256 prf{};
    std::vector<int8_t> extracted;
    BOOST_CHECK(ctx.ExtractHost(prf, extracted, &err));
    BOOST_CHECK_EQUAL(extracted.size(), params.StateBytes());
}

BOOST_AUTO_TEST_CASE(rc_tpu_episode_device_qualify)
{
    // HARD BLOCKER without PJRT+TPU SDK registration.
    matmul_v4::tpu::ResetTpuPjrtRcEpisodeProviderForTesting();
    BOOST_CHECK(!matmul_v4::tpu::IsTpuPjrtRcEpisodeAvailable());
    BOOST_CHECK_EQUAL(matmul_v4::tpu::RcTpuDeficit(), "requires PJRT+TPU");
#if !defined(BTX_HAVE_TPU_PJRT)
    matmul_v4::tpu::TpuPjrtRcEpisodeProviderV1 fake{};
    fake.provider_name = "fake";
    fake.run_barrier_batch = [](void*, const int8_t*, size_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, uint32_t, const int8_t*, int32_t*,
                                bool*) { return false; };
    BOOST_CHECK(!matmul_v4::tpu::RegisterTpuPjrtRcEpisodeProvider(fake));
#endif
}

BOOST_AUTO_TEST_CASE(rc_trainium_episode_device_qualify)
{
    matmul_v4::trainium::ResetTrainiumNeuronRcEpisodeProviderForTesting();
    BOOST_CHECK(!matmul_v4::trainium::IsTrainiumNeuronRcEpisodeAvailable());
    BOOST_CHECK_EQUAL(matmul_v4::trainium::RcTrainiumDeficit(), "requires Neuron+Trainium");
}

BOOST_AUTO_TEST_CASE(rc_ascend_episode_device_qualify)
{
    if (!matmul_v4::ascend::IsAscendRcEpisodeAvailable()) {
        BOOST_CHECK_EQUAL(matmul_v4::ascend::RcAscendDeficit(), "requires CANN+Ascend");
    }
    // Cube INT8 ≠ native MX float.
    std::vector<int8_t> L(32, 1), R(32 * 32, 1);
    std::vector<int32_t> out;
    bool used = true;
    if (!matmul_v4::ascend::TryLaunchRcAscendGemmS8S8(L, R, 1, 32, 32, out, &used)) {
        BOOST_CHECK(!used || out.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
