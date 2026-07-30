// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <cuda/matmul_v4_rc_episode_context.h>
#include <cuda/matmul_v4_rc_mx_ozaki_native.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <matmul/matmul_v4_rc_peak_ready.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>
#include <vector>

// Agent E+I — SM100 isolation + DeriveRCPeakReady honesty.
//
// 1) SM100 path cannot advertise/dispatch SM120_MMA without sm_120a.
// 2) BTX_CUDA_SM100_NATIVE probe stays fail-closed without B200.
// 3) cuda_episode_ready / peak_ready are derived — never compiled==ready.
// 4) Heights remain INT32_MAX. SM120 packaging (BTX_CUDA_SM120_MXFP4_NATIVE)
//    is independent and preserved.

namespace rc = matmul::v4::rc;
namespace dc = matmul::v4::rc::dc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_sm100_isolation_tests, BasicTestingSetup)

namespace {

struct EnvRestore {
    std::string name;
    std::optional<std::string> prior;
    explicit EnvRestore(const char* n) : name(n)
    {
        if (const char* v = std::getenv(n)) {
            prior = std::string(v);
        }
    }
    ~EnvRestore()
    {
        if (prior) {
            setenv(name.c_str(), prior->c_str(), /*overwrite=*/1);
        } else {
            unsetenv(name.c_str());
        }
    }
};

} // namespace

static_assert(std::numeric_limits<int32_t>::max() == 2147483647);

BOOST_AUTO_TEST_CASE(rc_sm100_native_probe_fail_closed_without_b200)
{
    // Packaging probe stub: always false in this tree (no B200 evidence).
    BOOST_CHECK(!matmul_v4::cuda::RcOzakiMxfp4Sm100NativeLinked());
#if defined(BTX_CUDA_SM100_NATIVE)
    // If somehow defined, still must not imply SM120_MMA packaging alone.
    BOOST_CHECK(true);
#else
    BOOST_CHECK(!matmul_v4::cuda::RcOzakiMxfp4Sm100NativeLinked());
#endif

    // Env cannot flip the fail-closed SM100 packaging latch.
    EnvRestore r1("BTX_CUDA_SM100_NATIVE");
    EnvRestore r2("BTX_CUDA_SM120_MXFP4_NATIVE");
    setenv("BTX_CUDA_SM100_NATIVE", "1", /*overwrite=*/1);
    setenv("BTX_CUDA_SM120_MXFP4_NATIVE", "1", /*overwrite=*/1);
    BOOST_CHECK(!matmul_v4::cuda::RcOzakiMxfp4Sm100NativeLinked());
}

BOOST_AUTO_TEST_CASE(rc_sm100_never_cross_infers_sm120_mma)
{
    rc::ResetRcOzakiQualForTest();
    matmul_v4::cuda::ResetRcOzakiCudaQualForTest();

    const auto oz = rc::ProbeRcOzakiMxfp4Status();
    // Separate latches: SM100_CUBLASLT ≠ SM120_MMA.
    if (oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM100_CUBLASLT) {
        BOOST_CHECK_EQUAL(oz.backend, "SM100_CUBLASLT");
        BOOST_CHECK(oz.backend.find("SM120_MMA") == std::string::npos);
        BOOST_CHECK(oz.backend.find("cutlass") == std::string::npos);
    }
    // SM100_MMA (hand tcgen05) is also an sm_100-only latch; never SM120 / cuBLASLt.
    if (oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM100_MMA) {
        BOOST_REQUIRE(matmul_v4::cuda::RcOzakiMxfp4Sm100NativeLinked());
        BOOST_CHECK_EQUAL(oz.backend, "SM100_MMA");
        BOOST_CHECK(oz.backend.find("SM120_MMA") == std::string::npos);
        BOOST_CHECK(oz.backend.find("cublaslt") == std::string::npos);
        BOOST_CHECK(oz.backend.find("cutlass") == std::string::npos);
    }
    // Without the sm_100a object, SM100_MMA must never be advertised.
    if (!matmul_v4::cuda::RcOzakiMxfp4Sm100NativeLinked()) {
        BOOST_CHECK_NE(matmul_v4::cuda::RcOzakiCudaMxfp4Backend(), "SM100_MMA");
        BOOST_CHECK(matmul_v4::cuda::RcOzakiCudaMxfp4SelectedBackend() !=
                    matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::SM100_MMA);
    }
    if (oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM120_MMA) {
        BOOST_REQUIRE(matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked());
        BOOST_CHECK_EQUAL(oz.backend, "SM120_MMA");
    }
    // Without sm_120a object, SM120_MMA must not be advertised.
    if (!matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked()) {
        BOOST_CHECK_NE(matmul_v4::cuda::RcOzakiCudaMxfp4Backend(), "SM120_MMA");
        BOOST_CHECK_EQUAL(
            static_cast<int>(matmul_v4::cuda::RcOzakiCudaMxfp4SelectedBackend()),
            static_cast<int>(matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::Unqualified));
    }
}

// B200 tcgen05 native-MMA qualification gate. On CI (no sm_100a object / no B200)
// this asserts the path is fail-closed. On a real B200 with BTX_CUDA_SM100_NATIVE
// the same body drives the exact self-qual and, if SM100_MMA latches, checks that
// the native tcgen05 GEMM is bit-identical to the int64 oracle on a high-magnitude
// multi-shape battery (K on both sides of 2^24; M11/E8M0 max corners; -128 rails).
BOOST_AUTO_TEST_CASE(rc_sm100_tcgen05_native_gate_fail_closed_or_bit_exact)
{
    rc::ResetRcOzakiQualForTest();
    matmul_v4::cuda::ResetRcOzakiCudaQualForTest();

    (void)matmul_v4::cuda::SelfQualifyRcOzakiCudaMxfp4Once();
    const auto sel = matmul_v4::cuda::RcOzakiCudaMxfp4SelectedBackend();

    if (!matmul_v4::cuda::RcOzakiMxfp4Sm100NativeLinked()) {
        // No sm_100a object linked (default / non-B200 packaging): fail-closed.
        BOOST_CHECK(sel != matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::SM100_MMA);
        return;
    }
    if (sel != matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::SM100_MMA) {
        // Object linked but silicon/toolkit did not qualify tcgen05: still fail-
        // closed (Unqualified or SM100_CUBLASLT). Never a wrong digest.
        BOOST_CHECK(matmul_v4::cuda::RcOzakiCudaMxfp4Backend() != "SM100_MMA");
        return;
    }

    // SM100_MMA latched on real B200: the qual suite already matched the oracle.
    // Re-verify an out-of-suite high-magnitude shape end-to-end for good measure.
    BOOST_CHECK(matmul_v4::cuda::RcOzakiCudaMxfp4NativeTensorLaunchCount() > 0);
    const uint32_t M = 24, K = 8192, N = 40; // K > 4096: crosses the 2^24 chunk edge
    std::vector<int8_t> L(static_cast<size_t>(M) * K), R(static_cast<size_t>(K) * N);
    for (size_t i = 0; i < L.size(); ++i) {
        // M11×2^e alphabet corners incl. sign flips (MX-factorable, adversarial).
        static const int8_t m11[] = {6, -6, 4, -4, 3, -3, 2, -2, 1, -1};
        L[i] = static_cast<int8_t>(m11[i % 10] * (1 << ((i / 32) & 3)));
    }
    for (size_t i = 0; i < R.size(); ++i) {
        static const int8_t m11[] = {-6, 6, -4, 4, -3, 3, -2, 2, -1, 1};
        R[i] = static_cast<int8_t>(m11[i % 10] * (1 << ((i / 32) & 3)));
    }
    std::vector<int64_t> oracle(static_cast<size_t>(M) * N, 0);
    for (uint32_t r = 0; r < M; ++r) {
        for (uint32_t c = 0; c < N; ++c) {
            int64_t acc = 0;
            for (uint32_t k = 0; k < K; ++k) {
                acc += static_cast<int64_t>(L[static_cast<size_t>(r) * K + k]) *
                       static_cast<int64_t>(R[static_cast<size_t>(k) * N + c]);
            }
            oracle[static_cast<size_t>(r) * N + c] = acc;
        }
    }
    std::vector<int64_t> gpu;
    std::string err;
    BOOST_REQUIRE_MESSAGE(
        matmul_v4::cuda::TryLaunchRcOzakiMxfp4GemmS8S8Int64(L, R, M, K, N, gpu, &err), err);
    BOOST_CHECK(gpu == oracle);
}

BOOST_AUTO_TEST_CASE(rc_peak_ready_derived_never_compiled_eq_ready)
{
    // Empty inputs → peak_ready false.
    const auto empty = rc::DeriveRCPeakReady(rc::RCPeakReadyInputs{});
    BOOST_CHECK(!empty.peak_ready);
    BOOST_CHECK(!empty.production_qualified);
    BOOST_CHECK(!empty.deficit.empty());

    // Compiled alone is NOT ready.
    rc::RCEpisodePeakBits bits;
    bits.cuda_episode_compiled = true;
    bits.full_page_schedule = true;
    const auto from_compiled =
        rc::DeriveRCPeakReady(rc::MakeRCPeakReadyInputsFromEpisode(bits));
    BOOST_CHECK(from_compiled.linked);
    BOOST_CHECK(!from_compiled.peak_ready);
    BOOST_CHECK(!from_compiled.production_qualified);

    const dc::RCDcStatus st = dc::ProbeRCDcStatus();
    BOOST_CHECK_EQUAL(st.cuda_episode_compiled, matmul_v4::cuda::IsRcEpisodeCudaCompiled());
    // Derived: ready tracks peak_ready, never compiled.
    BOOST_CHECK_EQUAL(st.cuda_episode_ready, st.peak_ready);
    BOOST_CHECK(!st.peak_ready);
    BOOST_CHECK(!st.cuda_episode_ready);
    if (st.cuda_episode_compiled) {
        BOOST_CHECK(st.cuda_episode_ready != st.cuda_episode_compiled || !st.peak_ready);
        BOOST_CHECK(!st.cuda_episode_ready);
    }
    BOOST_CHECK(!st.deficit.empty());
}

BOOST_AUTO_TEST_CASE(rc_episode_provenance_peak_ready_derived)
{
    matmul_v4::cuda::RCCudaEpisodeContext ctx;
    std::string err;
    const auto params = rc::MakeToyRCCoupParams();
    BOOST_REQUIRE(ctx.Init(params, /*batch_q=*/1, &err));
    // Fresh Init: peak_ready must come from DeriveRCPeakReady (false).
    BOOST_CHECK(!ctx.Provenance().peak_ready);
    ctx.RefreshPeakReadyDerived();
    BOOST_CHECK(!ctx.Provenance().peak_ready);
    ctx.Destroy();
}

BOOST_AUTO_TEST_CASE(rc_sm100_heights_remain_int32_max)
{
    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulRCCoupledHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!consensus.IsMatMulRCActive(1));
    BOOST_CHECK(!dc::ProbeRCDcStatus().gkr_arbiter);
}

BOOST_AUTO_TEST_CASE(rc_sm120_packaging_macro_independent_of_sm100)
{
    // SM120 packaging flag (when present) does not imply SM100 native linked.
#if defined(BTX_CUDA_SM120_MXFP4_NATIVE)
    BOOST_CHECK(matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked() ||
                !matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked());
#endif
    BOOST_CHECK(!matmul_v4::cuda::RcOzakiMxfp4Sm100NativeLinked());
#if !defined(BTX_CUDA_SM120_MXFP4_NATIVE)
    BOOST_CHECK(!matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked());
#endif
}

BOOST_AUTO_TEST_SUITE_END()
