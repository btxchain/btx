// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <cuda/matmul_v4_rc_mx_ozaki_native.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <matmul/matmul_v4_rc_scale_axes.h>
#include <matmul/matmul_v4_rc_selfqual.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>
#include <vector>

// PR #89 Agent D — adversarial honesty for plain sm_120 packaging vs
// feature-qualified sm_120a native MXFP4 (SM120_MMA).
//
// Native SM120_MMA may be advertised ONLY when the dedicated sm_120a object is
// linked AND self-qual succeeds. CPU builds, CUDA stubs, and plain
// BTX_CUDA_ARCHITECTURES=120 fatbins without BTX_CUDA_SM120_MXFP4_NATIVE must
// stay fail-closed (Unqualified / native_mxfp4=false).
//
// Does NOT touch digests, heights, or 1ea2a63 economic levers.

namespace rc = matmul::v4::rc;
namespace lt = matmul::v4::lt;
namespace dc = matmul::v4::rc::dc;


BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_sm120_native_capability_tests, BasicTestingSetup)

namespace {

bool WrongGemmS8S8(const std::vector<int8_t>& /*L*/, const std::vector<int8_t>& /*R*/,
                   uint32_t rows, uint32_t /*inner*/, uint32_t cols, std::vector<int32_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, 123456789);
    return true;
}

bool WrongGemmS32S8(const std::vector<int32_t>& /*L*/, const std::vector<int8_t>& /*R*/,
                    uint32_t rows, uint32_t /*inner*/, uint32_t cols, std::vector<int32_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, -999);
    return true;
}

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

void AssertNativeMxfp4NotAdvertised(const char* ctx)
{
    BOOST_CHECK_MESSAGE(!rc::IsRcOzakiMxfp4Qualified(), ctx);
    BOOST_CHECK_MESSAGE(!matmul_v4::cuda::IsRcOzakiCudaMxfp4Qualified(), ctx);
    BOOST_CHECK_EQUAL(
        static_cast<int>(matmul_v4::cuda::RcOzakiCudaMxfp4SelectedBackend()),
        static_cast<int>(matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::Unqualified));
    const auto oz = rc::ProbeRcOzakiMxfp4Status();
    BOOST_CHECK_MESSAGE(!oz.qualified, ctx);
    BOOST_CHECK_EQUAL(static_cast<int>(oz.selected),
                      static_cast<int>(rc::RCOzakiMxfp4SelectedBackend::Unqualified));
    BOOST_CHECK(oz.backend.find("SM120_MMA") == std::string::npos);
    BOOST_CHECK(oz.backend.find("cutlass") == std::string::npos);
    const auto st = rc::ProbeRCSelfQual(lt::ExactGemmBackend{});
    BOOST_CHECK_MESSAGE(!st.native_mxfp4_qualified, ctx);
    BOOST_CHECK_MESSAGE(!st.native_fp8_qualified, ctx);
}

} // namespace

// Compile-time freeze of 1ea2a63 public inertness + datacenter levers.
static_assert(std::numeric_limits<int32_t>::max() == 2147483647);
static_assert(rc::kRCThreeAxisScheduleEnabled);
static_assert(rc::kRCAxisW0State == (48ull << 30));
static_assert(rc::kRCAxisX0Exchange == (4ull << 30));
static_assert(rc::kRCAxisC0Local == (12ull << 40));
static_assert(dc::kRCCoupFullBankScheduleEnabled);
static_assert(dc::kRCCoupMaterialExchangeEnabled);
static_assert(dc::kRCThreeAxisScheduleWireEnabled);
static_assert(dc::kRCCoupPagesPerBarrierLobe == 12u);
static_assert(dc::kRCCoupExchangeRowsDefault == 128u);
static_assert(dc::kRCMinerBatchQDefault == 32u);
static_assert(dc::kRCMinerBatchQMax == 256u);
static_assert(dc::kRCPackedBankTargetGiBCount == 4u);

BOOST_AUTO_TEST_CASE(rc_sm120_native_absent_when_dedicated_object_not_linked)
{
    // CPU / plain CUDA stub / fatbin without BTX_CUDA_SM120_MXFP4_NATIVE:
    // dedicated sm_120a object is absent → native capability stays false.
    rc::ResetRcOzakiQualForTest();
    matmul_v4::cuda::ResetRcOzakiCudaQualForTest();

#if !defined(BTX_CUDA_SM120_MXFP4_NATIVE)
    BOOST_CHECK(!matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked());
#endif

#if !defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    BOOST_CHECK(!matmul_v4::cuda::IsRcOzakiCudaCompiled());
    BOOST_CHECK(!matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked());
#endif

    if (!matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked()) {
        AssertNativeMxfp4NotAdvertised("dedicated sm_120a object absent");
        // Selected backend must never claim SM120_MMA without the linked kernel.
        BOOST_CHECK_NE(matmul_v4::cuda::RcOzakiCudaMxfp4Backend(), "SM120_MMA");
        const std::string deficit = matmul_v4::cuda::RcOzakiCudaMxfp4Deficit();
        // Honest deficit may mention not_linked / tu_not_linked / no_native / Unqualified.
        BOOST_CHECK(deficit.empty() || deficit.find("not_linked") != std::string::npos ||
                    deficit.find("tu_not_linked") != std::string::npos ||
                    deficit.find("no_native") != std::string::npos ||
                    deficit.find("Unqualified") != std::string::npos ||
                    deficit.find("not_qualified") != std::string::npos ||
                    deficit.find("no_vendor") != std::string::npos ||
                    deficit.find("scalar-decode") != std::string::npos ||
                    deficit.find("unsupported_arch") != std::string::npos ||
                    deficit.find("selfqual") != std::string::npos);
    } else {
        // sm_120a object linked: still must not claim native until self-qual passes.
        // Do not assert qualified==true here (silicon / suite dependent).
        BOOST_CHECK(matmul_v4::cuda::IsRcOzakiCudaCompiled());
        if (!matmul_v4::cuda::IsRcOzakiCudaMxfp4Qualified()) {
            BOOST_CHECK_EQUAL(
                static_cast<int>(matmul_v4::cuda::RcOzakiCudaMxfp4SelectedBackend()),
                static_cast<int>(matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::Unqualified));
        }
    }
}

BOOST_AUTO_TEST_CASE(rc_sm120_forced_selfqual_failure_fail_closed)
{
    // Forced ExactGemm self-qual failure must remain fail-closed and must NOT
    // flip native MXFP4 (Ozaki native is independent of ExactGemm mining accel).
    rc::ResetRcOzakiQualForTest();
    rc::ResetRCSelfQualCacheForTest();

    lt::ExactGemmBackend bad;
    bad.gemm_s8s8 = &WrongGemmS8S8;
    bad.gemm_s32s8 = &WrongGemmS32S8;
    BOOST_REQUIRE(bad.HasDeviceGemms());

    const rc::RCSelfQualStatus st = rc::ProbeRCSelfQual(bad);
    BOOST_CHECK(!st.mining_accelerator_ok);
    BOOST_CHECK(!st.exact_gemm_backend_ok);
    BOOST_CHECK(!st.native_fp8_qualified);
    BOOST_CHECK(!st.deficit_reason.empty());
    BOOST_CHECK(!rc::RCAcceleratorAdmissible(bad));

    // Native latch tracks Ozaki device path only — never inferred from a bad
    // ExactGemm, and never flipped by the failed self-qual itself.
    BOOST_CHECK_EQUAL(st.native_mxfp4_qualified, rc::IsRcOzakiMxfp4Qualified());
    if (!matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked()) {
        BOOST_CHECK(!st.native_mxfp4_qualified);
        BOOST_CHECK(!rc::IsRcOzakiMxfp4Qualified());
    }
}

BOOST_AUTO_TEST_CASE(rc_sm120_heights_arbiter_levers_unchanged_1ea2a63)
{
    // Public nets stay inert: heights INT32_MAX, GKR arbiter OFF, DC levers
    // match the 1ea2a63 B200:5090 economics lock (compile-time + runtime).
    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulRCCoupledHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!consensus.IsMatMulRCActive(1));
    BOOST_CHECK(!consensus.IsMatMulRCCoupledActive(1));

    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
    const dc::RCDcStatus dc_st = dc::ProbeRCDcStatus();
    BOOST_CHECK(!dc_st.gkr_arbiter);

    BOOST_CHECK(dc::kRCCoupFullBankScheduleEnabled);
    BOOST_CHECK(dc::kRCCoupMaterialExchangeEnabled);
    BOOST_CHECK(dc::kRCThreeAxisScheduleWireEnabled);
    BOOST_CHECK_EQUAL(dc::kRCCoupPagesPerBarrierLobe, 12u);
    BOOST_CHECK_EQUAL(dc::kRCCoupExchangeRowsDefault, 128u);
    BOOST_CHECK_EQUAL(dc::kRCPackedBankPrimaryGiB, 51.0);
    BOOST_CHECK_EQUAL(dc::kRCMinerBatchQDefault, 32u);
    BOOST_CHECK_EQUAL(dc::kRCMinerBatchQMax, 256u);

    BOOST_CHECK(rc::kRCThreeAxisScheduleEnabled);
    BOOST_CHECK_EQUAL(rc::kRCAxisW0State, 48ull << 30);
    BOOST_CHECK_EQUAL(rc::kRCAxisX0Exchange, 4ull << 30);
    BOOST_CHECK_EQUAL(rc::kRCAxisC0Local, 12ull << 40);
    BOOST_CHECK_EQUAL(rc::kRCAxisHardCapState, 96ull << 30);
}

BOOST_AUTO_TEST_CASE(rc_sm120_env_vars_do_not_advertise_native)
{
    // Env must never falsely advertise RC native MXFP4 / SM120_MMA.
    // (Digest-affecting DC levers are compile-time only; this covers native latch.)
    rc::ResetRcOzakiQualForTest();
    matmul_v4::cuda::ResetRcOzakiCudaQualForTest();

    EnvRestore r1("BTX_MATMUL_V4_LT_REQUIRE_NATIVE_MX");
    EnvRestore r2("BTX_RC_ACCEL_POLICY");
    EnvRestore r3("BTX_RC_GKR_ARBITER");
    EnvRestore r4("BTX_CUDA_SM120_MXFP4_NATIVE");
    EnvRestore r5("BTX_RC_OZAKI_FORCE_NATIVE");
    EnvRestore r6("BTX_MATMUL_V4_BACKEND");

    setenv("BTX_MATMUL_V4_LT_REQUIRE_NATIVE_MX", "1", /*overwrite=*/1);
    setenv("BTX_RC_ACCEL_POLICY", "native_mxfp4", /*overwrite=*/1);
    setenv("BTX_RC_GKR_ARBITER", "1", /*overwrite=*/1);
    setenv("BTX_CUDA_SM120_MXFP4_NATIVE", "1", /*overwrite=*/1);
    setenv("BTX_RC_OZAKI_FORCE_NATIVE", "1", /*overwrite=*/1);
    setenv("BTX_MATMUL_V4_BACKEND", "cuda", /*overwrite=*/1);

    // Arbiter env cannot enable EnvRCGkrArbiterEnabled while hard-disabled, and
    // must never imply native MX. Heights / DC levers remain compile-time;
    // native latch ignores these envs.
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
    BOOST_CHECK(!rc::kRCGkrFormalSoundnessReady);

    if (!matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked()) {
        AssertNativeMxfp4NotAdvertised("env must not advertise native without sm_120a object");
    } else if (!matmul_v4::cuda::IsRcOzakiCudaMxfp4Qualified()) {
        // Linked but unqualified: still Unqualified selection; env must not override.
        BOOST_CHECK_EQUAL(
            static_cast<int>(matmul_v4::cuda::RcOzakiCudaMxfp4SelectedBackend()),
            static_cast<int>(matmul_v4::cuda::RcOzakiMxfp4SelectedBackend::Unqualified));
        BOOST_CHECK(!rc::ProbeRCSelfQual(lt::ExactGemmBackend{}).native_mxfp4_qualified ||
                    rc::IsRcOzakiMxfp4Qualified());
    }

    // Restoring env happens in EnvRestore dtors; confirm native still honest after.
    unsetenv("BTX_RC_GKR_ARBITER");
    BOOST_CHECK(!rc::EnvRCGkrArbiterEnabled());
}

BOOST_AUTO_TEST_CASE(rc_sm120_plain_arch_key_never_implies_feature_qualified)
{
    // Honesty: arch_key "sm_120" (plain packaging) is not "sm_120a feature-
    // qualified". Native SM120_MMA requires the dedicated object + suite.
    rc::ResetRcOzakiQualForTest();
    const auto oz = rc::ProbeRcOzakiMxfp4Status();
    if (oz.qualified && oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM120_MMA) {
        BOOST_REQUIRE(matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked());
        // Feature-qualified evidence: linked kernel + SM120_MMA latch.
        BOOST_CHECK(oz.arch_key.find("sm_12") != std::string::npos);
        BOOST_CHECK_EQUAL(oz.backend, "SM120_MMA");
    } else {
        BOOST_CHECK(oz.selected == rc::RCOzakiMxfp4SelectedBackend::Unqualified ||
                    oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM100_CUBLASLT ||
                    oz.selected == rc::RCOzakiMxfp4SelectedBackend::SM100_MMA);
        if (!oz.qualified) {
            BOOST_CHECK(oz.backend.find("SM120_MMA") == std::string::npos ||
                        oz.backend.find("scalar") != std::string::npos);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
