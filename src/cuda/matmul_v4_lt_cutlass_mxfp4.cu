// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_cutlass_mxfp4.h>

#include <matmul/matmul_v4_lt_mx_exact.h>

#include <cuda_runtime.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#if defined(BTX_BMX4C_CUTLASS_HEADERS)
#include <cutlass/cutlass.h>
// Pinned SM120 OCP MXFP4 recipe (mx_float4_t + UE8M0 / block-32), mirroring
// CUTLASS examples/79_blackwell_geforce_gemm/79c_* and Colfax MXFP4 notes:
//   using ElementA = cutlass::mx_float4_t<cutlass::float_e2m1_t>;
//   using ElementB = cutlass::mx_float4_t<cutlass::float_e2m1_t>;
//   using ArchTag = cutlass::arch::Sm120;
//   using OperatorClass = cutlass::arch::OpClassBlockScaledTensorOp;
//   ClusterShape = Shape<_1,_1,_1>;  // GeForce: no TMA multicast
// Full CollectiveBuilder / GemmUniversalAdapter is intentionally NOT
// instantiated here until a toolkit+silicon pair self-qualifies bit-identical
// to MxProjectionMatchesCpuOracle. Headers alone must not advertise a path.
#endif

// LT CUTLASS SM120 OCP MXFP4 TU (CMake BTX_BMX4C_CUTLASS_MXFP4 / BTX_LT_CUTLASS_MXFP4).
// Pack path is complete; tensor launch stays fail-closed until a pinned recipe
// passes the same oracle as matmul_v4_lt_mx_native.cu.

namespace matmul_v4::cuda::lt_cutlass_mxfp4 {
namespace {

[[nodiscard]] bool DeviceLooksBlackwellSm120Family()
{
    int device = 0;
    if (cudaGetDevice(&device) != cudaSuccess) return false;
    cudaDeviceProp props{};
    if (cudaGetDeviceProperties(&props, device) != cudaSuccess) return false;
    // Consumer Blackwell (sm_120 / sm_121) is the GeForce OCP MXFP4 target.
    // Datacenter sm_100 needs a separate sm_100a recipe — decline here.
    return (props.major == 12);
}

/**
 * Host-visible CUTLASS attempt: pack → (optional) block-scaled GEMM → int32.
 * Until a pinned CollectiveBuilder body is linked and oracle-qualified, this
 * returns false after validating the pack (honest decline, not a float stub).
 */
[[nodiscard]] bool LaunchCutlassSm120OcpMxfp4ProjectedRight(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    std::string& error)
{
    out.clear();

#if !defined(BTX_BMX4C_CUTLASS_HEADERS)
    error = "LT CUTLASS MXFP4: CUTLASS headers not compiled in (BTX_BMX4C_CUTLASS_HEADERS)";
    return false;
#else
    if (!DeviceLooksBlackwellSm120Family()) {
        error = "LT CUTLASS MXFP4: device is not SM120-family (OCP MXFP4 GeForce recipe)";
        return false;
    }

    std::vector<uint8_t> a_e2m1;
    std::vector<uint8_t> b_e2m1;
    std::vector<uint8_t> sfa;
    std::vector<uint8_t> sfb;
    if (!PackProjectedRightMxToCutlassMxfp4(mu.data(), scales.data(), V.data(), n, m, a_e2m1,
                                            b_e2m1, sfa, sfb, error)) {
        return false;
    }

    // Recipe gate: cutlass.h is present and pack succeeded, but no qualified
    // Sm120 mx_float4_t GemmUniversalAdapter is linked for this toolkit.
    // Wiring the CollectiveBuilder here without silicon self-qual would either
    // fail to compile across CUTLASS versions or ship an unqualified float path.
    (void)a_e2m1;
    (void)b_e2m1;
    (void)sfa;
    (void)sfb;
#if defined(CUTLASS_ARCH_MMA_SM120_SUPPORTED) || defined(CUTLASS_ARCH_MMA_SM121_SUPPORTED)
    error = "LT CUTLASS MXFP4: SM120 arch macros present but no pinned OCP "
            "mx_float4_t block-scaled recipe is linked/self-qualified; decline";
#else
    error = "LT CUTLASS MXFP4: CUTLASS headers present but CUTLASS_ARCH_MMA_SM120_SUPPORTED "
            "not set for this toolkit; decline";
#endif
    return false;
#endif // BTX_BMX4C_CUTLASS_HEADERS
}

[[nodiscard]] bool SelfQualifyCutlassLtMxfp4Once()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        const std::pair<uint32_t, uint32_t> shapes[] = {
            {32, 16},
            {64, 32},
            {64, 17},
            {96, 48},
        };
        for (const auto& [n, m] : shapes) {
            if ((n % kBlockLen) != 0) return;
            std::vector<int8_t> mu(static_cast<size_t>(n) * n, 1);
            std::vector<uint8_t> scales(static_cast<size_t>(n) * (n / kBlockLen), 1);
            std::vector<int8_t> V(static_cast<size_t>(n) * m, 2);
            std::vector<int32_t> got;
            std::string err;
            if (!LaunchCutlassSm120OcpMxfp4ProjectedRight(mu, scales, V, n, m, got, err)) {
                return;
            }
            if (!matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, got)) {
                return;
            }
        }
        ok = true;
    });
    return ok;
}

} // namespace

bool IsLtCutlassMxfp4Compiled()
{
#if defined(BTX_BMX4C_CUTLASS_HEADERS)
    return true;
#else
    return false;
#endif
}

bool IsLtCutlassMxfp4Linked()
{
    if (!IsLtCutlassMxfp4Compiled()) return false;
    return SelfQualifyCutlassLtMxfp4Once();
}

bool TryLaunchCutlassMxfp4ProjectedRight(const std::vector<int8_t>& mu,
                                         const std::vector<uint8_t>& scales,
                                         const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                         std::vector<int32_t>& out, std::string* error)
{
    std::string local_err;
    std::string& err = error ? *error : local_err;
    if (n == 0 || m == 0 || (n % kBlockLen) != 0) {
        err = "TryLaunchCutlassMxfp4ProjectedRight: bad dims";
        out.clear();
        return false;
    }
    const uint32_t nblk = n / kBlockLen;
    if (mu.size() != static_cast<size_t>(n) * n ||
        scales.size() != static_cast<size_t>(n) * nblk ||
        V.size() != static_cast<size_t>(n) * m) {
        err = "TryLaunchCutlassMxfp4ProjectedRight: size mismatch";
        out.clear();
        return false;
    }
    if (!LaunchCutlassSm120OcpMxfp4ProjectedRight(mu, scales, V, n, m, out, err)) {
        out.clear();
        return false;
    }
    if (!matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        err = "TryLaunchCutlassMxfp4ProjectedRight: oracle mismatch";
        out.clear();
        return false;
    }
    return true;
}

} // namespace matmul_v4::cuda::lt_cutlass_mxfp4
