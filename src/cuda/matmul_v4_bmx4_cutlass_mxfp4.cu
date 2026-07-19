// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_bmx4_cutlass_mxfp4.h>

#include <matmul/matmul_v4_bmx4.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#if defined(BTX_BMX4C_CUTLASS_HEADERS)
#include <cutlass/cutlass.h>
// Future: #include <cutlass/gemm/device/...mxfp4...> once the pinned recipe lands.
#endif

// CUTLASS grouped MXFP4 tensor TU (CMake BTX_BMX4C_CUTLASS_MXFP4=ON).
//
// This translation unit is compiled ONLY when the option is on and CUDA is
// enabled. IsGroupedMxfp4TensorKernelLinked returns true ONLY after a
// process-local self-qualification against the portable exact grouped path
// passes on a real tensor launch.
//
// Until a pinned tcgen05 grouped kernel body is brought up on Blackwell silicon,
// LaunchCutlassGroupedMxfp4Tensor fails closed and self-qual never passes —
// callers keep using the portable exact path. That is intentional honesty:
// compiling this TU must not advertise a tensor path that does not run.

namespace matmul_v4::cuda::cutlass_mxfp4 {
namespace {

[[nodiscard]] bool LaunchCutlassGroupedMxfp4Tensor(GroupedMxfp4Orientation /*orient*/,
                                                   const int8_t* /*proj*/,
                                                   const int8_t* /*mantissa*/,
                                                   const uint8_t* /*scale*/,
                                                   uint32_t /*n*/,
                                                   uint32_t /*m*/,
                                                   std::vector<int32_t>& /*out*/,
                                                   GroupedMxfp4Problem* /*shape*/,
                                                   std::string& error)
{
    // Fail closed: headers alone are not a working OCP-MXFP4 grouped kernel.
    // Portable LaunchGroupedMxfp4Projection remains the exact fallback.
    error = "CUTLASS MXFP4 grouped tensor kernel TU compiled but no qualified "
            "tcgen05 recipe is linked for this toolkit/silicon; use portable exact path";
    return false;
}

[[nodiscard]] bool SelfQualifyCutlassMxfp4Once()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        // Tiny deterministic fixture: tensor launch must match portable exact.
        constexpr uint32_t n = 32;
        constexpr uint32_t m = 8;
        std::vector<int8_t> U(static_cast<size_t>(m) * n, 1);
        std::vector<int8_t> mu(static_cast<size_t>(n) * n, 2);
        std::vector<uint8_t> scale(static_cast<size_t>(n) * (n / kBlockLen), 0);
        for (uint32_t i = 0; i < n; ++i) {
            for (uint32_t kb = 0; kb < n / kBlockLen; ++kb) {
                scale[static_cast<size_t>(i) * (n / kBlockLen) + kb] =
                    static_cast<uint8_t>((i + kb) % kNumScaleCodes);
            }
        }

        std::vector<int32_t> portable;
        GroupedMxfp4Problem shape{};
        std::string err;
        if (!GroupedMxfp4ProjectLeft(U.data(), mu.data(), scale.data(), n, m, portable, &shape, err)) {
            return;
        }

        std::vector<int32_t> tensor;
        if (!LaunchCutlassGroupedMxfp4Tensor(GroupedMxfp4Orientation::Left, U.data(), mu.data(),
                                             scale.data(), n, m, tensor, nullptr, err)) {
            return; // fail closed — do not advertise Linked
        }
        if (tensor != portable) {
            return;
        }
        ok = true;
    });
    return ok;
}

} // namespace

bool IsGroupedMxfp4TensorKernelCompiled()
{
#if defined(BTX_BMX4C_CUTLASS_HEADERS)
    return true;
#else
    return false;
#endif
}

bool IsGroupedMxfp4TensorKernelLinked()
{
    // Compiled TU + CUTLASS headers + passed self-qual. Never true on flag alone.
    if (!IsGroupedMxfp4TensorKernelCompiled()) {
        return false;
    }
    return SelfQualifyCutlassMxfp4Once();
}

} // namespace matmul_v4::cuda::cutlass_mxfp4
