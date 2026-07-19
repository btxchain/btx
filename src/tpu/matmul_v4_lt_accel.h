// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TPU_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_TPU_MATMUL_V4_LT_ACCEL_H

#include <cstddef>
#include <cstdint>
#include <vector>

// Cloud TPU/PJRT boundary for the v4.4-LT ExactGemm lane.
//
// libtpu is a PJRT plugin, while BTX is not an OpenXLA/Bazel application.  To
// avoid making BTX depend on PJRT's large and evolving C API surface, a small
// bridge built against the installed OpenXLA/libtpu release registers this
// versioned provider.  Registration and every launch fail closed unless BTX
// was built with BTX_HAVE_TPU_PJRT.
//
// The provider must execute the matrix product on a TPU MXU. It may use native
// INT8 accumulation or the mathematically exact bounded BF16 -> FP32 path: BTX
// proves that every possible partial sum is within 2^24 before launching.
// Merely obtaining the right result through a CPU fallback is not sufficient:
// `used_exact_mxu` must be set by the provider. BTX independently self-qualifies
// the provider against the CPU ExactGemm transcript before exposing it.

namespace matmul_v4::tpu {

inline constexpr uint32_t kTpuPjrtExactGemmProviderAbiV1 = 1;

struct TpuPjrtExactGemmProviderV1 {
    uint32_t abi_version{kTpuPjrtExactGemmProviderAbiV1};
    size_t struct_size{sizeof(TpuPjrtExactGemmProviderV1)};
    const char* provider_name{nullptr};
    void* context{nullptr};

    // Inputs and output are contiguous row-major arrays. For BF16 execution,
    // the provider must require FP32 accumulation, check every FP32 output is
    // finite/integral/in-S32-range, and convert it exactly to S32. The callback
    // must not throw, must be concurrent-call safe, and returns false on any
    // PJRT compile/load/transfer/execute or conversion error. `used_exact_mxu`
    // may be true only for native MXU execution, never a host fallback.
    bool (*gemm_s8s8)(void* context, const int8_t* left, size_t left_elems,
                      const int8_t* right, size_t right_elems,
                      uint32_t rows, uint32_t inner, uint32_t cols,
                      int32_t* out, size_t out_elems,
                      bool* used_exact_mxu){nullptr};
};

/** Register the process-lifetime PJRT bridge.  First provider wins. */
[[nodiscard]] bool RegisterTpuPjrtExactGemmProvider(
    const TpuPjrtExactGemmProviderV1& provider);

/** Test-only lifecycle hook.  Production code must not replace a provider. */
void ResetTpuPjrtExactGemmProviderForTesting();

/** True only after the registered provider passes all exactness probes and
 *  reports that a TPU MXU—not a host fallback—executed every probe. */
[[nodiscard]] bool IsTpuPjrtExactGemmAvailable();

/** ExactGemmBackend::S8S8Fn-compatible adapter. */
[[nodiscard]] bool TryLaunchLtTpuGemmS8S8(const std::vector<int8_t>& left,
                                          const std::vector<int8_t>& right,
                                          uint32_t rows, uint32_t inner, uint32_t cols,
                                          std::vector<int32_t>& out);

/** No documented TPU exact S32 x S8 MXU contract exists; always declines. */
[[nodiscard]] bool TryLaunchLtTpuGemmS32S8(const std::vector<int32_t>& left,
                                           const std::vector<int8_t>& right,
                                           uint32_t rows, uint32_t inner, uint32_t cols,
                                           std::vector<int32_t>& out);

} // namespace matmul_v4::tpu

#endif // BITCOIN_TPU_MATMUL_V4_LT_ACCEL_H
