// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_coupled_device.h>

#include <cuda/matmul_v4_lt_accel.h>
#include <hip/matmul_v4_lt_accel.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_lt.h>
#include <metal/matmul_v4_lt_accel.h>

#include <vector>

namespace matmul::v4::rc {
namespace {

namespace lt = matmul::v4::lt;

} // namespace

RCCoupledDeviceProbe ProbeRCCoupledDevice()
{
    RCCoupledDeviceProbe st;
    // Same RC-gated ExactGemm resolve used by MineCoupledPuzzle / harness:
    // CUDA/HIP/Metal LaunchGemmS8S8 when available and self-qualified.
    const lt::ExactGemmBackend backend = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
    if (backend.gemm_s8s8 == nullptr) {
        st.provider = "cpu";
        st.detail = "no_device_backend_after_rc_selfqual";
        return st;
    }
    st.backend_resolved = true;
    st.provider = "device";

    // Toy coupled lobe shape: 1×32 · 32×32 → 1×32 (local ExactGemm per lobe).
    constexpr uint32_t k = 32;
    std::vector<int8_t> L(k);
    std::vector<int8_t> page(static_cast<size_t>(k) * k);
    for (uint32_t i = 0; i < k; ++i) {
        L[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 97) - 48);
    }
    for (uint32_t i = 0; i < k * k; ++i) {
        page[i] = static_cast<int8_t>((static_cast<int32_t>(i * 5) % 95) - 47);
    }
    const std::vector<int32_t> cpu = lt::ExactGemmS8S8(L, page, /*rows=*/1, k, k);
    std::vector<int32_t> device;
    bool ok = false;
    try {
        ok = backend.gemm_s8s8(L, page, /*rows=*/1, k, k, device);
    } catch (...) {
        ok = false;
    }
    st.device_gemm_returned = ok;
    if (!ok) {
        st.detail = "device_gemm_declined";
        return st;
    }
    st.matched_cpu_exactgemm = (device == cpu);
    if (!st.matched_cpu_exactgemm) {
        st.detail = "device_gemm_mismatch_vs_cpu";
        return st;
    }
#if defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    st.used_tensor_imma_or_mfma = matmul_v4::cuda::LtLastS8S8UsedImma();
    if (st.used_tensor_imma_or_mfma) st.provider = "cuda_imma";
    else st.provider = "cuda_or_device";
#elif defined(BTX_ENABLE_HIP)
    st.used_tensor_imma_or_mfma = matmul_v4::hip::LtLastS8S8UsedMfma();
    if (st.used_tensor_imma_or_mfma) st.provider = "hip_mfma";
    else st.provider = "hip_or_device";
#elif defined(BTX_ENABLE_METAL)
    st.used_tensor_imma_or_mfma = matmul_v4::metal::LtLastS8S8UsedTensorOps();
    if (st.used_tensor_imma_or_mfma) st.provider = "metal_tensor_ops";
    else st.provider = "metal_or_device";
#else
    st.provider = "resolved_device_stub_or_alu";
#endif
    st.detail = "ok";
    return st;
}

} // namespace matmul::v4::rc
