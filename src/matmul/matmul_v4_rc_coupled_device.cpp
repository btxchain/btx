// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_coupled_device.h>

#include <cuda/matmul_v4_lt_accel.h>
#include <cuda/matmul_v4_rc_episode_context.h>
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
        // Honesty: never leave provider="device" on decline.
        st.provider.clear();
        st.detail = "device_gemm_declined";
        return st;
    }
    st.matched_cpu_exactgemm = (device == cpu);
    if (!st.matched_cpu_exactgemm) {
        // Honesty: never leave provider="device" on mismatch.
        st.provider.clear();
        st.detail = "device_gemm_mismatch_vs_cpu";
        return st;
    }
#if defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    st.used_tensor_imma_or_mfma = matmul_v4::cuda::LtLastS8S8UsedImma();
    // Honesty: never report cuda_imma / mfma / tensor when the path was ALU.
    st.provider = st.used_tensor_imma_or_mfma ? "cuda_imma" : "cuda_alu";
#elif defined(BTX_ENABLE_HIP)
    st.used_tensor_imma_or_mfma = matmul_v4::hip::LtLastS8S8UsedMfma();
    st.provider = st.used_tensor_imma_or_mfma ? "hip_mfma" : "hip_alu";
#elif defined(BTX_ENABLE_METAL)
    st.used_tensor_imma_or_mfma = matmul_v4::metal::LtLastS8S8UsedTensorOps();
    st.provider = st.used_tensor_imma_or_mfma ? "metal_tensor_ops" : "metal_alu";
#else
    st.used_tensor_imma_or_mfma = false;
    st.provider = "alu_or_stub";
#endif
    st.detail = "ok";
    return st;
}

RCCudaEpisodeResidentProbe ProbeRCCudaEpisodeResident()
{
    RCCudaEpisodeResidentProbe st;
    st.cuda_episode_compiled = matmul_v4::cuda::IsRcEpisodeCudaCompiled();
    st.device_bank_resident_api = true;
    st.graph_capture_once_api = true;
    st.host_bridge_removed = true; // MineCoupledPuzzle ExactGemm bridge gone
    st.peak_ready = false;
    st.device_digest = false; // AssembleCoupledEpisodeDigest remains on host
    if (!st.cuda_episode_compiled) {
        st.permute_extract_parked = true;
        st.gemm_path_label = "stub_not_wired";
        st.parked_reason = "graph_unavailable:not_wired";
        st.detail = "cpu_stub_build";
        return st;
    }
    // CUDA TU: device_barrier_tail (permute/mix/Extract/BarrierRoot) is wired;
    // episode digest + native MXFP4 remain residual → peak_ready stays false.
    st.permute_extract_parked = false;
    st.gemm_path_label = "portable_device_alu";
    st.parked_reason =
        "AssembleCoupledEpisodeDigest_on_host; native_mxfp4_device_ptr_awaiting_wsB; "
        "peak_ready=false";
    st.detail = "device_barrier_tail; resident_gemm_graph_api_ready; peak_ready=false";
    return st;
}

} // namespace matmul::v4::rc
