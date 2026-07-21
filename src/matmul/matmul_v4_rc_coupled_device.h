// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_COUPLED_DEVICE_H
#define BTX_MATMUL_MATMUL_V4_RC_COUPLED_DEVICE_H

#include <cstdint>
#include <string>

// ENC_RC Stage C — multi-backend readiness for coupled local lobe GEMMs.
//
// Mining / harness path:
//   gemm = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
//   MineCoupledPuzzle(header, height, params, gemm);
//
// Resident CUDA episode path (Workstream C):
//   RCCudaEpisodeContext — bank/state resident + once-captured GEMM graph.
//   ProbeRCCudaEpisodeResident() reports honest residency / parked stages.
//
// MakeResolvedExactGemmBackendForRC wires CUDA/HIP/Metal LaunchGemmS8S8 (or
// Ascend/TPU when admitted) only after ProbeRCSelfQual. Empty backend ⇒ CPU
// ExactGemmS8S8 (fail-closed). Consensus REJECT always passes an empty backend.
//
// Vendor stubs (!BTX_ENABLE_CUDA_EXPERIMENTAL / !BTX_ENABLE_HIP / !BTX_ENABLE_METAL)
// keep LaunchGemmS8S8 returning false so ResolveBackend selects CPU — no silent
// native_* claim. See doc/btx-matmul-v4.4-multi-vendor-exactgemm-architecture-2026-07-19.md
// § "ENC_RC coupled local GEMM".

namespace matmul::v4::rc {

/** Probe whether coupled local ExactGemm can exercise a resolved CUDA/HIP/Metal
 *  device backend after RC self-qual (s8×s8 dequant path). Skip-friendly in tests
 *  when no GPU is present. Never sets native_mxfp4 / native_fp8. */
struct RCCoupledDeviceProbe {
    bool backend_resolved{false};
    bool device_gemm_returned{false};
    bool matched_cpu_exactgemm{false};
    bool used_tensor_imma_or_mfma{false}; // informational; false when stub/CPU
    std::string provider;                // "cuda" / "hip" / "metal" / "cpu" / …
    std::string detail;
};

[[nodiscard]] RCCoupledDeviceProbe ProbeRCCoupledDevice();

/**
 * Honest snapshot of the CUDA resident episode path (Workstream C).
 * peak_ready / device_digest remain false until device Extract + qualified
 * native MXFP4 device-ptr GEMMs are wired end-to-end.
 */
struct RCCudaEpisodeResidentProbe {
    bool cuda_episode_compiled{false};
    bool device_bank_resident_api{false};
    bool graph_capture_once_api{false};
    bool host_bridge_removed{false};
    bool peak_ready{false};
    bool device_digest{false};
    bool permute_extract_parked{true};
    std::string gemm_path_label;
    std::string parked_reason;
    std::string detail;
};

[[nodiscard]] RCCudaEpisodeResidentProbe ProbeRCCudaEpisodeResident();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_COUPLED_DEVICE_H
