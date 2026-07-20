// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_CUDA_MATMUL_V4_RC_MX_OZAKI_NATIVE_H
#define BTX_CUDA_MATMUL_V4_RC_MX_OZAKI_NATIVE_H

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC Ozaki device backends (Amendment 1.B).
// ExactGemm panels ≠ native MXFP4. Native path must not call LaunchGemmS8S8.

namespace matmul_v4::cuda {

[[nodiscard]] bool IsRcOzakiCudaCompiled();

// --- ExactGemm IMMA panels (not native MXFP4) ---
[[nodiscard]] bool IsRcOzakiCudaExactPanelsQualified();
[[nodiscard]] bool SelfQualifyRcOzakiCudaExactPanelsOnce();
[[nodiscard]] bool TryLaunchRcOzakiExactPanelsGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

// --- Native block-scaled MXFP4 (SM120 / SM100 separate latches) ---
[[nodiscard]] bool IsRcOzakiCudaMxfp4Qualified();
[[nodiscard]] std::string RcOzakiCudaMxfp4ArchKey();
[[nodiscard]] std::string RcOzakiCudaMxfp4Backend();
[[nodiscard]] bool SelfQualifyRcOzakiCudaMxfp4Once();
/** Real MXFP4 device path only — must not fall back to LaunchGemmS8S8. */
[[nodiscard]] bool TryLaunchRcOzakiMxfp4GemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

void ResetRcOzakiCudaQualForTest();

} // namespace matmul_v4::cuda

#endif // BTX_CUDA_MATMUL_V4_RC_MX_OZAKI_NATIVE_H
