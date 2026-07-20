// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_mx_ozaki.h>

#include <cuda/matmul_v4_rc_mx_ozaki_native.h>

#include <algorithm>
#include <mutex>
#include <string>

namespace matmul::v4::rc {
namespace {

std::mutex g_host_mu;
bool g_exact_ran{false};
bool g_exact_qualified{false};
std::string g_exact_deficit;

bool g_mx_ran{false};
bool g_mx_attempted{false};
bool g_mx_qualified{false};
std::string g_mx_backend;
std::string g_mx_arch_key;
std::string g_mx_deficit;

std::vector<int32_t> ExactGemmS8S8DispatchedLocal(const lt::ExactGemmBackend& gemm,
                                                  const std::vector<int8_t>& L,
                                                  const std::vector<int8_t>& R, uint32_t rows,
                                                  uint32_t inner, uint32_t cols)
{
    if (gemm.gemm_s8s8 != nullptr) {
        std::vector<int32_t> device;
        if (gemm.gemm_s8s8(L, R, rows, inner, cols, device) &&
            device.size() == static_cast<size_t>(rows) * cols) {
            return device;
        }
    }
    return lt::ExactGemmS8S8(L, R, rows, inner, cols);
}

[[nodiscard]] bool DenseInt64GemmLocal(const std::vector<int8_t>& left,
                                       const std::vector<int8_t>& right, uint32_t rows,
                                       uint32_t inner, uint32_t cols, std::vector<int64_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            int64_t acc = 0;
            for (uint32_t k = 0; k < inner; ++k) {
                acc += static_cast<int64_t>(left[static_cast<size_t>(r) * inner + k]) *
                       static_cast<int64_t>(right[static_cast<size_t>(k) * cols + c]);
            }
            out[static_cast<size_t>(r) * cols + c] = acc;
        }
    }
    return true;
}

/** Adversarial M11×E8M0 max corner: alternating ±6·2^e along K blocks. */
void FillM11E8M0MaxPanel(std::vector<int8_t>& L, std::vector<int8_t>& R, uint32_t rows,
                         uint32_t inner, uint32_t cols, uint32_t seed, uint8_t e)
{
    L.assign(static_cast<size_t>(rows) * inner, 0);
    R.assign(static_cast<size_t>(inner) * cols, 0);
    const int32_t mag = 6 * (1 << e);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t k = 0; k < inner; ++k) {
            const bool neg = ((r + k + seed) & 1u) != 0;
            L[static_cast<size_t>(r) * inner + k] =
                static_cast<int8_t>(neg ? -mag : mag);
        }
    }
    for (uint32_t k = 0; k < inner; ++k) {
        for (uint32_t c = 0; c < cols; ++c) {
            const bool neg = ((k * 3u + c + seed) & 1u) != 0;
            R[static_cast<size_t>(k) * cols + c] =
                static_cast<int8_t>(neg ? -mag : mag);
        }
    }
}

void FillPseudoPanel(std::vector<int8_t>& L, std::vector<int8_t>& R, uint32_t rows,
                     uint32_t inner, uint32_t cols, uint32_t seed)
{
    L.resize(static_cast<size_t>(rows) * inner);
    R.resize(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < L.size(); ++i) {
        L[i] = static_cast<int8_t>((static_cast<int32_t>(i + seed) % 13) - 6);
    }
    for (size_t i = 0; i < R.size(); ++i) {
        R[i] = static_cast<int8_t>((static_cast<int32_t>(i * 5 + seed) % 11) - 5);
    }
}

[[nodiscard]] bool ExactPanelsMatchOracle(uint32_t rows, uint32_t inner, uint32_t cols,
                                          uint32_t seed, bool max_corner, uint8_t e,
                                          std::string& reason)
{
    std::vector<int8_t> L, R;
    if (max_corner) {
        FillM11E8M0MaxPanel(L, R, rows, inner, cols, seed, e);
    } else {
        FillPseudoPanel(L, R, rows, inner, cols, seed);
    }
    std::vector<int64_t> oracle;
    DenseInt64GemmLocal(L, R, rows, inner, cols, oracle);

    if (matmul_v4::cuda::IsRcOzakiCudaCompiled()) {
        std::vector<int64_t> device;
        std::string err;
        if (matmul_v4::cuda::TryLaunchRcOzakiExactPanelsGemmS8S8Int64(L, R, rows, inner, cols,
                                                                      device, &err) &&
            device == oracle) {
            return true;
        }
        // Fall through to portable ExactGemm panels if CUDA declines.
    }

    std::vector<int64_t> limb;
    if (!RcOzakiCpuLimbSplitGemmS8S8Int64(L, R, rows, inner, cols, limb)) {
        reason = "ozaki_cpu_limb_split_failed";
        return false;
    }
    if (limb != oracle) {
        reason = "ozaki_exact_panels_mismatch_vs_int64_oracle";
        return false;
    }
    return true;
}

struct ExactPanelsQualResult {
    bool qualified{false};
    std::string deficit;
};

[[nodiscard]] ExactPanelsQualResult RunExactPanelsSelfQualBody()
{
    ExactPanelsQualResult r;
    if (matmul_v4::cuda::IsRcOzakiCudaCompiled() &&
        matmul_v4::cuda::SelfQualifyRcOzakiCudaExactPanelsOnce() &&
        matmul_v4::cuda::IsRcOzakiCudaExactPanelsQualified()) {
        r.qualified = true;
        return r;
    }

    std::string reason;
    const bool ok =
        ExactPanelsMatchOracle(8, 8, 8, /*seed=*/1, /*max_corner=*/false, 0, reason) &&
        ExactPanelsMatchOracle(16, 8192, 16, /*seed=*/7, /*max_corner=*/false, 0, reason) &&
        ExactPanelsMatchOracle(8, 4096, 8, /*seed=*/3, /*max_corner=*/true, /*e=*/3, reason) &&
        ExactPanelsMatchOracle(4, 4095, 4, /*seed=*/11, /*max_corner=*/true, /*e=*/2, reason) &&
        ExactPanelsMatchOracle(4, 4097, 4, /*seed=*/13, /*max_corner=*/true, /*e=*/1, reason);
    if (!ok) {
        r.deficit = reason.empty() ? "ozaki_exact_panels_selfqual_failed" : reason;
        return r;
    }
    r.qualified = true;
    return r;
}

struct Mxfp4QualResult {
    bool attempted{false};
    bool qualified{false};
    std::string backend;
    std::string arch_key;
    std::string deficit;
};

[[nodiscard]] Mxfp4QualResult RunMxfp4SelfQualBody()
{
    Mxfp4QualResult r;
    r.attempted = true;
    if (!matmul_v4::cuda::IsRcOzakiCudaCompiled()) {
        r.deficit = "rc_ozaki_mxfp4_cuda_tu_not_linked";
        return r;
    }
    if (!matmul_v4::cuda::SelfQualifyRcOzakiCudaMxfp4Once() ||
        !matmul_v4::cuda::IsRcOzakiCudaMxfp4Qualified()) {
        r.deficit = "rc_ozaki_mxfp4_device_selfqual_failed";
        return r;
    }
    r.qualified = true;
    r.backend = matmul_v4::cuda::RcOzakiCudaMxfp4Backend();
    r.arch_key = matmul_v4::cuda::RcOzakiCudaMxfp4ArchKey();
    if (r.backend.empty()) r.backend = "mxfp4_blockscaled_device";
    return r;
}

} // namespace

bool IsRcOzakiExactPanelsQualified()
{
    std::lock_guard<std::mutex> lock(g_host_mu);
    return g_exact_qualified;
}

bool IsRcOzakiMxfp4Qualified()
{
    std::lock_guard<std::mutex> lock(g_host_mu);
    return g_mx_qualified;
}

RCOzakiMxfp4Status ProbeRcOzakiMxfp4Status()
{
    (void)SelfQualifyRcOzakiExactPanelsOnce();
    (void)SelfQualifyRcOzakiMxfp4Once();
    RCOzakiMxfp4Status st;
    std::lock_guard<std::mutex> lock(g_host_mu);
    st.attempted = g_mx_attempted;
    st.qualified = g_mx_qualified;
    st.exact_panels_qualified = g_exact_qualified;
    st.backend = g_mx_backend;
    st.arch_key = g_mx_arch_key;
    if (g_mx_qualified) {
        st.deficit_reason.clear();
    } else if (!g_mx_deficit.empty()) {
        st.deficit_reason = g_mx_deficit;
    } else if (!g_mx_attempted) {
        st.deficit_reason = "ozaki_mxfp4_not_probed";
    } else {
        st.deficit_reason = "ozaki_mxfp4_not_qualified";
    }
    return st;
}

bool SelfQualifyRcOzakiExactPanelsOnce()
{
    {
        std::lock_guard<std::mutex> lock(g_host_mu);
        if (g_exact_ran) return g_exact_qualified;
        g_exact_ran = true;
    }
    // Run GEMMs outside the latch mutex (CUDA / ExactGemm may take other locks).
    const ExactPanelsQualResult r = RunExactPanelsSelfQualBody();
    std::lock_guard<std::mutex> lock(g_host_mu);
    g_exact_qualified = r.qualified;
    g_exact_deficit = r.deficit;
    return g_exact_qualified;
}

bool SelfQualifyRcOzakiMxfp4Once()
{
    {
        std::lock_guard<std::mutex> lock(g_host_mu);
        if (g_mx_ran) return g_mx_qualified;
        g_mx_ran = true;
    }
    const Mxfp4QualResult r = RunMxfp4SelfQualBody();
    std::lock_guard<std::mutex> lock(g_host_mu);
    g_mx_attempted = r.attempted;
    g_mx_qualified = r.qualified;
    g_mx_backend = r.backend;
    g_mx_arch_key = r.arch_key;
    g_mx_deficit = r.deficit;
    return g_mx_qualified;
}

bool TryRcOzakiMxfp4GemmS8S8Int64(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                 uint32_t rows, uint32_t inner, uint32_t cols,
                                 std::vector<int64_t>& out)
{
    out.clear();
    if (!SelfQualifyRcOzakiMxfp4Once() || !IsRcOzakiMxfp4Qualified()) {
        return false;
    }
    // Honesty: native claim must use the MXFP4 device path only — never ExactGemm.
    std::string err;
    return matmul_v4::cuda::TryLaunchRcOzakiMxfp4GemmS8S8Int64(left, right, rows, inner, cols, out,
                                                                &err);
}

bool TryRcOzakiExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                       const std::vector<int8_t>& right, uint32_t rows,
                                       uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                       const lt::ExactGemmBackend& gemm)
{
    out.clear();
    if (!SelfQualifyRcOzakiExactPanelsOnce() || !IsRcOzakiExactPanelsQualified()) {
        return false;
    }
    if (matmul_v4::cuda::IsRcOzakiCudaCompiled()) {
        std::string err;
        if (matmul_v4::cuda::TryLaunchRcOzakiExactPanelsGemmS8S8Int64(left, right, rows, inner,
                                                                      cols, out, &err)) {
            return true;
        }
    }
    return RcOzakiCpuLimbSplitGemmS8S8Int64(left, right, rows, inner, cols, out, gemm);
}

bool RcOzakiCpuLimbSplitGemmS8S8Int64(const std::vector<int8_t>& left,
                                     const std::vector<int8_t>& right, uint32_t rows,
                                     uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                     const matmul::v4::lt::ExactGemmBackend& gemm)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) return false;
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        return false;
    }
    static_assert(static_cast<uint64_t>(kRCOzakiExactChunk) * 2304ull < (uint64_t{1} << 24),
                  "kRCOzakiExactChunk must keep 2304·chunk < 2^24");

    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t k0 = 0; k0 < inner; k0 += kRCOzakiExactChunk) {
        const uint32_t len = std::min(kRCOzakiExactChunk, inner - k0);
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * len);
        std::vector<int8_t> Rpanel(static_cast<size_t>(len) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < len; ++t) {
                Lpanel[static_cast<size_t>(r) * len + t] =
                    left[static_cast<size_t>(r) * inner + (k0 + t)];
            }
        }
        for (uint32_t t = 0; t < len; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k0 + t) * cols + c];
            }
        }
        const auto partial =
            ExactGemmS8S8DispatchedLocal(gemm, Lpanel, Rpanel, rows, len, cols);
        if (partial.size() != out.size()) {
            out.clear();
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    return true;
}

void ResetRcOzakiQualForTest()
{
    std::lock_guard<std::mutex> lock(g_host_mu);
    g_exact_ran = false;
    g_exact_qualified = false;
    g_exact_deficit.clear();
    g_mx_ran = false;
    g_mx_attempted = false;
    g_mx_qualified = false;
    g_mx_backend.clear();
    g_mx_arch_key.clear();
    g_mx_deficit.clear();
    matmul_v4::cuda::ResetRcOzakiCudaQualForTest();
}

} // namespace matmul::v4::rc
