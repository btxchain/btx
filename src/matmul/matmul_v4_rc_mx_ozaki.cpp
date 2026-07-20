// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_mx_ozaki.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc {
namespace {

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

} // namespace

bool IsRcOzakiMxfp4Qualified()
{
    // Amendment 1.B: RC native MXFP4 stays false until Ozaki device path quals.
    return false;
}

RCOzakiMxfp4Status ProbeRcOzakiMxfp4Status()
{
    RCOzakiMxfp4Status st;
    st.attempted = false;
    st.qualified = false;
    st.deficit_reason =
        "ozaki_mxfp4_not_wired; see doc/btx-matmul-v4.5-rc-native-fp4-ozaki-plan-2026-07-20.md";
    return st;
}

bool TryRcOzakiMxfp4GemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                 const std::vector<int8_t>& /*right*/, uint32_t /*rows*/,
                                 uint32_t /*inner*/, uint32_t /*cols*/,
                                 std::vector<int64_t>& out)
{
    // Fail-closed: no device FP4 limb path yet. Callers must use int64 oracle
    // or RcOzakiCpuLimbSplitGemmS8S8Int64 (CPU reference only).
    out.clear();
    return false;
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
    // Bound check: each panel must satisfy ExactGemm's <2^24 product regime.
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

} // namespace matmul::v4::rc
