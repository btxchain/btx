// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/matmul_v4_rc_ozaki_accel.h>

#include <matmul/matmul_v4_rc_mx_ozaki.h>

#include <mutex>
#include <string>
#include <vector>

// Host / non-Darwin TU: unit-byte-exact Ozaki ExactPanels reference.
// Device Metal path is NOT linked here — HARD BLOCKER latch documents the
// missing part: Apple silicon + Metal (.mm TU + self-qual).

namespace matmul_v4::metal {
namespace {

std::mutex g_mu;
bool g_exact_ran{false};
bool g_exact_qualified{false};
bool g_mx_ran{false};

[[nodiscard]] bool DenseInt64(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                              uint32_t rows, uint32_t inner, uint32_t cols,
                              std::vector<int64_t>& out)
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

} // namespace

bool IsRcOzakiMetalCompiled()
{
    return false;
}

std::string RcOzakiMetalDeficit()
{
    return "requires Apple silicon + Metal";
}

bool HostReferenceRcOzakiExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                                 const std::vector<int8_t>& right, uint32_t rows,
                                                 uint32_t inner, uint32_t cols,
                                                 std::vector<int64_t>& out, std::string* error)
{
    // Portable ExactGemm limb-split — byte-identical to int64 dense oracle.
    if (!matmul::v4::rc::RcOzakiCpuLimbSplitGemmS8S8Int64(left, right, rows, inner, cols, out)) {
        if (error) *error = "metal_rc_ozaki_host_limb_split_failed";
        return false;
    }
    std::vector<int64_t> dense;
    DenseInt64(left, right, rows, inner, cols, dense);
    if (out != dense) {
        if (error) *error = "metal_rc_ozaki_host_mismatch_vs_int64_oracle";
        out.clear();
        return false;
    }
    if (error) error->clear();
    return true;
}

bool IsRcOzakiMetalExactPanelsQualified()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_exact_qualified;
}

bool SelfQualifyRcOzakiMetalExactPanelsOnce()
{
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_exact_ran) return g_exact_qualified;
    g_exact_ran = true;
    // No Metal device TU on this host — cannot qualify.
    g_exact_qualified = false;
    return false;
}

bool TryLaunchRcOzakiMetalExactPanelsGemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                                  const std::vector<int8_t>& /*right*/,
                                                  uint32_t /*rows*/, uint32_t /*inner*/,
                                                  uint32_t /*cols*/, std::vector<int64_t>& out,
                                                  std::string* error)
{
    out.clear();
    if (error) *error = RcOzakiMetalDeficit();
    return false;
}

bool IsRcOzakiMetalMxfp4Qualified()
{
    return false;
}

std::string RcOzakiMetalMxfp4Backend()
{
    return {};
}

std::string RcOzakiMetalMxfp4ArchKey()
{
    return {};
}

bool SelfQualifyRcOzakiMetalMxfp4Once()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_mx_ran = true;
    // Honesty: Metal has no OCP MXFP4 RC Ozaki tensor path. Never claim native.
    return false;
}

bool TryLaunchRcOzakiMetalMxfp4GemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                            const std::vector<int8_t>& /*right*/, uint32_t /*rows*/,
                                            uint32_t /*inner*/, uint32_t /*cols*/,
                                            std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (error) {
        *error = "metal_rc_ozaki_mxfp4_unavailable:requires Apple silicon + Metal "
                 "(no OCP MXFP4 RC tensor path; INT8 is not native MX)";
    }
    return false;
}

void ResetRcOzakiMetalQualForTest()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_exact_ran = false;
    g_exact_qualified = false;
    g_mx_ran = false;
}

} // namespace matmul_v4::metal
