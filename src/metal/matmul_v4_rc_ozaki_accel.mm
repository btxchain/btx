// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal RC Ozaki ExactPanels: Metal 4 mpp::tensor_ops::matmul2d
// (simdgroup / MPP) preferred after ExactGemmS8S8 self-qual; MSL ALU fallback.
// Native OCP MXFP4 remains fail-closed (not proven vs RC int64 Ozaki).

#include <metal/matmul_v4_rc_ozaki_accel.h>

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <metal/matmul_v4_lt_accel.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace matmul_v4::metal {
namespace {

std::mutex g_mu;
bool g_exact_ran{false};
bool g_exact_qualified{false};
bool g_mx_ran{false};
bool g_last_used_tensor_ops{false};
std::string g_exact_backend;

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

/** Limb-split via Metal LaunchGemmS8S8 (TensorOps or ALU) → int64 accumulate. */
[[nodiscard]] bool LaunchMetalOzakiExactPanels(const std::vector<int8_t>& left,
                                               const std::vector<int8_t>& right, uint32_t rows,
                                               uint32_t inner, uint32_t cols,
                                               std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "metal_rc_ozaki: degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "metal_rc_ozaki: size mismatch";
        return false;
    }
    if (!IsMatMulLTMetalAvailable()) {
        if (error) *error = "requires Apple silicon + Metal";
        return false;
    }

    constexpr uint32_t kChunk = matmul::v4::rc::kRCOzakiExactChunk;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    bool any_tensor = false;
    for (uint32_t k0 = 0; k0 < inner; k0 += kChunk) {
        const uint32_t len = std::min(kChunk, inner - k0);
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
        std::vector<int32_t> partial;
        if (!LaunchGemmS8S8(Lpanel, Rpanel, rows, len, cols, partial) ||
            partial.size() != out.size()) {
            if (error) *error = "metal_rc_ozaki: LaunchGemmS8S8 declined";
            out.clear();
            return false;
        }
        if (LtLastS8S8UsedTensorOps()) any_tensor = true;
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    g_last_used_tensor_ops = any_tensor;
    if (error) error->clear();
    return true;
}

[[nodiscard]] bool ExactShapeMatches(uint32_t rows, uint32_t inner, uint32_t cols, uint32_t seed,
                                     std::string* error)
{
    std::vector<int8_t> left(static_cast<size_t>(rows) * inner);
    std::vector<int8_t> right(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < left.size(); ++i) {
        left[i] = static_cast<int8_t>((static_cast<int32_t>(i + seed) % 97) - 48);
    }
    for (size_t i = 0; i < right.size(); ++i) {
        right[i] = static_cast<int8_t>((static_cast<int32_t>(i * 3 + seed) % 95) - 47);
    }
    std::vector<int64_t> cpu;
    if (!matmul::v4::rc::RcOzakiCpuLimbSplitGemmS8S8Int64(left, right, rows, inner, cols, cpu)) {
        if (error) *error = "cpu Ozaki ExactPanels oracle failed";
        return false;
    }
    std::vector<int64_t> device;
    if (!LaunchMetalOzakiExactPanels(left, right, rows, inner, cols, device, error)) return false;
    if (device != cpu) {
        if (error) *error = "Metal ExactPanels != CPU Ozaki oracle";
        return false;
    }
    return true;
}

} // namespace

bool IsRcOzakiMetalCompiled()
{
    return true;
}

std::string RcOzakiMetalDeficit()
{
    if (IsRcOzakiMetalExactPanelsQualified()) return {};
    if (!IsMatMulLTMetalAvailable()) return "requires Apple silicon + Metal";
    return "requires Apple Metal RC Ozaki ExactPanels self-qual "
           "(rc_metal_ozaki_exact_panels_device_qualify)";
}

bool HostReferenceRcOzakiExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                                 const std::vector<int8_t>& right, uint32_t rows,
                                                 uint32_t inner, uint32_t cols,
                                                 std::vector<int64_t>& out, std::string* error)
{
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

bool IsRcOzakiMetalExactPanelsAttempted()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_exact_ran;
}

bool IsRcOzakiMetalExactPanelsQualified()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_exact_qualified;
}

std::string RcOzakiMetalExactPanelsBackend()
{
    std::lock_guard<std::mutex> lock(g_mu);
    // Honest INT8 labels only — never OCP MXFP4.
    return g_exact_backend;
}

bool SelfQualifyRcOzakiMetalExactPanelsOnce()
{
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_exact_ran) return g_exact_qualified;
    }
    std::string err;
    const bool ok = IsMatMulLTMetalAvailable() && ExactShapeMatches(8, 8, 8, 1u, &err) &&
                    ExactShapeMatches(16, 8192, 16, 7u, &err) &&
                    ExactShapeMatches(8, 4096, 8, 3u, &err);
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_exact_ran) {
        g_exact_ran = true;
        g_exact_qualified = ok;
        if (ok) {
            // Prefer last launch provenance; fall back to TensorOps-capable label.
            g_exact_backend = g_last_used_tensor_ops ? "metal_int8_mpp_tensorops"
                                                    : "metal_int8_msl_alu";
        } else {
            g_exact_backend.clear();
        }
    }
    return g_exact_qualified;
}

bool TryLaunchRcOzakiMetalExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                                  const std::vector<int8_t>& right, uint32_t rows,
                                                  uint32_t inner, uint32_t cols,
                                                  std::vector<int64_t>& out, std::string* error)
{
    if (!SelfQualifyRcOzakiMetalExactPanelsOnce() || !IsRcOzakiMetalExactPanelsQualified()) {
        out.clear();
        if (error) *error = RcOzakiMetalDeficit();
        return false;
    }
    return LaunchMetalOzakiExactPanels(left, right, rows, inner, cols, out, error);
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
    // Apple MX·E8M0 / FP8 matmul2d is floating dequant — not RC OCP MXFP4.
    // Never set native qualified from INT8 ExactPanels.
    return false;
}

bool TryLaunchRcOzakiMetalMxfp4GemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                            const std::vector<int8_t>& /*right*/, uint32_t /*rows*/,
                                            uint32_t /*inner*/, uint32_t /*cols*/,
                                            std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (error) {
        *error = "metal_rc_ozaki_mxfp4_unavailable: no OCP MXFP4 RC tensor path on Metal "
                 "(INT8 ExactPanels ≠ native MX float)";
    }
    return false;
}

void ResetRcOzakiMetalQualForTest()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_exact_ran = false;
    g_exact_qualified = false;
    g_mx_ran = false;
    g_last_used_tensor_ops = false;
    g_exact_backend.clear();
}

} // namespace matmul_v4::metal
