// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_rc_mx_ozaki_native.h>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

// HIP OFF / no ROCm: host pack unit-exact + fail-closed device latches.
// HARD BLOCKER: "requires gfx950 silicon"

namespace matmul_v4::hip {
namespace {

std::mutex g_mu;
bool g_exact_ran{false};
bool g_exact_qualified{false};
bool g_mx_ran{false};

constexpr uint8_t kUe8m0Bias = 127;

[[nodiscard]] bool IsM11(int32_t mu)
{
    switch (mu) {
    case 0:
    case 1:
    case -1:
    case 2:
    case -2:
    case 3:
    case -3:
    case 4:
    case -4:
    case 6:
    case -6:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] uint8_t EncodeE2M1Nibble(int8_t mu)
{
    switch (mu) {
    case 0: return 0x0;
    case 1: return 0x2;
    case 2: return 0x4;
    case 3: return 0x5;
    case 4: return 0x6;
    case 6: return 0x7;
    case -1: return 0xA;
    case -2: return 0xC;
    case -3: return 0xD;
    case -4: return 0xE;
    case -6: return 0xF;
    default: return 0xFF;
    }
}

[[nodiscard]] bool FactorBlockToMx(const int8_t* vals, uint32_t n, uint8_t& e_out, int8_t* mu_out)
{
    for (int e = 3; e >= 0; --e) {
        const int32_t scale = 1 << e;
        bool ok = true;
        for (uint32_t i = 0; i < n; ++i) {
            const int32_t v = static_cast<int32_t>(vals[i]);
            if ((v % scale) != 0) {
                ok = false;
                break;
            }
            const int32_t mu = v / scale;
            if (!IsM11(mu)) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        e_out = static_cast<uint8_t>(e);
        for (uint32_t i = 0; i < n; ++i) {
            mu_out[i] = static_cast<int8_t>(static_cast<int32_t>(vals[i]) / scale);
        }
        for (uint32_t i = n; i < kRcOzakiHipMxBlk; ++i) mu_out[i] = 0;
        return true;
    }
    return false;
}

void PackNibble(uint8_t* packed, size_t elem_index, uint8_t nib)
{
    const size_t byte = elem_index / 2;
    if ((elem_index & 1u) == 0) {
        packed[byte] = static_cast<uint8_t>((packed[byte] & 0xF0u) | (nib & 0x0Fu));
    } else {
        packed[byte] = static_cast<uint8_t>((packed[byte] & 0x0Fu) | ((nib & 0x0Fu) << 4));
    }
}

[[nodiscard]] uint8_t UnpackNibble(const uint8_t* packed, size_t elem_index)
{
    const uint8_t b = packed[elem_index / 2];
    return ((elem_index & 1u) == 0) ? static_cast<uint8_t>(b & 0x0Fu)
                                   : static_cast<uint8_t>((b >> 4) & 0x0Fu);
}

} // namespace

bool IsRcOzakiHipCompiled()
{
    return false;
}

std::string RcOzakiHipDeficit()
{
    return "requires gfx950 silicon";
}

int8_t DecodeRcOzakiHipE2M1Nibble(uint8_t nib)
{
    switch (nib & 0x0Fu) {
    case 0x0: return 0;
    case 0x2: return 1;
    case 0xA: return -1;
    case 0x4: return 2;
    case 0xC: return -2;
    case 0x5: return 3;
    case 0xD: return -3;
    case 0x6: return 4;
    case 0xE: return -4;
    case 0x7: return 6;
    case 0xF: return -6;
    default: return 0;
    }
}

bool PackRcOzakiHipMxfp4OpATOpBN(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                uint32_t rows, uint32_t K, uint32_t cols, RcOzakiHipMxPack& out,
                                std::string* error)
{
    // Layout for hipBLASLt RC Ozaki: opA=T (A stored K×M), opB=N (B stored K×N),
    // VEC32 UE8M0 scales along K blocks.
    out = {};
    if (rows == 0 || K == 0 || cols == 0) {
        if (error) *error = "PackRcOzakiHipMxfp4: degenerate shape";
        return false;
    }
    if ((K % kRcOzakiHipMxBlk) != 0 && (K % 2u) != 0) {
        // K must be even for nibble packing; prefer multiples of 32 for VEC32.
    }
    if ((K % 2u) != 0) {
        if (error) *error = "PackRcOzakiHipMxfp4: K must be even for E2M1 packing";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * K ||
        right.size() != static_cast<size_t>(K) * cols) {
        if (error) *error = "PackRcOzakiHipMxfp4: size mismatch";
        return false;
    }
    const uint32_t kblocks = (K + kRcOzakiHipMxBlk - 1u) / kRcOzakiHipMxBlk;
    out.kblocks = kblocks;
    // A transposed storage: K×M elements → packed nibbles
    const size_t a_elems = static_cast<size_t>(K) * rows;
    const size_t b_elems = static_cast<size_t>(K) * cols;
    out.a_e2m1.assign((a_elems + 1) / 2, 0);
    out.b_e2m1.assign((b_elems + 1) / 2, 0);
    out.sfa_ue8m0.assign(static_cast<size_t>(rows) * kblocks, kUe8m0Bias);
    out.sfb_ue8m0.assign(static_cast<size_t>(cols) * kblocks, kUe8m0Bias);

    int8_t mu_tmp[kRcOzakiHipMxBlk];
    // Left (M×K row-major) → A as K×M (opA=T): pack along K for each M.
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kRcOzakiHipMxBlk;
            const uint32_t n = std::min(kRcOzakiHipMxBlk, K - k0);
            int8_t block[kRcOzakiHipMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = left[static_cast<size_t>(r) * K + (k0 + t)];
            }
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "PackRcOzakiHipMxfp4: left block not MX-factorable";
                return false;
            }
            out.sfa_ue8m0[static_cast<size_t>(r) * kblocks + bj] =
                static_cast<uint8_t>(kUe8m0Bias + e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "PackRcOzakiHipMxfp4: left mu not E2M1";
                    return false;
                }
                // Index in K×M storage: k * M + m
                PackNibble(out.a_e2m1.data(), static_cast<size_t>(k0 + t) * rows + r, nib);
            }
        }
    }
    // Right (K×N row-major) → B opB=N: pack along K for each N.
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kRcOzakiHipMxBlk;
            const uint32_t n = std::min(kRcOzakiHipMxBlk, K - k0);
            int8_t block[kRcOzakiHipMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = right[static_cast<size_t>(k0 + t) * cols + c];
            }
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "PackRcOzakiHipMxfp4: right block not MX-factorable";
                return false;
            }
            out.sfb_ue8m0[static_cast<size_t>(c) * kblocks + bj] =
                static_cast<uint8_t>(kUe8m0Bias + e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "PackRcOzakiHipMxfp4: right mu not E2M1";
                    return false;
                }
                PackNibble(out.b_e2m1.data(), static_cast<size_t>(k0 + t) * cols + c, nib);
            }
        }
    }
    if (error) error->clear();
    return true;
}

bool HostReferenceRcOzakiHipMxfp4GemmFromPack(const RcOzakiHipMxPack& pack, uint32_t rows,
                                             uint32_t inner, uint32_t cols,
                                             std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (pack.kblocks == 0 || rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "HostReferenceRcOzakiHipMxfp4: empty pack/shape";
        return false;
    }
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            int64_t acc = 0;
            for (uint32_t k = 0; k < inner; ++k) {
                const uint32_t bj = k / kRcOzakiHipMxBlk;
                const uint8_t ea = pack.sfa_ue8m0[static_cast<size_t>(r) * pack.kblocks + bj];
                const uint8_t eb = pack.sfb_ue8m0[static_cast<size_t>(c) * pack.kblocks + bj];
                const int32_t sa = 1 << (static_cast<int>(ea) - static_cast<int>(kUe8m0Bias));
                const int32_t sb = 1 << (static_cast<int>(eb) - static_cast<int>(kUe8m0Bias));
                const int8_t ma =
                    DecodeRcOzakiHipE2M1Nibble(UnpackNibble(pack.a_e2m1.data(),
                                                           static_cast<size_t>(k) * rows + r));
                const int8_t mb =
                    DecodeRcOzakiHipE2M1Nibble(UnpackNibble(pack.b_e2m1.data(),
                                                           static_cast<size_t>(k) * cols + c));
                acc += static_cast<int64_t>(ma) * sa * static_cast<int64_t>(mb) * sb;
            }
            out[static_cast<size_t>(r) * cols + c] = acc;
        }
    }
    if (error) error->clear();
    return true;
}

bool IsRcOzakiHipExactPanelsQualified()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_exact_qualified;
}

bool SelfQualifyRcOzakiHipExactPanelsOnce()
{
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_exact_ran) return g_exact_qualified;
    g_exact_ran = true;
    g_exact_qualified = false;
    return false;
}

bool TryLaunchRcOzakiHipExactPanelsGemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                                const std::vector<int8_t>& /*right*/,
                                                uint32_t /*rows*/, uint32_t /*inner*/,
                                                uint32_t /*cols*/, std::vector<int64_t>& out,
                                                std::string* error)
{
    out.clear();
    if (error) *error = RcOzakiHipDeficit();
    return false;
}

bool IsRcOzakiHipMxfp4Qualified()
{
    return false;
}

std::string RcOzakiHipMxfp4ArchKey()
{
    return {};
}

std::string RcOzakiHipMxfp4Backend()
{
    return {};
}

std::string RcOzakiHipMxfp4Deficit()
{
    return "requires gfx950 silicon";
}

bool SelfQualifyRcOzakiHipMxfp4Once()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_mx_ran = true;
    return false;
}

bool TryLaunchRcOzakiHipMxfp4GemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                          const std::vector<int8_t>& /*right*/, uint32_t /*rows*/,
                                          uint32_t /*inner*/, uint32_t /*cols*/,
                                          std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (error) *error = "requires gfx950 silicon";
    return false;
}

void ResetRcOzakiHipQualForTest()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_exact_ran = false;
    g_exact_qualified = false;
    g_mx_ran = false;
}

} // namespace matmul_v4::hip
