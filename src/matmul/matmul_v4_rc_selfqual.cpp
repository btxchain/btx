// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_selfqual.h>

#include <logging.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <primitives/block.h>
#include <uint256.h>

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace matmul::v4::rc {
namespace {

std::atomic<bool> g_rc_selfqual_ok{false};
std::atomic<bool> g_rc_selfqual_diagnosed{false};

CBlockHeader MakeSelfQualHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x7c);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0x3e);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x55);
        header.seed_b.data()[i] = static_cast<unsigned char>(0xaa);
    }
    return header;
}

[[nodiscard]] bool ProbeDirectS8S8(const matmul::v4::lt::ExactGemmBackend& backend,
                                   std::string& reason)
{
    if (backend.gemm_s8s8 == nullptr) {
        reason = "no_gemm_s8s8_slot";
        return false;
    }
    constexpr uint32_t k = 32;
    std::vector<int8_t> L(static_cast<size_t>(k) * k), R(static_cast<size_t>(k) * k);
    for (uint32_t i = 0; i < k * k; ++i) {
        L[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 97) - 48);
        R[i] = static_cast<int8_t>((static_cast<int32_t>(i * 3) % 95) - 47);
    }
    const auto cpu = matmul::v4::lt::ExactGemmS8S8(L, R, k, k, k);
    std::vector<int32_t> device;
    bool ok = false;
    try {
        ok = backend.gemm_s8s8(L, R, k, k, k, device) && device == cpu;
    } catch (...) {
        ok = false;
    }
    if (!ok) {
        reason = "gemm_s8s8_mismatch_vs_cpu_exactgemm";
        return false;
    }
    return true;
}

[[nodiscard]] bool ProbeEpisodeDigestMatch(const matmul::v4::lt::ExactGemmBackend& backend,
                                           const RCEpisodeParams& params, uint64_t nonce,
                                           std::string& reason)
{
    const auto header = MakeSelfQualHeader(nonce);
    const uint256 cpu = MineRCEpisode(header, params, /*height=*/0, nullptr,
                                      matmul::v4::lt::ExactGemmBackend{});
    const uint256 with = MineRCEpisode(header, params, /*height=*/0, nullptr, backend);
    if (cpu.IsNull() || with != cpu) {
        reason = "episode_digest_mismatch_backend_vs_cpu";
        return false;
    }
    return true;
}

[[nodiscard]] bool ProbeWgradBoundary(std::string& reason)
{
    // Synthetic G,X with |entries|=48 and b_seq=8192 → 2304·K > 2^24.
    constexpr uint32_t b_seq = 8192;
    constexpr uint32_t d_model = 32;
    static_assert(static_cast<uint64_t>(b_seq) * 2304ull > (uint64_t{1} << 24),
                  "boundary probe requires wgrad bound > 2^24");

    std::vector<int8_t> G(static_cast<size_t>(b_seq) * d_model, 48);
    std::vector<int8_t> X(static_cast<size_t>(b_seq) * d_model, 48);

    const auto oracle = TestHelperGemmGXtInt64(G, X, b_seq, d_model);
    const auto chunked =
        TestHelperGemmGXtViaChunkedExact(G, X, b_seq, d_model, matmul::v4::lt::ExactGemmBackend{});
    if (oracle != chunked) {
        reason = "wgrad_int64_vs_chunked_exact_mismatch";
        return false;
    }
    if (oracle.empty() || std::llabs(oracle[0]) <= (1LL << 24)) {
        reason = "wgrad_boundary_magnitude_too_small";
        return false;
    }
    return true;
}

} // namespace

RCSelfQualStatus ProbeRCSelfQual(const matmul::v4::lt::ExactGemmBackend& backend)
{
    RCSelfQualStatus st;
    st.cpu_oracle_ok = true;
    st.native_mxfp4_qualified = false;
    st.native_fp8_qualified = false;
    st.exact_gemm_backend_ok = false;
    st.mining_accelerator_ok = false;

    // CPU-only path: oracle is always available; no accelerator to admit.
    if (backend.gemm_s8s8 == nullptr) {
        st.deficit_reason = "cpu_exactgemm_no_device_backend";
        g_rc_selfqual_ok.store(false, std::memory_order_release);
        return st;
    }

    std::string reason;

    if (!ProbeDirectS8S8(backend, reason)) {
        st.deficit_reason = reason;
        st.cpu_oracle_ok = true;
        g_rc_selfqual_ok.store(false, std::memory_order_release);
        return st;
    }

    if (!ProbeEpisodeDigestMatch(backend, MakeToyRCEpisodeParams(), /*nonce=*/42, reason)) {
        st.deficit_reason = reason;
        g_rc_selfqual_ok.store(false, std::memory_order_release);
        return st;
    }

    // Medium episode: exercises larger Phase-2 shapes (still CI-safe).
    if (!ProbeEpisodeDigestMatch(backend, MakeMediumRCEpisodeParams(), /*nonce=*/7, reason)) {
        st.deficit_reason = std::string("medium_") + reason;
        g_rc_selfqual_ok.store(false, std::memory_order_release);
        return st;
    }

    if (!ProbeWgradBoundary(reason)) {
        st.deficit_reason = reason;
        g_rc_selfqual_ok.store(false, std::memory_order_release);
        return st;
    }

    st.exact_gemm_backend_ok = true;
    st.mining_accelerator_ok = true;
    st.deficit_reason.clear();
    // native_* remain false until a device RC MX path exists.
    st.native_mxfp4_qualified = false;
    st.native_fp8_qualified = false;
    g_rc_selfqual_ok.store(true, std::memory_order_release);
    return st;
}

void DiagnoseRCSelfQualOnce()
{
    bool expected = false;
    if (!g_rc_selfqual_diagnosed.compare_exchange_strong(expected, true)) return;

    const RCSelfQualStatus st = ProbeRCSelfQual(matmul::v4::lt::ExactGemmBackend{});
    LogPrintf("MatMul-v4.4-RC ExactGemm self-qual: mining_accelerator_ok=%d exact_gemm_backend_ok=%d "
              "native_mxfp4=%d native_fp8=%d (%s)\n",
              st.mining_accelerator_ok ? 1 : 0, st.exact_gemm_backend_ok ? 1 : 0,
              st.native_mxfp4_qualified ? 1 : 0, st.native_fp8_qualified ? 1 : 0,
              st.deficit_reason.empty() ? "ok" : st.deficit_reason.c_str());
}

bool RCAcceleratorAdmissible(const matmul::v4::lt::ExactGemmBackend& backend)
{
    const RCSelfQualStatus st = ProbeRCSelfQual(backend);
    return st.mining_accelerator_ok;
}

bool HasPassedRCSelfQual()
{
    return g_rc_selfqual_ok.load(std::memory_order_acquire);
}

} // namespace matmul::v4::rc
