// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_selfqual.h>

#include <consensus/params.h>
#include <logging.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <matmul/matmul_v4_rc_scale.h>
#include <primitives/block.h>
#include <uint256.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace matmul::v4::rc {
namespace {

std::atomic<bool> g_rc_selfqual_ok{false};
std::atomic<bool> g_rc_selfqual_diagnosed{false};
std::atomic<uint64_t> g_rc_selfqual_probe_count{0};

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

/** Medium-like shape whose wgrad K exceeds 2^24, scaled with epoch b_seq when live. */
RCEpisodeParams MakeEpochScaledMedium(const RCEpisodeParams& live)
{
    RCEpisodeParams p = MakeMediumRCEpisodeParams();
    // Keep toy-ish spatial dims for CI, but ensure b_seq covers >2^24 and tracks
    // the live epoch's contraction (at least the medium floor of 8192).
    const uint32_t floor_bs = 8192;
    const uint32_t live_bs = live.b_seq;
    // Cap for self-qual wall-clock: never exceed medium*2 or live (whichever smaller of caps).
    constexpr uint32_t kSelfQualBSeqCap = 16384;
    p.b_seq = floor_bs;
    // Optionally bump toward live when live is modest and above the floor.
    if (live_bs > floor_bs && live_bs <= kSelfQualBSeqCap) {
        p.b_seq = live_bs;
    }
    p.b_seq = std::min(kSelfQualBSeqCap, p.b_seq);
    // Align to 32.
    if (p.b_seq % 32u != 0) {
        p.b_seq = ((p.b_seq + 31u) / 32u) * 32u;
    }
    return p;
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

[[nodiscard]] bool ProbeWgradBoundary(uint32_t b_seq, std::string& reason)
{
    // Synthetic G,X with |entries|=48 → 2304·K should exceed 2^24 for b_seq≥8192.
    constexpr uint32_t d_model = 32;
    if (static_cast<uint64_t>(b_seq) * 2304ull <= (uint64_t{1} << 24)) {
        reason = "wgrad_boundary_b_seq_too_small";
        return false;
    }

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

RCSelfQualStatus ProbeRCSelfQual(const matmul::v4::lt::ExactGemmBackend& backend,
                                 std::optional<int32_t> height,
                                 const Consensus::Params* params_ref)
{
    g_rc_selfqual_probe_count.fetch_add(1, std::memory_order_relaxed);

    RCSelfQualStatus st;
    st.cpu_oracle_ok = true;
    st.native_mxfp4_qualified = false;
    st.native_fp8_qualified = false;
    st.exact_gemm_backend_ok = false;
    st.mining_accelerator_ok = false;

    // Always surface Ozaki MXFP4 / ExactPanels latches (independent of ExactGemm).
    (void)SelfQualifyRcOzakiExactPanelsOnce();
    (void)SelfQualifyRcOzakiMxfp4Once();
    st.native_mxfp4_qualified = IsRcOzakiMxfp4Qualified();
    st.native_fp8_qualified = false;

    // CPU-only path: oracle is always available; no ExactGemm accelerator to admit.
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

    const bool have_epoch = height.has_value() && params_ref != nullptr;
    if (have_epoch) {
        // §4: qualify at live epoch shape (not a fixed medium).
        const RCEpisodeParams live =
            ConsensusRCEpisodeParamsForHeight(*height, *params_ref);
        // Compact stand-in for <2^24 stages: toy episode (CI-safe).
        if (!ProbeEpisodeDigestMatch(backend, MakeToyRCEpisodeParams(), /*nonce=*/42, reason)) {
            st.deficit_reason = reason;
            g_rc_selfqual_ok.store(false, std::memory_order_release);
            return st;
        }
        // >2^24 regime at epoch-scaled medium contraction (not full live dims).
        const RCEpisodeParams med = MakeEpochScaledMedium(live);
        if (!ProbeEpisodeDigestMatch(backend, med, /*nonce=*/7, reason)) {
            st.deficit_reason = std::string("epoch_medium_") + reason;
            g_rc_selfqual_ok.store(false, std::memory_order_release);
            return st;
        }
        if (!ProbeWgradBoundary(med.b_seq, reason)) {
            st.deficit_reason = reason;
            g_rc_selfqual_ok.store(false, std::memory_order_release);
            return st;
        }
        // Record that live shape was consulted (dims available for T-FP9).
        if (live.n_ctx == 0 || live.b_seq == 0) {
            st.deficit_reason = "live_epoch_dims_invalid";
            g_rc_selfqual_ok.store(false, std::memory_order_release);
            return st;
        }
    } else {
        if (!ProbeEpisodeDigestMatch(backend, MakeToyRCEpisodeParams(), /*nonce=*/42, reason)) {
            st.deficit_reason = reason;
            g_rc_selfqual_ok.store(false, std::memory_order_release);
            return st;
        }
        if (!ProbeEpisodeDigestMatch(backend, MakeMediumRCEpisodeParams(), /*nonce=*/7, reason)) {
            st.deficit_reason = std::string("medium_") + reason;
            g_rc_selfqual_ok.store(false, std::memory_order_release);
            return st;
        }
        if (!ProbeWgradBoundary(MakeMediumRCEpisodeParams().b_seq, reason)) {
            st.deficit_reason = reason;
            g_rc_selfqual_ok.store(false, std::memory_order_release);
            return st;
        }
    }

    st.exact_gemm_backend_ok = true;
    st.mining_accelerator_ok = true;
    st.deficit_reason.clear();
    // Amendment 1.B: native MXFP4 only after Ozaki MXFP4 device path quals.
    // ExactGemm panels may qualify separately and must NOT flip native_*.
    // LT native_mxfp4_qualified must never be copied here.
    // (Ozaki latches already refreshed at probe entry.)
    st.native_mxfp4_qualified = IsRcOzakiMxfp4Qualified();
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

uint64_t RCSelfQualProbeInvocationCountForTest()
{
    return g_rc_selfqual_probe_count.load(std::memory_order_relaxed);
}

void ResetRCSelfQualProbeCountForTest()
{
    g_rc_selfqual_probe_count.store(0, std::memory_order_relaxed);
}

void ResetRCSelfQualCacheForTest()
{
    g_rc_selfqual_ok.store(false, std::memory_order_release);
    g_rc_selfqual_diagnosed.store(false, std::memory_order_release);
    g_rc_selfqual_probe_count.store(0, std::memory_order_relaxed);
}

} // namespace matmul::v4::rc
