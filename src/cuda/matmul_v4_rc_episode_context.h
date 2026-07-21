// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_CUDA_MATMUL_V4_RC_EPISODE_CONTEXT_H
#define BTX_CUDA_MATMUL_V4_RC_EPISODE_CONTEXT_H

#include <matmul/matmul_v4_rc_coupled.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC / ENC_RC_COUPLED miner-local CUDA episode context.
//
// Goal: keep bank pages + active state + int64 accumulators resident in a
// persistent device arena across barriers, then amortize launch overhead with
// CUDA Graphs (cudaStreamBeginCapture → GEMM/Extract DAG → instantiate →
// cudaGraphLaunch). Digests MUST remain byte-identical to
// RecomputeCoupledPuzzleReference. Never raises nMatMulRCHeight /
// nMatMulRCCoupledHeight and never enables the GKR arbiter.

namespace matmul_v4::cuda {

/** True when this binary compiled the CUDA episode TU (not the stub). */
[[nodiscard]] bool IsRcEpisodeCudaCompiled();

/** Arch key like "sm_120"; empty if unknown / stub. */
[[nodiscard]] std::string RcEpisodeCudaArchKey();

struct RCCudaEpisodeShape {
    uint32_t barriers{0};
    uint32_t lobes{0};
    uint32_t lobe_width{0};
    uint32_t bank_pages{0};
    uint32_t batch_q{1};
};

class RCCudaEpisodeContext
{
public:
    RCCudaEpisodeContext() = default;
    ~RCCudaEpisodeContext() { Destroy(); }

    RCCudaEpisodeContext(const RCCudaEpisodeContext&) = delete;
    RCCudaEpisodeContext& operator=(const RCCudaEpisodeContext&) = delete;

    /**
     * Allocate (or resize) the persistent arena for `shape`.
     * CUDA ON: cudaMallocAsync for bank / state / accumulators.
     * Stub: records shape and returns true only for ValidateRCCoupParams-shaped
     * inputs so host tests can exercise the API; device pointers stay null.
     */
    [[nodiscard]] bool Init(const RCCudaEpisodeShape& shape, std::string* error = nullptr);

    /** Convenience: map RCCoupParams (+ optional Q) into Init. */
    [[nodiscard]] bool Init(const matmul::v4::rc::RCCoupParams& params, uint32_t batch_q = 1,
                            std::string* error = nullptr);

    /**
     * Upload / bind bank pages into the resident arena (H2D once per template).
     * Stub: accepts host pages and returns true without a device copy.
     */
    [[nodiscard]] bool LoadBank(const std::vector<std::vector<int8_t>>& pages,
                                std::string* error = nullptr);

    /**
     * Bind the episode header/height used by RunBarrierGraph for lobe seeds,
     * bank commitment, and digest assembly. Also seeds active lobe state from
     * DeriveCoupledLobeSeeds (same as RecomputeCoupledPuzzleReference).
     */
    [[nodiscard]] bool BindEpisode(const CBlockHeader& header, int32_t height,
                                   std::string* error = nullptr);

    /**
     * Upload active lobe state (StateBytes() int8) into the resident arena.
     * Optional override after BindEpisode; size must match lobes×lobe_width.
     */
    [[nodiscard]] bool SetActiveState(const std::vector<int8_t>& state,
                                      std::string* error = nullptr);

    /** Download resident active state after a successful graph run (or Set). */
    [[nodiscard]] bool DownloadActiveState(std::vector<int8_t>& out,
                                           std::string* error = nullptr) const;

    /**
     * Capture/launch the barrier DAG as a CUDA Graph (amortized launches).
     * CUDA ON: cudaStreamBeginCapture → bank lookup + lobe GEMMs + permute/mix
     * + Extract host-node + barrier-root material → instantiate → launch per
     * barrier; digest == RecomputeCoupledPuzzleReference.
     * Stub: returns false with "graph_unavailable:not_wired".
     */
    [[nodiscard]] bool RunBarrierGraph(std::string* error = nullptr);

    /** Episode digest from the last successful RunBarrierGraph; null if none. */
    [[nodiscard]] const uint256* LastDigest() const;

    /** Release device arena (cudaFreeAsync / destroy graph). Idempotent. */
    void Destroy();

    [[nodiscard]] bool Ready() const { return m_ready; }
    [[nodiscard]] const RCCudaEpisodeShape& Shape() const { return m_shape; }

private:
    RCCudaEpisodeShape m_shape{};
    bool m_ready{false};
    bool m_bank_loaded{false};
    bool m_episode_bound{false};
    bool m_have_digest{false};
    bool m_state_ready{false};
    void* m_arena{nullptr}; // device ptr when CUDA ON; always null on stub
    size_t m_arena_bytes{0};
    CBlockHeader m_header{};
    int32_t m_height{0};
    uint256 m_last_digest{};
    // Host mirror of bank pages (digest / Extract path).
    std::vector<std::vector<int8_t>> m_pages;
    // Host mirror of active state (Set / Bind / post-Extract).
    std::vector<int8_t> m_state;
    // CUDA graph / stream (opaque; only used in .cu).
    void* m_stream{nullptr};
    void* m_graph{nullptr};
    void* m_graph_exec{nullptr};
};

} // namespace matmul_v4::cuda

#endif // BTX_CUDA_MATMUL_V4_RC_EPISODE_CONTEXT_H
