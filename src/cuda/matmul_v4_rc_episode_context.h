// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_CUDA_MATMUL_V4_RC_EPISODE_CONTEXT_H
#define BTX_CUDA_MATMUL_V4_RC_EPISODE_CONTEXT_H

#include <matmul/matmul_v4_rc_coupled.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC / ENC_RC_COUPLED miner-local CUDA episode context (scaffolding).
//
// Goal: keep bank pages + active state + int64 accumulators resident in a
// persistent device arena across barriers, then amortize launch overhead with
// CUDA Graphs (cudaGraphLaunch) once the barrier DAG is captured.
//
// Arena allocation prefers cudaMallocAsync on a per-device memory pool when
// BTX_ENABLE_CUDA_EXPERIMENTAL is ON; the honesty stub (no CUDA) reports
// IsRcEpisodeCudaCompiled()==false and all methods fail closed.
//
// Digests MUST remain byte-identical to the CPU consensus oracle
// (RecomputeCoupledPuzzleReference). This context never raises
// nMatMulRCHeight / nMatMulRCCoupledHeight and never enables the GKR arbiter.
//
// Status: Init / LoadBank / Destroy are structured; RunBarrierGraph returns
// false with error "graph_unavailable:not_wired" until device GEMM + Extract
// are wired (never implies CUDA Graph capture succeeded).

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
     * Capture/launch the barrier DAG as a CUDA Graph (amortized launches).
     * Currently returns false with error "graph_unavailable:not_wired" —
     * device GEMM + Extract not wired; do not treat as a successful capture.
     */
    [[nodiscard]] bool RunBarrierGraph(std::string* error = nullptr);

    /** Release device arena (cudaFreeAsync / destroy graph). Idempotent. */
    void Destroy();

    [[nodiscard]] bool Ready() const { return m_ready; }
    [[nodiscard]] const RCCudaEpisodeShape& Shape() const { return m_shape; }

private:
    RCCudaEpisodeShape m_shape{};
    bool m_ready{false};
    bool m_bank_loaded{false};
    void* m_arena{nullptr}; // device ptr when CUDA ON; always null on stub
    size_t m_arena_bytes{0};
};

} // namespace matmul_v4::cuda

#endif // BTX_CUDA_MATMUL_V4_RC_EPISODE_CONTEXT_H
