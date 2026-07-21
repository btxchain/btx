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
// Persistent arena: bank pages + active state + int64 accumulators.
// Barrier lobe GEMMs: capture once, replay from resident device pointers
// (no per-GEMM H2D/D2H/sync, no global bridge mutex).
//
// PARKED (honest, fail-closed — do NOT claim device-only / peak_ready):
//   - device-native balanced permute / all-to-all / Extract / barrier-root SHA
//   - native MXFP4 lobe GEMMs via Workstream-B device-pointer API (hook below)
//   - device-assembled episode digest
// Host barrier tail (ApplyCoupledBarrierTail) runs once per barrier after a
// single D2H of the int64 accumulator; Extract fires once after reduction.
//
// Digests MUST remain byte-identical to RecomputeCoupledPuzzleReference when
// GEMM partials match ExactGemmS8S8. Never raises nMatMulRCHeight /
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

/**
 * Provenance for the resident episode path. Defaults are fail-closed.
 * peak_ready stays false until device Extract + qualified native MXFP4 are
 * wired end-to-end (not claimed by this workstream alone).
 */
struct RCCudaEpisodeProvenance {
    bool qstar_device_batched{false};
    bool device_bank_resident{false};
    bool device_state_resident{false};
    /** True only when Workstream-B packed MX operand gen runs on device. */
    bool device_mx_operand_generation{false};
    bool resident_native_mxfp4_attempted{false};
    bool resident_native_mxfp4_qualified{false};
    uint64_t graph_capture_count{0};
    uint64_t graph_replay_count{0};
    /** True when the timed window path has no per-nonce cudaStreamSynchronize. */
    bool per_nonce_sync_absent{false};
    uint64_t h2d_bytes_per_window{0};
    uint64_t d2h_bytes_per_window{0};
    /** Digest/status batch slots returned for the window (RC chat_staging analog). */
    uint64_t digest_batch_slots{0};
    /** Honest GEMM label: portable_device_alu | parked_awaiting_wsB_mxfp4_device_ptr */
    std::string gemm_path_label{"uninitialized"};
    /** Honest barrier-tail label. */
    std::string permute_extract_label{"parked_host_barrier_tail"};
    bool device_digest{false};
    bool peak_ready{false};
    std::string parked_reason;
};

/**
 * Workstream-B consumer hook: device-pointer native MXFP4 (or other qualified)
 * 1×W·W×W → int64 row. When unset / returns false, resident path uses the
 * portable device ALU kernel inside the captured graph (labeled, not native).
 */
using RcResidentDeviceGemmHook = bool (*)(const int8_t* dA, const int8_t* dB, int64_t* dOut,
                                          uint32_t rows, uint32_t cols, uint32_t inner,
                                          void* stream, std::string* error);

void SetRcResidentDeviceGemmHook(RcResidentDeviceGemmHook hook);
[[nodiscard]] RcResidentDeviceGemmHook GetRcResidentDeviceGemmHook();

class RCCudaEpisodeContext
{
public:
    RCCudaEpisodeContext() = default;
    ~RCCudaEpisodeContext() { Destroy(); }

    RCCudaEpisodeContext(const RCCudaEpisodeContext&) = delete;
    RCCudaEpisodeContext& operator=(const RCCudaEpisodeContext&) = delete;

    /**
     * Allocate (or resize) the persistent arena for `shape`.
     * CUDA ON: cudaMalloc for bank / Q states / accumulators.
     * Stub: records shape; device pointers stay null.
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

    /**
     * Download resident active state after a successful graph run (or Set).
     * After RunBarrierGraph this is the ACTUAL final Extracted state, not the
     * BindEpisode seed.
     */
    [[nodiscard]] bool DownloadActiveState(std::vector<int8_t>& out,
                                           std::string* error = nullptr) const;

    /**
     * Capture (once) + replay the resident barrier GEMM DAG; host barrier tail
     * for PARKED permute/mix/Extract; assemble digest on host.
     * Does NOT call MineCoupledPuzzle for every nonce (CPU full replay is
     * CompareWithCpuOracle / ResealAgainstCpuOracle only).
     */
    [[nodiscard]] bool RunBarrierGraph(std::string* error = nullptr);

    /**
     * Q-nonce window: one bank (already LoadBank), upload Q lobe-seed states,
     * run resident episodes, return digests only (no per-loser payload D2H).
     * batch_q in Init must be >= headers.size().
     */
    [[nodiscard]] bool RunNonceWindow(const std::vector<CBlockHeader>& headers, int32_t height,
                                      std::vector<uint256>& digests_out,
                                      std::string* error = nullptr);

    /** Episode digest from the last successful RunBarrierGraph / window slot 0. */
    [[nodiscard]] const uint256* LastDigest() const;

    [[nodiscard]] const RCCudaEpisodeProvenance& Provenance() const { return m_prov; }

    /**
     * Explicit differential vs RecomputeCoupledPuzzleReference (self-qual /
     * tests only — not on the mining hot path).
     */
    [[nodiscard]] bool CompareWithCpuOracle(std::string* error = nullptr) const;

    /**
     * Potential-winner reseal: reject if LastDigest != CPU oracle (also used
     * after fault injection of a corrupted device digest).
     */
    [[nodiscard]] bool ResealAgainstCpuOracle(std::string* error = nullptr);

    /** Test-only: flip a bit in the last digest to simulate device corruption. */
    void FaultInjectCorruptDigest(bool enable);

    /** Release device arena (cudaFree / destroy graph). Idempotent. */
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
    bool m_graph_captured{false};
    bool m_fault_corrupt_digest{false};
    void* m_arena{nullptr}; // device ptr when CUDA ON; always null on stub
    size_t m_arena_bytes{0};
    CBlockHeader m_header{};
    int32_t m_height{0};
    uint256 m_last_digest{};
    uint256 m_bank_root{};
    // Host mirror of bank pages (commitment / Extract path).
    std::vector<std::vector<int8_t>> m_pages;
    // Host mirror of active state (Set / Bind / post-Extract final).
    std::vector<int8_t> m_state;
    RCCudaEpisodeProvenance m_prov{};
    // CUDA graph / stream (opaque; only used in .cu).
    void* m_stream{nullptr};
    void* m_graph{nullptr};
    void* m_graph_exec{nullptr};
};

} // namespace matmul_v4::cuda

#endif // BTX_CUDA_MATMUL_V4_RC_EPISODE_CONTEXT_H
