// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_CUDA_MATMUL_V4_RC_EXACT_REPLAY_CUDA_H
#define BTX_CUDA_MATMUL_V4_RC_EXACT_REPLAY_CUDA_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC ExactReplay CUDA accelerator — miner/validator hot path.
//
// Target shape (Metal M4 Max parity): ~2 Phase-1 GEMMs/round + 2 Phase-2
// GEMMs/layer with device ExtractMX, zero CPU ExactGemm fallback, no host
// panel re-pack / int64 Y bounce between GEMM and Extract.
// Digests MUST stay byte-identical to the host int64 oracle. Fail-closed:
// any device decline returns false and the caller keeps the host path.
//
// The explicitly authorized Profile-1 seeded lanes also generate canonical
// Q/K/V and FFN weights on the selected CUDA device. Other profiles and proof
// paths retain the established host-input contract.

namespace matmul_v4::cuda {

/** Preferred Phase-1 context tile when a full-n_ctx score matrix will not fit. */
inline constexpr uint32_t kRcExactReplayPhase1CtxChunk = 65536;

struct RcExactReplayCudaStats {
    int device_index{-1};
    uint64_t device_gemm_calls{0};
    uint64_t cpu_gemm_fallbacks{0};
    uint64_t device_extract_tiles{0};
    bool phase1_device{false};
    bool phase2_gemm_device{false};
    bool phase2_extract_device{false};
    bool phase2_ffn_fused_device{false};
    bool phase2_ffn_chain_resident{false};
    std::string detail;
};

[[nodiscard]] bool IsRcExactReplayCudaAvailable();

/** Reset / snapshot process-local stats (measure harness). */
void ResetRcExactReplayCudaStats();
[[nodiscard]] RcExactReplayCudaStats GetRcExactReplayCudaStats();

/**
 * Phase-1 AssociativeRecall on device:
 *   H2D Q,K,V once → prefer one IMMA Q·Kᵀ over full n_ctx + device ExtractMX(S)
 *   + one IMMA S·V + device ExtractMX(Z). Falls back to large context tiles when
 *   the full score matrix will not fit in free VRAM.
 */
[[nodiscard]] bool TryCudaRcPhase1AssociativeRecall(
    const std::vector<int8_t>& Q, const std::vector<int8_t>& K,
    const std::vector<int8_t>& V, const uint256& prf_S, const uint256& prf_Z,
    uint32_t n_q, uint32_t n_ctx, uint32_t d_head, std::vector<int8_t>& out_Z,
    const uint256* seed_q = nullptr, const uint256* seed_k = nullptr,
    const uint256* seed_v = nullptr);

/**
 * Exact int8·int8 → int64 GEMM. Prefer a single IMMA launch over full K (int32
 * accumulate is exact for RC magnitudes); device K-panel pack only if a single
 * launch declines. One H2D of A/B, one D2H of Y.
 */
[[nodiscard]] bool TryCudaRcFusedExactGemmInt64(
    const std::vector<int8_t>& A, uint32_t m, uint32_t k, const std::vector<int8_t>& B,
    uint32_t n, std::vector<int64_t>& out);

/** Device ExtractMXMatrixInt64 twin (rows×cols, cols % 32 == 0). */
[[nodiscard]] bool TryCudaRcExtractMXMatrixInt64(
    const uint256& prf_key, const std::vector<int64_t>& Y, uint32_t rows, uint32_t cols,
    std::vector<int8_t>& out);

/**
 * Fully fused FFN layer on device (Metal shape):
 *   H = Extract(X·W_up);  out = Extract(H·W_down + X)
 * Keeps intermediates resident; only X/W H2D and out D2H.
 */
[[nodiscard]] bool TryCudaRcFusedFfnLayer(
    const std::vector<int8_t>& X, const std::vector<int8_t>& W_up,
    const std::vector<int8_t>& W_down, const uint256& prf_up, const uint256& prf_dn,
    uint32_t b_seq, uint32_t d_model, uint32_t d_ff, std::vector<int8_t>& out);

/**
 * Metal-parity resident FFN chain: X stays on device across all L layers.
 * Host provides X0 and per-layer (or shared) weights; device fills out_X[1..L]
 * (out_X[0] = X0). Async D2H of each completed layer overlaps the next layer's
 * weight upload when possible.
 */
[[nodiscard]] bool TryCudaRcFusedFfnChain(
    const std::vector<int8_t>& X0, bool weights_shared, const std::vector<int8_t>& W_up_shared,
    const std::vector<int8_t>& W_down_shared, const std::vector<std::vector<int8_t>>& W_up_layers,
    const std::vector<std::vector<int8_t>>& W_down_layers, const std::vector<uint256>& prf_up,
    const std::vector<uint256>& prf_dn, uint32_t b_seq, uint32_t d_model, uint32_t d_ff,
    uint32_t L_lyr, std::vector<std::vector<int8_t>>& out_X,
    const std::vector<uint256>* up_seeds = nullptr,
    const std::vector<uint256>* down_seeds = nullptr);

// --- ExactGemmBackend ABI (Metal-parity Launch* entry points) -----------------
// These match matmul::v4::lt::ExactGemmBackend::RC*Fn so ResolveExactGemmBackendForRC
// can attach CUDA ExactReplay the same way Metal attaches LaunchRcExactReplay*.

[[nodiscard]] bool LaunchRcExactReplayFusedFfn(
    const std::vector<int8_t>& X, const std::vector<int8_t>& W_up,
    const std::vector<int8_t>& W_down, const uint256& prf_up, const uint256& prf_down,
    uint32_t row_begin, uint32_t rows, uint32_t d_model, uint32_t d_ff,
    std::vector<int8_t>& out);

[[nodiscard]] bool LaunchRcExactReplayFusedFfnChain(
    const std::vector<int8_t>& X0, const std::vector<std::vector<int8_t>>& W_up,
    const std::vector<std::vector<int8_t>>& W_down, const std::vector<uint256>& prf_up,
    const std::vector<uint256>& prf_down, uint32_t rows, uint32_t d_model, uint32_t d_ff,
    std::vector<std::vector<int8_t>>& layer_outputs);

[[nodiscard]] bool LaunchRcExactReplayPhase1(
    const std::vector<int8_t>& Q, const std::vector<int8_t>& K, const std::vector<int8_t>& V,
    const uint256& prf_s, const uint256& prf_z, uint32_t query_rows, uint32_t context_rows,
    uint32_t d_head, std::vector<int8_t>& out_z);

/** Profile-1-only seeded lanes. These generate canonical ExpandMx operands on
 * the CUDA device and then execute the existing resident ExactReplay kernels.
 * Callers retain the ordinary host-input callbacks for non-strict fallback. */
[[nodiscard]] bool LaunchRcExactReplayFusedFfnChainSeeded(
    const std::vector<int8_t>& X0, const std::vector<uint256>& up_seeds,
    const std::vector<uint256>& down_seeds, const std::vector<uint256>& prf_up,
    const std::vector<uint256>& prf_down, uint32_t rows, uint32_t d_model,
    uint32_t d_ff, std::vector<std::vector<int8_t>>& layer_outputs);

[[nodiscard]] bool LaunchRcExactReplayPhase1Seeded(
    const uint256& seed_q, const uint256& seed_k, const uint256& seed_v,
    const uint256& prf_s, const uint256& prf_z, uint32_t query_rows,
    uint32_t context_rows, uint32_t d_head, std::vector<int8_t>& out_z);

/** Direct CUDA implementation of the canonical ExpandMx operand stream.
 * The implementation deterministically extends rejection-sampling batches
 * until every requested mantissa exists; it never reports success for an
 * incomplete device stream. */
[[nodiscard]] bool LaunchRcExactReplayExpandMx(
    const uint256& seed, uint32_t rows, uint32_t columns,
    std::vector<int8_t>& output);

/** Test-only continuation seam: caps each rejection-sampling batch without
 * changing the canonical counter stream. */
[[nodiscard]] bool LaunchRcExactReplayExpandMxForTest(
    const uint256& seed, uint32_t rows, uint32_t columns,
    uint32_t max_blocks_per_batch, std::vector<int8_t>& output);

} // namespace matmul_v4::cuda

#endif // BTX_CUDA_MATMUL_V4_RC_EXACT_REPLAY_CUDA_H
