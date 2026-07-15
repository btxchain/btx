// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_BATCH_H
#define BTX_MATMUL_MATMUL_V4_BATCH_H

#include <matmul/matmul_v4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

// Cross-nonce BATCHED miner for the MatMul v4.1 batched-sketch profile
// (design spec §K.2b, Appendix C-13; PR #89 follow-up). This is the CPU
// reference of the batched miner structure the GPU backends must mirror:
//
//   * A, U, V are TEMPLATE-scoped (§A.2 v4.1, invariant I1'): expanded ONCE
//     per template, and the left factor P = U*A is computed ONCE per template
//     (one m x n x n GEMM, amortized over the whole nonce sweep).
//   * Per nonce, only B is expanded (nonce-fresh); the per-nonce right factor
//     is Q_i = B_i*V (n x m).
//   * The Q per-nonce combines are fused into ONE LARGE DENSE GEMM
//         P * [B_1*V | B_2*V | ... | B_Q*V]   (m x n by n x Q*m)
//     via the limb-tensor path (ComputeCombineLimbTensorStacked, Appendix
//     C-13) — the dense, square-ish shape the profile exists to enforce; the
//     result is sliced per nonce, serialized, and digested. On device the
//     Q_i = B_i*V GEMMs also stack ([B_1; ...; B_Q] * V, Q*n x n x m) and
//     operand expansion for window w+1 overlaps the GEMMs of window w (SHA on
//     integer units, GEMMs on tensor units). Neither fusion changes any byte:
//     integer arithmetic is exact and every output entry depends only on its
//     own row/column, so every result below is asserted equal to the
//     single-nonce matmul_v4::ComputeDigest.
//
// DETERMINISM: pure integer arithmetic; results are byte-identical to the
// per-nonce reference path for every nonce in the batch (enforced by
// matmul_v4_batch_tests.cpp). Batching is a MINER-ONLY optimization: the
// verifier (matmul_v4::VerifySketch) is untouched and still checks ONE
// winning nonce in O(n^2).

namespace matmul::v4 {

/** Default nonce-window size Q for the CPU reference miner (pow.cpp wiring;
 *  override with the BTX_MATMUL_V4_BATCH environment variable, clamped to
 *  [1, kMaxMinerBatch]). GPU backends choose their own Q to fill the device —
 *  larger Q makes the stacked combine GEMM denser at Q*m*(n+m)*4 bytes of
 *  int32 intermediates per window (~64 MiB at n=4096, b=4, Q=8 for Qstack). */
inline constexpr uint32_t kDefaultMinerBatch = 8;
inline constexpr uint32_t kMaxMinerBatch = 1024;

/** Result of one nonce attempt inside a batch. */
struct BatchNonceResult {
    uint64_t nonce{0};
    uint256 digest;
    std::vector<unsigned char> payload; // serialized sketch, 8*m^2 bytes
};

/** Template-scoped batched sketch miner. Construct once per block template;
 *  Mine() sweeps nonce windows reusing the cached A, U, V and P = U*A. */
class BatchedSketchMiner
{
public:
    /** `header` is the block template (any nNonce64 / §H.4 seeds; the
     *  template projection zeroes them). `n` must validate against kTileB
     *  (ValidateDims) and the combine limb bound (n <= 8589). */
    BatchedSketchMiner(const CBlockHeader& header, uint32_t n);

    /** False iff (n, kTileB) failed validation; Mine() must not be called. */
    [[nodiscard]] bool Valid() const { return m_valid; }

    /** Compute digests for a window of fully-populated candidate headers
     *  (nNonce64 set per candidate and seed_a/seed_b already re-derived per
     *  the §H.4 rule, exactly as SolveMatMulV4 does). Every entry is
     *  byte-identical to matmul_v4::ComputeDigest on the same header. Returns
     *  false iff the miner is invalid, `headers` is empty, or any header does
     *  not project onto this miner's template (fail closed: a stale template
     *  must never be silently combined with fresh nonces). */
    [[nodiscard]] bool Mine(const std::vector<CBlockHeader>& headers,
                            std::vector<BatchNonceResult>& out) const;

    /** Convenience window for tests/benches: clones the construction template
     *  and sets nNonce64 = start_nonce + i for i in [0, count). NOTE: this
     *  does NOT re-derive the §H.4 seed_a/seed_b header fields per nonce, so
     *  it matches the consensus miner only for headers whose seed fields are
     *  held fixed; the real solve loop (pow.cpp) uses the header-window
     *  overload above. */
    [[nodiscard]] bool Mine(uint64_t start_nonce, uint32_t count,
                            std::vector<BatchNonceResult>& out) const;

    /** m = n / kTileB. */
    [[nodiscard]] uint32_t SketchDim() const { return m_m; }

    /** The template hash all candidate headers must project onto. */
    [[nodiscard]] const uint256& TemplateHash() const { return m_template_hash; }

private:
    CBlockHeader m_template;
    uint256 m_template_hash;
    uint32_t m_n{0};
    uint32_t m_m{0};
    bool m_valid{false};
    std::vector<int8_t> m_A; // template-cached operand A (n*n, balanced s8)
    std::vector<int8_t> m_U; // template-cached projector U (m*n)
    std::vector<int8_t> m_V; // template-cached projector V (n*m)
    std::vector<int32_t> m_P; // template-cached left factor P = U*A (m*n, exact s32)
};

} // namespace matmul::v4

#endif // BTX_MATMUL_MATMUL_V4_BATCH_H
