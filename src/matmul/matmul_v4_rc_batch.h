// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_BATCH_H
#define BTX_MATMUL_MATMUL_V4_RC_BATCH_H

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

// Miner-local Q-batch API for ENC_RC_COUPLED.
//
// Each Q candidate owns independent sigma / lobe state / barrier roots /
// episode digest. Shared across the window: template-scoped bank pages only.
// There is no slot-0 serialization — digests_out[i] is computed from
// headers[i]'s private state alone and must match
// RecomputeCoupledPuzzleReference(headers[i], ...) byte-for-byte.
//
// Optional ExactGemm stacking (Q×W · W×W) is a throughput lever when the page
// schedule is shared; under full_bank_schedule each header still runs its own
// GEMMs. Consensus digests are unchanged either way.
//
// Does not raise heights. Does not enable full-bank schedule / material
// exchange / GKR arbiter beyond RCCoupOptions defaults.

namespace matmul::v4::rc {

/** Soft harness ceiling for RunCoupledQSweep (measurement / tests). Not a
 *  consensus constant; miner TryMineRCCoupledBatch still caps at
 *  dc::kRCMinerBatchQMax. */
inline constexpr uint32_t kRCCoupledQSweepHarnessMax = 4096;

struct RCMinerBatchConfig {
    uint32_t Q{dc::kRCMinerBatchQDefault};
    bool use_resident_bank{true};
};

/**
 * Consecutive-nonce window as SolveMatMulV4RCCoupled builds before
 * TryMineRCCoupledBatch. Caller must re-pin §H.4 seed_a/seed_b per nonce
 * (SetDeterministicMatMulSeeds); bank identity uses RCBankTemplateHash
 * (nonce/seeds cleared). This only clones base and advances nNonce64/nNonce.
 */
[[nodiscard]] inline std::vector<CBlockHeader> BuildRCCoupledMinerNonceWindow(
    const CBlockHeader& base, uint32_t Q)
{
    std::vector<CBlockHeader> window;
    window.reserve(Q);
    for (uint32_t i = 0; i < Q; ++i) {
        CBlockHeader h = base;
        h.nNonce64 = base.nNonce64 + i;
        h.nNonce = static_cast<uint32_t>(h.nNonce64);
        window.push_back(std::move(h));
    }
    return window;
}

/**
 * Mine digests for a window of headers with the same RCCoupParams.
 * Returns false if headers empty, Q out of range, params invalid, or headers
 * do not share a bank template (RCBankTemplateHash / ComputeTemplateHash).
 * On success digests_out.size() == headers.size() and digests_out[i] equals
 * MineCoupledPuzzle(headers[i], ...) / RecomputeCoupledPuzzleReference byte-for-byte.
 *
 * Caps headers.size() at dc::kRCMinerBatchQMax (miner opt, not consensus).
 */
[[nodiscard]] bool TryMineRCCoupledBatch(
    const std::vector<CBlockHeader>& headers, int32_t height, const RCCoupParams& params,
    std::vector<uint256>& digests_out, const RCMinerBatchConfig& cfg = {},
    const matmul::v4::lt::ExactGemmBackend& gemm = {},
    const RCCoupOptions& options = {});

/**
 * Harness / measurement Q-sweep: same independent-state oracle as
 * TryMineRCCoupledBatch, but allows Q beyond dc::kRCMinerBatchQMax up to
 * kRCCoupledQSweepHarnessMax (or q_cap if non-zero and smaller).
 * Digests remain consensus-identical to solo RecomputeCoupledPuzzleReference.
 * Never raises heights.
 */
[[nodiscard]] bool RunCoupledQSweep(
    const std::vector<CBlockHeader>& headers, int32_t height, const RCCoupParams& params,
    std::vector<uint256>& digests_out, uint32_t q_cap = 0,
    const matmul::v4::lt::ExactGemmBackend& gemm = {},
    const RCCoupOptions& options = {});

/** Alias used by datacenter docs / harness — same as MineCoupledPuzzle. */
[[nodiscard]] inline uint256 MineRCCoupledEpisode(
    const CBlockHeader& header, int32_t height, const RCCoupParams& params,
    const matmul::v4::lt::ExactGemmBackend& gemm = {},
    const RCCoupOptions& options = {})
{
    return MineCoupledPuzzle(header, height, params, gemm, options);
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_BATCH_H
