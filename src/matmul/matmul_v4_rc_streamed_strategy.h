// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STREAMED_STRATEGY_H
#define BTX_MATMUL_MATMUL_V4_RC_STREAMED_STRATEGY_H

#include <cstdint>

// Adversarial Streamed / capacity-bypass strategies for ENC_RC V3 measurement.
//
// These are miner-local harness labels only. They do not change consensus
// digests, heights, or GKR. Never invent performance numbers — pair each
// strategy with device-timed absolute nonce/s on the target SKU.
//
// See doc/btx-matmul-v4.5-v3-adversarial-miner-analysis.md § Streamed strategies.

namespace matmul::v4::rc {

enum class RCStreamedStrategy : uint32_t {
    /** Unlabeled / not selected. */
    Unspecified = 0,
    /** Keep a hot ~32 GiB working set of bank pages on device; fault the rest. */
    Hot32GiBCache = 1,
    /** Stage bank pages from pinned host memory (cudaHostAlloc / equivalent). */
    PinnedHost = 2,
    /** Overlap compute on buffer A with H2D of buffer B (and swap). */
    DoubleBuffer = 3,
    /** Regenerate pages from seed/XOF instead of retaining full bank capacity. */
    SeedRegen = 4,
    /** Shard barriers / pages / Q across multiple consumer GPUs. */
    MultiGpuShard = 5,
    /** Compose Hot32GiBCache with streaming of cold pages. */
    PartialCacheStream = 6,
    /** Compose Hot32GiBCache with SeedRegen for cold misses. */
    PartialCacheRegen = 7,
};

[[nodiscard]] inline constexpr const char* RCStreamedStrategyName(RCStreamedStrategy s)
{
    switch (s) {
    case RCStreamedStrategy::Unspecified: return "unspecified";
    case RCStreamedStrategy::Hot32GiBCache: return "hot_32gib_cache";
    case RCStreamedStrategy::PinnedHost: return "pinned_host";
    case RCStreamedStrategy::DoubleBuffer: return "double_buffer";
    case RCStreamedStrategy::SeedRegen: return "seed_regen";
    case RCStreamedStrategy::MultiGpuShard: return "multi_gpu_shard";
    case RCStreamedStrategy::PartialCacheStream: return "partial_cache_stream";
    case RCStreamedStrategy::PartialCacheRegen: return "partial_cache_regen";
    }
    return "unknown";
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STREAMED_STRATEGY_H
