// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_DISTRIBUTED_H
#define BTX_MATMUL_MATMUL_V4_RC_DISTRIBUTED_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC Stage D — distributed bit-exactness (CPU simulation).
//
// Consensus segment IDs are fixed by (K, seg_len) and NEVER depend on device
// count N. Devices only *own* a subset of those IDs; reduction combines int64
// segment partials with integer addition only. ExtractMX fires once on the
// completed sum (H1).
//
// Canonical transcript order (documented; used by DigestSyntheticDistributed):
//   1. Domain tag "BTX_RC_DIST_SYNTH_V1"
//   2. LE32 shape fields: m, n, k, seg_len  (NOT n_devices — N is non-consensus)
//   3. For each consensus segment_id = 0 .. n_segs-1 ascending:
//        LE int64 row-major partial (m×n)
//   4. Extracted int8 matrix (m×n) after ONE Extract on Σ partials
//   5. SHA256d over the concatenation → digest
//
// Can operate on the synthetic GEMM below (preferred; does not depend on
// Stage C). Optionally, Stage C coupled-puzzle barrier mixes are the same
// integer-sum / one-Extract discipline — reuse ReduceDevicePartials /
// DistReduceOrder::PairwiseButterfly on int64 lobe partials; do not re-Extract
// inside a device tree.

namespace matmul::v4::rc {

/** Toy synthetic contraction shape (all dims % 32 for ExtractMX). */
struct DistSynthShape {
    uint32_t m{32};       // rows of C
    uint32_t n{32};       // cols of C
    uint32_t k{128};      // contraction length
    uint32_t seg_len{32}; // consensus-fixed K-segment length
};

/** How a device's local partials are folded before the global segment sum. */
enum class DistReduceOrder : uint8_t {
    TreeLeftToRight = 0, // fold device list [0..N) left-associative
    TreeRightToLeft = 1, // fold device list right-associative
    PairwiseButterfly = 2, // pairwise swap-distance butterfly (N power-of-two)
};

[[nodiscard]] inline uint32_t DistNumSegs(uint32_t k_len, uint32_t seg_len)
{
    if (k_len == 0 || seg_len == 0) return 0;
    return (k_len + seg_len - 1u) / seg_len;
}

/**
 * Consensus segment ID for a K-index — independent of device count.
 * segment_id = k0 / seg_len where k0 is the segment start.
 */
[[nodiscard]] inline uint32_t ConsensusSegmentId(uint32_t k0, uint32_t seg_len)
{
    return seg_len == 0 ? 0u : k0 / seg_len;
}

/** Round-robin ownership: device = segment_id % n_devices. */
[[nodiscard]] inline uint32_t DeviceForSegment(uint32_t segment_id, uint32_t n_devices)
{
    return n_devices == 0 ? 0u : segment_id % n_devices;
}

/** Expand deterministic int8 A (m×k) and B (k×n) from a 32-byte seed. */
void ExpandSynthOperands(const uint256& seed, const DistSynthShape& shape,
                         std::vector<int8_t>& A, std::vector<int8_t>& B);

/**
 * Exact int64 partial for one consensus segment:
 *   C_partial[i][j] = Σ_{t=k0}^{k0+len-1} A[i][t]·B[t][j]
 * Shape of out: m×n. Does NOT Extract.
 */
[[nodiscard]] std::vector<int64_t> SynthSegmentPartial(const std::vector<int8_t>& A,
                                                       const std::vector<int8_t>& B,
                                                       const DistSynthShape& shape,
                                                       uint32_t segment_id);

/**
 * Simulate N devices: each owns segments where DeviceForSegment(id,N)==dev,
 * producing that device's sum of its segment partials (still m×n int64).
 * Also fills per-segment partials in consensus order (canonical; identical for
 * every N).
 */
struct DistDevicePartials {
    /** segs[segment_id] = m×n int64 partial (consensus ID order). */
    std::vector<std::vector<int64_t>> segs;
    /** per_device[dev] = integer sum of that device's owned segs. */
    std::vector<std::vector<int64_t>> per_device;
};

[[nodiscard]] DistDevicePartials SimulateDevices(const std::vector<int8_t>& A,
                                                 const std::vector<int8_t>& B,
                                                 const DistSynthShape& shape,
                                                 uint32_t n_devices);

/** Integer-sum reduce of device matrices under the given fold order. */
[[nodiscard]] std::vector<int64_t> ReduceDevicePartials(
    const std::vector<std::vector<int64_t>>& per_device, DistReduceOrder order);

/** Sum consensus segment partials in ascending segment_id order (canonical). */
[[nodiscard]] std::vector<int64_t> SumSegmentPartials(
    const std::vector<std::vector<int64_t>>& segs);

/**
 * One ExtractMX on the completed int64 matrix (H1). prf from
 * DeriveMatExpandPrfKey(seed_extract).
 */
[[nodiscard]] std::vector<int8_t> ExtractOnce(const uint256& seed_extract,
                                              const std::vector<int64_t>& Y, uint32_t m,
                                              uint32_t n);

/** Canonical digest over segment partials ‖ Extracted tensor (see file header).
 *  Independent of device count and reduction order. */
[[nodiscard]] uint256 DigestSyntheticDistributed(const DistSynthShape& shape,
                                                 const std::vector<std::vector<int64_t>>& segs,
                                                 const std::vector<int8_t>& extracted);

/**
 * End-to-end: expand → segment → reduce devices → Extract once → digest.
 * pre_extract_sum is the int64 matrix immediately before Extract (for equality
 * checks across reduction orders / N).
 */
struct DistEpisodeResult {
    std::vector<int64_t> pre_extract_sum;
    std::vector<int8_t> extracted;
    uint256 digest{};
    uint32_t n_segs{0};
    uint32_t n_devices{0};
    DistReduceOrder order{DistReduceOrder::TreeLeftToRight};
};

[[nodiscard]] DistEpisodeResult RunSyntheticDistributed(const uint256& seed,
                                                        const DistSynthShape& shape,
                                                        uint32_t n_devices,
                                                        DistReduceOrder order);

[[nodiscard]] const char* DistReduceOrderName(DistReduceOrder order);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_DISTRIBUTED_H
