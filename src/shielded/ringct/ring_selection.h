// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_RINGCT_RING_SELECTION_H
#define BTX_SHIELDED_RINGCT_RING_SELECTION_H

#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include <span.h>

namespace shielded::ringct {

/** Ring member positions plus the index of the real spend member. */
struct RingSelection {
    std::vector<uint64_t> positions;
    size_t real_index{0};
};

/** Shared ring member positions plus the real index for each spend member. */
struct SharedRingSelection {
    std::vector<uint64_t> positions;
    std::vector<size_t> real_indices;
};

/**
 * Select ring member positions from the global commitment tree.
 *
 * Sampling is deterministic from @p seed and uses a stratified age-density
 * sampler so practical tree sizes avoid both oldest-bucket collapse and
 * ad-hoc wallet-specific recency fingerprints.
 * The returned real_index identifies the real spend member.
 */
[[nodiscard]] RingSelection SelectRingPositions(uint64_t real_position,
                                                uint64_t tree_size,
                                                const uint256& seed,
                                                size_t ring_size);

/**
 * Select ring positions while trying to avoid @p excluded_positions.
 *
 * Exclusions are best-effort: if the tree does not have enough unique members,
 * selection remains deterministic and may reuse excluded positions.
 */
[[nodiscard]] RingSelection SelectRingPositionsWithExclusions(uint64_t real_position,
                                                              uint64_t tree_size,
                                                              const uint256& seed,
                                                              size_t ring_size,
                                                              Span<const uint64_t> excluded_positions);

/**
 * Select one shared ring for multiple real spend members.
 *
 * The returned ring contains every position in @p real_positions exactly once,
 * plus deterministically sampled decoys. `real_indices[i]` identifies the
 * location of `real_positions[i]` inside the shared ring.
 */
[[nodiscard]] SharedRingSelection SelectSharedRingPositionsWithExclusions(
    Span<const uint64_t> real_positions,
    uint64_t tree_size,
    const uint256& seed,
    size_t ring_size,
    Span<const uint64_t> excluded_positions);

/** Minimum global commitment tree size required for post-fork privacy use. */
[[nodiscard]] uint64_t GetMinimumPrivacyTreeSize(size_t ring_size);

} // namespace shielded::ringct

#endif // BTX_SHIELDED_RINGCT_RING_SELECTION_H
