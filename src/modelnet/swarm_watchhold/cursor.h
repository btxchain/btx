// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_CURSOR_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_CURSOR_H

#include <cstdint>

namespace modelnet {

/**
 * The latest watched sequence.
 * Advance stores a sequence at or above 1 that is strictly greater than
 * latest. A stale or replayed sequence is refused and latest stays.
 * There is no rewind and no method that releases a secret.
 */
class SwarmWatchHoldCursor {
public:
    int64_t latest() const;
    bool observed() const;

    /**
     * Store sequence as latest.
     * Refuses sequence below 1, and refuses a sequence that is not strictly
     * greater than the one already stored. On refusal the cursor is unchanged.
     */
    bool Advance(int64_t sequence);

private:
    int64_t m_latest{0};
    bool m_observed{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_CURSOR_H
