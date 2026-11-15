// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REORG_H
#define BTX_MODELNET_SWARM_REORG_H

#include <string>

namespace modelnet {

/**
 * Local channel record after a confirmation drop.
 * in_flight_released stays false. This record does not broadcast and does
 * not release in-flight payments.
 */
struct SwarmReorgChannel {
    bool broadcast{false};
    int confirmations{0};
    bool in_flight_released{false};
    bool confirmed{false};
};

/** Outcome of SwarmNoteReorg. code is the only field. */
struct SwarmReorgResult {
    std::string code;
};

/**
 * Reconciles a local channel record after a confirmation drop.
 * This function does not broadcast and does not release in-flight payments.
 *
 * in_flight_released is forced false on every return.
 * broadcast false is REORG_NO_BROADCAST, confirmations become 0, confirmed
 * is false, and the call returns false.
 * new_confirmations < 0 is REORG, confirmations stay unchanged, confirmed
 * is false, and the call returns false.
 * Otherwise the code is REORG_HELD, confirmations become the minimum of the
 * previous confirmations and new_confirmations, confirmed is false, and the
 * call returns true. A drop does not increase confirmations and does not
 * mark the channel confirmed.
 */
bool SwarmNoteReorg(SwarmReorgChannel& channel, int new_confirmations, SwarmReorgResult& result);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REORG_H
