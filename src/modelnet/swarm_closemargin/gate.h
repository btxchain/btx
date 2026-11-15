// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_GATE_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_GATE_H

#include <modelnet/swarm_closemargin/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * What Shrink should do with blocks.
 * code is MARGIN, REPLAY, or empty when the count may be stored.
 * store is true only for a new count of 160.
 * Storing the count does not shrink the margin.
 * This function does not modify the book.
 */
struct SwarmCloseMarginHoldDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Shrink.
 * A count other than 160 is MARGIN and is not stored.
 * A count of 160 already stored is REPLAY. The first request stays.
 * A new count of 160 may be stored. The caller then returns HELD.
 * MARGIN is decided before REPLAY. REPLAY is decided before HELD.
 */
SwarmCloseMarginHoldDecision SwarmCloseMarginHoldDecide(const SwarmCloseMarginHoldBook& book, int64_t blocks);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_GATE_H
