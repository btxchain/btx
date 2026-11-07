// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_MINE_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_MINE_H

#include <cstdint>

namespace modelnet {

/**
 * Mining counters this plane keeps fixed. There is no setter.
 * mined() stays false. blocks() stays 0.
 * Noting a spacing and claiming a deadline do not change them.
 * Nothing is mined.
 */
class SwarmClockSpanMine {
public:
    bool mined() const;
    int64_t blocks() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_MINE_H
