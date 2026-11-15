// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_QUIET_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * Send counters this plane keeps fixed. There is no setter.
 * bytes_moved() stays 0. broadcast() stays false.
 * Noting a spacing and claiming a deadline do not change them.
 */
class SwarmClockSpanQuiet {
public:
    int64_t bytes_moved() const;
    bool broadcast() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_QUIET_H
