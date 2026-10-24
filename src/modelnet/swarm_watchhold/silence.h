// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_SILENCE_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_SILENCE_H

#include <cstdint>

namespace modelnet {

/**
 * What a watched sequence is not allowed to do.
 * broadcast() stays false. mined() stays false. bytes_moved() stays 0.
 * There is no method that sets any of these.
 */
class SwarmWatchHoldSilence {
public:
    bool broadcast() const;
    bool mined() const;
    int64_t bytes_moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_SILENCE_H
