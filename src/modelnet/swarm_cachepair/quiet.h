// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_QUIET_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * What a recorded cache pair is not allowed to do.
 * bytes_moved() stays 0. cuda_buffer() stays false.
 * launched() stays false. There is no method that sets any of these.
 */
class SwarmCachePairQuiet {
public:
    int64_t bytes_moved() const;
    bool cuda_buffer() const;
    bool launched() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_QUIET_H
