// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_INTEGER_BOUND_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_INTEGER_BOUND_H

#include <cstddef>

namespace modelnet {

/**
 * Reads the frozen integer dataset. This plane has no call that appends
 * an example, and it does not claim a GPU ran.
 */
class SwarmDescendantIntegerBound {
public:
    std::size_t pairs() const;
    const char* profile() const;
    bool extends_dataset() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_INTEGER_BOUND_H
