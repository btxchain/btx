// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_QUIET_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * What a cursor advance is not allowed to do.
 * bytes_moved() stays 0. mined() stays false. blocks() stays 0.
 * There is no method that sets any of these.
 */
class SwarmCursorFenceQuiet {
public:
    int64_t bytes_moved() const;
    bool mined() const;
    int64_t blocks() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_QUIET_H
