// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_QUIET_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * What a canary rollback is not allowed to do.
 * bytes_moved() stays 0. blocks() stays 0. gpu(), graduated(),
 * and mined() stay false. There is no method that sets any of these.
 */
class SwarmCanaryBackQuiet {
public:
    int64_t bytes_moved() const;
    int64_t blocks() const;
    bool gpu() const;
    bool graduated() const;
    bool mined() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_QUIET_H
