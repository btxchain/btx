// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_REALM_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_REALM_H

#include <cstdint>

namespace modelnet {

/**
 * Status this plane cannot change.
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 * There is no method that sets any of them.
 */
class SwarmIdleDrainRealm {
public:
    int64_t bytes_moved() const;
    bool gpu() const;
    bool launched() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_REALM_H
