// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_QUIET_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * What family admission is not allowed to do.
 * bytes_moved() stays 0. launched() stays false.
 * There is no method that sets either.
 */
class SwarmFamilyAdmitQuiet {
public:
    int64_t bytes_moved() const;
    bool launched() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_QUIET_H
