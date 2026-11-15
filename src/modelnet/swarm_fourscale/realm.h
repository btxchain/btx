// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_REALM_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_REALM_H

namespace modelnet {

/**
 * Graduation flag for this plane.
 * It stays false. There is no setter. Graduate cannot turn it on.
 */
class SwarmFourScaleRealm {
public:
    bool graduated() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_REALM_H
