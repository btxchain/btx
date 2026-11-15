// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_DISCOVER_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_DISCOVER_H

#include <string>

namespace modelnet {

/**
 * Discovery does not connect.
 * connects() is false for every peer, including one that has been admitted.
 * There is no method that opens a connection or stores a peer.
 */
class SwarmFamilyAdmitDiscover {
public:
    bool connects(const std::string& peer) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_DISCOVER_H
