// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_LINK_H
#define BITCOIN_MODELNET_SWARM_NATPUB_LINK_H

#include <modelnet/swarm_natpub/discover.h>

#include <string>

namespace modelnet {

/**
 * Connection view for this plane.
 * connected() follows discovery and stays false. Claim does not flip it.
 * There is no setter.
 */
class SwarmNatPubLink {
public:
    bool connected() const;
    bool connected(const std::string& endpoint) const;

private:
    SwarmNatPubDiscover m_discover;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_LINK_H
