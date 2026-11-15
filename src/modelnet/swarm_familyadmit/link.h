// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_LINK_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_LINK_H

#include <modelnet/swarm_familyadmit/discover.h>

#include <string>

namespace modelnet {

/**
 * Connection view for a peer.
 * connected() follows discovery and stays false. Admission does not
 * flip it. There is no setter.
 */
class SwarmFamilyAdmitLink {
public:
    bool connected(const std::string& peer) const;

private:
    SwarmFamilyAdmitDiscover m_discover;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_LINK_H
