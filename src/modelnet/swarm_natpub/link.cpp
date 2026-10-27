// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/link.h>

namespace modelnet {

bool SwarmNatPubLink::connected() const
{
    return m_discover.connects();
}

bool SwarmNatPubLink::connected(const std::string& endpoint) const
{
    return m_discover.connects(endpoint);
}

} // namespace modelnet
