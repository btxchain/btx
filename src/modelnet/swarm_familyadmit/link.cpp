// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/link.h>

namespace modelnet {

bool SwarmFamilyAdmitLink::connected(const std::string& peer) const
{
    return m_discover.connects(peer);
}

} // namespace modelnet
