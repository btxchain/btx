// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/link.h>

namespace modelnet {

bool SwarmPrivFamLink::connected() const
{
    return m_discover.connects();
}

bool SwarmPrivFamLink::connected(const std::string& family) const
{
    return m_discover.connects(family);
}

} // namespace modelnet
