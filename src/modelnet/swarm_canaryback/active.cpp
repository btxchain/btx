// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/active.h>

namespace modelnet {

const std::string& SwarmCanaryBackActive::get() const
{
    return m_id;
}

void SwarmCanaryBackActive::replace(const std::string& id)
{
    m_id = id;
}

} // namespace modelnet
