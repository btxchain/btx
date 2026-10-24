// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/flag.h>

namespace modelnet {

void SwarmPromoteFlag::mark()
{
    m_marked = true;
}

void SwarmPromoteFlag::clear()
{
    m_marked = false;
}

} // namespace modelnet
