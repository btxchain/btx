// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/remain.h>

namespace modelnet {

void SwarmEarlyHaltRemain::arm(int64_t budget)
{
    if (m_armed) return;
    m_armed = true;
    m_left = budget;
}

void SwarmEarlyHaltRemain::spend()
{
    if (m_left > 0) {
        m_left -= 1;
    }
}

void SwarmEarlyHaltRemain::freeze()
{
    m_left = 0;
}

} // namespace modelnet
