// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/score.h>

namespace modelnet {

bool SwarmEarlyHaltScore::lower_than(int64_t next) const
{
    return m_held && next < m_value;
}

void SwarmEarlyHaltScore::store(int64_t next)
{
    m_held = true;
    m_value = next;
}

} // namespace modelnet
