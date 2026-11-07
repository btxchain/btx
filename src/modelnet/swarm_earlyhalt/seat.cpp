// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/seat.h>

namespace modelnet {

void SwarmEarlyHaltSeat::admit(int64_t budget)
{
    if (m_opened) return;
    m_opened = true;
    m_budget = budget;
}

} // namespace modelnet
