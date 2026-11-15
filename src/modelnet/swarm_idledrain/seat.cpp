// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/seat.h>

namespace modelnet {

void SwarmIdleDrainSeat::admit()
{
    if (m_opened) return;
    m_opened = true;
}

} // namespace modelnet
