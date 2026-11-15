// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/reserve.h>

#include <cstdint>

namespace modelnet {

bool SwarmFaultReserve::frozen() const
{
    return m_frozen;
}

bool SwarmFaultReserve::has() const
{
    return m_set;
}

int64_t SwarmFaultReserve::amount() const
{
    if (!m_set) {
        return 0;
    }
    return m_amount;
}

void SwarmFaultReserve::Freeze()
{
    m_frozen = true;
}

bool SwarmFaultReserve::store(int64_t amount)
{
    if (m_set) {
        return false;
    }
    if (amount < 1) {
        return false;
    }
    m_amount = amount;
    m_set = true;
    return true;
}

} // namespace modelnet
