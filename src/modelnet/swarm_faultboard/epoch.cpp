// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/epoch.h>

#include <cstdint>

namespace modelnet {

int64_t SwarmFaultEpoch::get() const
{
    return m_epoch;
}

void SwarmFaultEpoch::Assign(int64_t epoch)
{
    m_epoch = epoch;
}

} // namespace modelnet
