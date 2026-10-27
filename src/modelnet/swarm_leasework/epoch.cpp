// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/epoch.h>

namespace modelnet {

int64_t LeaseWorkEpoch::current() const
{
    return m_epoch;
}

void LeaseWorkEpoch::Bump()
{
    ++m_epoch;
}

} // namespace modelnet
