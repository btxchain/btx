// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/note.h>

#include <modelnet/swarm_watchhold/limits.h>
#include <modelnet/swarm_watchhold/margin.h>

namespace modelnet {

bool SwarmWatchHoldNote::noted() const
{
    return m_noted;
}

bool SwarmWatchHoldNote::built() const
{
    return kSwarmWatchHoldRefundBuilt;
}

int64_t SwarmWatchHoldNote::height() const
{
    if (!m_noted) return 0;
    return m_height;
}

int64_t SwarmWatchHoldNote::refund_height() const
{
    if (!m_noted) return 0;
    return m_refund_height;
}

bool SwarmWatchHoldNote::Remember(int64_t height, int64_t refund_height)
{
    if (SwarmWatchHoldMarginShort(height, refund_height)) return false;
    m_height = height;
    m_refund_height = refund_height;
    m_noted = true;
    return true;
}

} // namespace modelnet
