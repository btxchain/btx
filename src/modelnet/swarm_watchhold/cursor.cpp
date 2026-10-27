// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/cursor.h>

#include <modelnet/swarm_watchhold/limits.h>

namespace modelnet {

int64_t SwarmWatchHoldCursor::latest() const
{
    if (!m_observed) return 0;
    return m_latest;
}

bool SwarmWatchHoldCursor::observed() const
{
    return m_observed;
}

bool SwarmWatchHoldCursor::Advance(int64_t sequence)
{
    if (sequence < kSwarmWatchHoldMinSequence) return false;
    if (m_observed && sequence <= m_latest) return false;
    m_latest = sequence;
    m_observed = true;
    return true;
}

} // namespace modelnet
