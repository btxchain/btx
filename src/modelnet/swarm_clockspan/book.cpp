// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/book.h>

#include <modelnet/swarm_clockspan/limits.h>

#include <utility>

namespace modelnet {

bool SwarmClockSpanBook::noted() const
{
    return m_stored && SwarmClockSpanRecordUsable(m_record);
}

int64_t SwarmClockSpanBook::spacing() const
{
    if (!noted()) return kSwarmClockSpanUnset;
    return m_record.seconds;
}

bool SwarmClockSpanBook::store(int64_t seconds)
{
    // A second store is not written. The first spacing stays.
    if (m_stored) return false;
    SwarmClockSpanRecord record = SwarmClockSpanMakeRecord(seconds);
    if (!SwarmClockSpanRecordUsable(record)) return false;
    m_record = std::move(record);
    m_stored = true;
    return true;
}

} // namespace modelnet
