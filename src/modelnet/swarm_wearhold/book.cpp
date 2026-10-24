// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/book.h>

#include <modelnet/swarm_wearhold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmWearHoldBook::measured() const
{
    return m_stored && SwarmWearHoldRecordUsable(m_record);
}

int64_t SwarmWearHoldBook::joules() const
{
    if (!measured()) return kSwarmWearHoldUnset;
    return m_record.joules;
}

bool SwarmWearHoldBook::store(int64_t joules)
{
    // A second store is not written. The first joule count stays.
    if (m_stored) return false;
    SwarmWearHoldRecord record = SwarmWearHoldMakeRecord(joules);
    if (!SwarmWearHoldRecordUsable(record)) return false;
    m_record = std::move(record);
    m_stored = true;
    return true;
}

} // namespace modelnet
