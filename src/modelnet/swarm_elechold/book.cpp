// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/book.h>

#include <modelnet/swarm_elechold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmElecHoldBook::measured() const
{
    return m_stored && SwarmElecHoldRecordUsable(m_record);
}

int64_t SwarmElecHoldBook::watt_hours() const
{
    if (!measured()) return kSwarmElecHoldUnset;
    return m_record.watt_hours;
}

bool SwarmElecHoldBook::store(int64_t watt_hours)
{
    // A second store is not written. The first watt-hour count stays.
    if (m_stored) return false;
    SwarmElecHoldRecord record = SwarmElecHoldMakeRecord(watt_hours);
    if (!SwarmElecHoldRecordUsable(record)) return false;
    m_record = std::move(record);
    m_stored = true;
    return true;
}

} // namespace modelnet
