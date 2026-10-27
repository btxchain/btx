// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/record.h>

#include <modelnet/swarm_elechold/watthour.h>

namespace modelnet {

SwarmElecHoldRecord SwarmElecHoldMakeRecord(int64_t watt_hours)
{
    SwarmElecHoldRecord record;
    record.watt_hours = watt_hours;
    return record;
}

bool SwarmElecHoldRecordUsable(const SwarmElecHoldRecord& record)
{
    return SwarmElecHoldStorable(record.watt_hours);
}

} // namespace modelnet
