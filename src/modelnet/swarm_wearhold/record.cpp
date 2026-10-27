// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/record.h>

#include <modelnet/swarm_wearhold/joule.h>

namespace modelnet {

SwarmWearHoldRecord SwarmWearHoldMakeRecord(int64_t joules)
{
    SwarmWearHoldRecord record;
    record.joules = joules;
    return record;
}

bool SwarmWearHoldRecordUsable(const SwarmWearHoldRecord& record)
{
    return SwarmWearHoldStorable(record.joules);
}

} // namespace modelnet
