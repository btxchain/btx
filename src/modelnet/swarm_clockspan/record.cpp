// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/record.h>

#include <modelnet/swarm_clockspan/span.h>

namespace modelnet {

SwarmClockSpanRecord SwarmClockSpanMakeRecord(int64_t seconds)
{
    SwarmClockSpanRecord record;
    record.seconds = seconds;
    return record;
}

bool SwarmClockSpanRecordUsable(const SwarmClockSpanRecord& record)
{
    return SwarmClockSpanIsExact(record.seconds);
}

} // namespace modelnet
