// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_RECORD_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_RECORD_H

#include <cstdint>

namespace modelnet {

/**
 * The spacing stored by a successful Note.
 * The record holds the seconds only. It has no deadline and no block count.
 */
struct SwarmClockSpanRecord {
    int64_t seconds{0};
};

SwarmClockSpanRecord SwarmClockSpanMakeRecord(int64_t seconds);

/** True only when seconds is 90. */
bool SwarmClockSpanRecordUsable(const SwarmClockSpanRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_RECORD_H
