// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_SPAN_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_SPAN_H

#include <cstdint>

namespace modelnet {

/** True when seconds is below 1. That note stores nothing. */
bool SwarmClockSpanBelowOne(int64_t seconds);

/** True when seconds is the 90-second block spacing. */
bool SwarmClockSpanIsExact(int64_t seconds);

/**
 * True when seconds is at least 1 and is not 90.
 * That note is SPACING and stores nothing.
 */
bool SwarmClockSpanIsOther(int64_t seconds);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_SPAN_H
