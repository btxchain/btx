// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_REPLAY_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_REPLAY_H

#include <modelnet/swarm_clockspan/book.h>

#include <cstdint>

namespace modelnet {

/**
 * True when seconds is 90 and that spacing is already stored.
 * A value below 1, and any other positive seconds, is not a replay.
 */
bool SwarmClockSpanIsReplay(const SwarmClockSpanBook& book, int64_t seconds);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_REPLAY_H
