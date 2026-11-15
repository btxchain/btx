// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_OBSERVE_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_OBSERVE_H

#include <modelnet/swarm_watchhold/cursor.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Watch one sequence.
 * sequence below 1 is SEQUENCE and stores nothing.
 * sequence below latest is STALE and does not change latest.
 * sequence equal to latest is REPLAY.
 * A greater sequence becomes latest.
 * This function takes no secret. Watching a sequence does not release one.
 */
bool SwarmWatchHoldObserve(SwarmWatchHoldCursor& cursor, int64_t sequence, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_OBSERVE_H
