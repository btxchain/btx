// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/observe.h>

#include <modelnet/swarm_watchhold/codes.h>
#include <modelnet/swarm_watchhold/limits.h>

namespace modelnet {

bool SwarmWatchHoldObserve(SwarmWatchHoldCursor& cursor, int64_t sequence, std::string& err)
{
    if (sequence < kSwarmWatchHoldMinSequence) {
        err = kSwarmWatchHoldSequence;
        return false;
    }
    if (cursor.observed() && sequence < cursor.latest()) {
        err = kSwarmWatchHoldStale;
        return false;
    }
    if (cursor.observed() && sequence == cursor.latest()) {
        err = kSwarmWatchHoldReplay;
        return false;
    }
    if (!cursor.Advance(sequence)) {
        err = cursor.observed() && sequence == cursor.latest() ? kSwarmWatchHoldReplay : kSwarmWatchHoldStale;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
