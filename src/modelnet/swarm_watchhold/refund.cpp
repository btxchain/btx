// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/refund.h>

#include <modelnet/swarm_watchhold/codes.h>
#include <modelnet/swarm_watchhold/margin.h>

namespace modelnet {

bool SwarmWatchHoldRefund(const SwarmWatchHoldCursor& cursor, SwarmWatchHoldNote& note, int64_t height, int64_t refund_height, std::string& err)
{
    if (SwarmWatchHoldMarginShort(height, refund_height)) {
        err = kSwarmWatchHoldMargin;
        return false;
    }
    if (!cursor.observed()) {
        err = kSwarmWatchHoldSequence;
        return false;
    }
    if (!note.Remember(height, refund_height)) {
        err = kSwarmWatchHoldMargin;
        return false;
    }
    err = kSwarmWatchHoldHeld;
    return false;
}

} // namespace modelnet
