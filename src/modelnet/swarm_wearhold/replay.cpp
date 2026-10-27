// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/replay.h>

#include <modelnet/swarm_wearhold/joule.h>

namespace modelnet {

bool SwarmWearHoldIsReplay(const SwarmWearHoldBook& book, int64_t joules)
{
    if (!SwarmWearHoldStorable(joules)) return false;
    return book.measured();
}

} // namespace modelnet
