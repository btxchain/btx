// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/gate.h>

#include <modelnet/swarm_wearhold/codes.h>
#include <modelnet/swarm_wearhold/replay.h>
#include <modelnet/swarm_wearhold/under.h>

namespace modelnet {

std::string SwarmWearHoldRefusal(const SwarmWearHoldBook& book, int64_t joules)
{
    std::string err;
    if (!SwarmWearHoldUnder{}.accept(joules, err)) return err;
    if (SwarmWearHoldIsReplay(book, joules)) return std::string{kSwarmWearHoldReplay};
    return {};
}

} // namespace modelnet
