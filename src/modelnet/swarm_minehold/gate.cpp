// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/gate.h>

#include <modelnet/swarm_minehold/blank.h>
#include <modelnet/swarm_minehold/codes.h>
#include <modelnet/swarm_minehold/replay.h>

namespace modelnet {

SwarmMineHoldDecision SwarmMineHoldDecide(const SwarmMineHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmMineHoldBlank{}.accept(name, err)) {
        return SwarmMineHoldDecision{err, false};
    }
    if (SwarmMineHoldIsReplay(book, name)) {
        return SwarmMineHoldDecision{std::string{kSwarmMineHoldReplay}, false};
    }
    return SwarmMineHoldDecision{{}, true};
}

} // namespace modelnet
