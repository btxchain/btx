// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/gate.h>

#include <modelnet/swarm_passhold/blank.h>
#include <modelnet/swarm_passhold/codes.h>
#include <modelnet/swarm_passhold/replay.h>

namespace modelnet {

SwarmPassHoldDecision SwarmPassHoldDecide(const SwarmPassHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmPassHoldBlank{}.accept(name, err)) {
        return SwarmPassHoldDecision{err, false};
    }
    if (SwarmPassHoldIsReplay(book, name)) {
        return SwarmPassHoldDecision{std::string{kSwarmPassHoldReplay}, false};
    }
    return SwarmPassHoldDecision{{}, true};
}

} // namespace modelnet
