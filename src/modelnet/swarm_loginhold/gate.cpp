// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/gate.h>

#include <modelnet/swarm_loginhold/blank.h>
#include <modelnet/swarm_loginhold/codes.h>
#include <modelnet/swarm_loginhold/replay.h>

namespace modelnet {

SwarmLoginHoldDecision SwarmLoginHoldDecide(const SwarmLoginHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmLoginHoldBlank{}.accept(name, err)) {
        return SwarmLoginHoldDecision{err, false};
    }
    if (SwarmLoginHoldIsReplay(book, name)) {
        return SwarmLoginHoldDecision{std::string{kSwarmLoginHoldReplay}, false};
    }
    return SwarmLoginHoldDecision{{}, true};
}

} // namespace modelnet
