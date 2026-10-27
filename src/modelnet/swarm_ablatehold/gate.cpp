// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/gate.h>

#include <modelnet/swarm_ablatehold/blank.h>
#include <modelnet/swarm_ablatehold/codes.h>
#include <modelnet/swarm_ablatehold/replay.h>

namespace modelnet {

SwarmAblateHoldDecision SwarmAblateHoldDecide(const SwarmAblateHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmAblateHoldBlank{}.accept(name, err)) {
        return SwarmAblateHoldDecision{err, false};
    }
    if (SwarmAblateHoldIsReplay(book, name)) {
        return SwarmAblateHoldDecision{std::string{kSwarmAblateHoldReplay}, false};
    }
    return SwarmAblateHoldDecision{{}, true};
}

} // namespace modelnet
