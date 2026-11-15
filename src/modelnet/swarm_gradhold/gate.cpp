// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/gate.h>

#include <modelnet/swarm_gradhold/blank.h>
#include <modelnet/swarm_gradhold/codes.h>
#include <modelnet/swarm_gradhold/replay.h>

namespace modelnet {

SwarmGradHoldDecision SwarmGradHoldDecide(const SwarmGradHoldBook& book, const std::string& update_id)
{
    std::string err;
    if (!SwarmGradHoldBlank{}.accept(update_id, err)) {
        return SwarmGradHoldDecision{err, false};
    }
    if (SwarmGradHoldIsReplay(book, update_id)) {
        return SwarmGradHoldDecision{std::string{kSwarmGradHoldReplay}, false};
    }
    return SwarmGradHoldDecision{{}, true};
}

} // namespace modelnet
