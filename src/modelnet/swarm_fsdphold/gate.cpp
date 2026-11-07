// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/gate.h>

#include <modelnet/swarm_fsdphold/blank.h>
#include <modelnet/swarm_fsdphold/codes.h>
#include <modelnet/swarm_fsdphold/replay.h>

namespace modelnet {

SwarmFsdpHoldDecision SwarmFsdpHoldDecide(const SwarmFsdpHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmFsdpHoldBlank{}.accept(name, err)) {
        return SwarmFsdpHoldDecision{err, false};
    }
    if (SwarmFsdpHoldIsReplay(book, name)) {
        return SwarmFsdpHoldDecision{std::string{kSwarmFsdpHoldReplay}, false};
    }
    return SwarmFsdpHoldDecision{{}, true};
}

} // namespace modelnet
