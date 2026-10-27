// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/gate.h>

#include <modelnet/swarm_synchold/blank.h>
#include <modelnet/swarm_synchold/codes.h>
#include <modelnet/swarm_synchold/replay.h>

namespace modelnet {

SwarmSyncHoldDecision SwarmSyncHoldDecide(const SwarmSyncHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmSyncHoldBlank{}.accept(name, err)) {
        return SwarmSyncHoldDecision{err, false};
    }
    if (SwarmSyncHoldIsReplay(book, name)) {
        return SwarmSyncHoldDecision{std::string{kSwarmSyncHoldReplay}, false};
    }
    return SwarmSyncHoldDecision{{}, true};
}

} // namespace modelnet
