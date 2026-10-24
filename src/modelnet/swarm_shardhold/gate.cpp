// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/gate.h>

#include <modelnet/swarm_shardhold/blank.h>
#include <modelnet/swarm_shardhold/codes.h>
#include <modelnet/swarm_shardhold/replay.h>

namespace modelnet {

SwarmShardHoldDecision SwarmShardHoldDecide(const SwarmShardHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmShardHoldBlank{}.accept(name, err)) {
        return SwarmShardHoldDecision{err, false};
    }
    if (SwarmShardHoldIsReplay(book, name)) {
        return SwarmShardHoldDecision{std::string{kSwarmShardHoldReplay}, false};
    }
    return SwarmShardHoldDecision{{}, true};
}

} // namespace modelnet
