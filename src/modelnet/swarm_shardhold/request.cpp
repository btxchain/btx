// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/request.h>

#include <modelnet/swarm_shardhold/codes.h>
#include <modelnet/swarm_shardhold/gate.h>
#include <modelnet/swarm_shardhold/stay.h>

namespace modelnet {

bool SwarmShardHoldRequest::Apply(SwarmShardHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmShardHoldDecision decision = SwarmShardHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmShardHoldReplay;
        } else {
            err = kSwarmShardHoldShard;
        }
        return false;
    }
    err = SwarmShardHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
