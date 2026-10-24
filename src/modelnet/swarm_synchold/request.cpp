// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/request.h>

#include <modelnet/swarm_synchold/codes.h>
#include <modelnet/swarm_synchold/gate.h>
#include <modelnet/swarm_synchold/stay.h>

namespace modelnet {

bool SwarmSyncHoldRequest::Apply(SwarmSyncHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmSyncHoldDecision decision = SwarmSyncHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmSyncHoldReplay;
        } else {
            err = kSwarmSyncHoldSync;
        }
        return false;
    }
    err = SwarmSyncHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
