// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/request.h>

#include <modelnet/swarm_minehold/codes.h>
#include <modelnet/swarm_minehold/gate.h>
#include <modelnet/swarm_minehold/stay.h>

namespace modelnet {

bool SwarmMineHoldRequest::Apply(SwarmMineHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmMineHoldDecision decision = SwarmMineHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmMineHoldReplay;
        } else {
            err = kSwarmMineHoldMine;
        }
        return false;
    }
    err = SwarmMineHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
