// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/request.h>

#include <modelnet/swarm_passhold/codes.h>
#include <modelnet/swarm_passhold/gate.h>
#include <modelnet/swarm_passhold/stay.h>

namespace modelnet {

bool SwarmPassHoldRequest::Apply(SwarmPassHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmPassHoldDecision decision = SwarmPassHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmPassHoldReplay;
        } else {
            err = kSwarmPassHoldPassthrough;
        }
        return false;
    }
    err = SwarmPassHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
