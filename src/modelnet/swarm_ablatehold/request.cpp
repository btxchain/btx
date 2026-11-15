// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/request.h>

#include <modelnet/swarm_ablatehold/codes.h>
#include <modelnet/swarm_ablatehold/gate.h>
#include <modelnet/swarm_ablatehold/stay.h>

namespace modelnet {

bool SwarmAblateHoldRequest::Apply(SwarmAblateHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmAblateHoldDecision decision = SwarmAblateHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmAblateHoldReplay;
        } else {
            err = kSwarmAblateHoldAblation;
        }
        return false;
    }
    err = SwarmAblateHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
