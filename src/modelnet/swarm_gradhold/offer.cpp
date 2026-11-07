// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/offer.h>

#include <modelnet/swarm_gradhold/codes.h>
#include <modelnet/swarm_gradhold/gate.h>

namespace modelnet {

bool SwarmGradHoldOffer::Apply(SwarmGradHoldBook& book, const std::string& update_id, std::string& err) const
{
    const SwarmGradHoldDecision decision = SwarmGradHoldDecide(book, update_id);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(update_id) || !book.contains(update_id)) {
        if (book.contains(update_id)) {
            err = kSwarmGradHoldReplay;
        } else {
            err = kSwarmGradHoldUpdate;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
