// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/request.h>

#include <modelnet/swarm_mixedhold/codes.h>
#include <modelnet/swarm_mixedhold/gate.h>
#include <modelnet/swarm_mixedhold/stay.h>

namespace modelnet {

bool SwarmMixedHoldRequest::Apply(SwarmMixedHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmMixedHoldDecision decision = SwarmMixedHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmMixedHoldReplay;
        } else {
            err = kSwarmMixedHoldPrecision;
        }
        return false;
    }
    err = SwarmMixedHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
