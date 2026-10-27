// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/request.h>

#include <modelnet/swarm_holdrot/codes.h>
#include <modelnet/swarm_holdrot/gate.h>
#include <modelnet/swarm_holdrot/stay.h>

namespace modelnet {

bool SwarmHoldoutRotateRequest::Apply(SwarmHoldoutRotateBook& book, const std::string& holdout, std::string& err) const
{
    const SwarmHoldoutRotateDecision decision = SwarmHoldoutRotateDecide(book, holdout);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(holdout) || !book.contains(holdout)) {
        if (book.contains(holdout)) {
            err = kSwarmHoldoutRotateReplay;
        } else {
            err = kSwarmHoldoutRotateHoldout;
        }
        return false;
    }
    err = SwarmHoldoutRotateStay{}.refusal();
    return false;
}

} // namespace modelnet
