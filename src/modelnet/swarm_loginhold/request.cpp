// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/request.h>

#include <modelnet/swarm_loginhold/codes.h>
#include <modelnet/swarm_loginhold/gate.h>
#include <modelnet/swarm_loginhold/stay.h>

namespace modelnet {

bool SwarmLoginHoldRequest::Apply(SwarmLoginHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmLoginHoldDecision decision = SwarmLoginHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmLoginHoldReplay;
        } else {
            err = kSwarmLoginHoldLogin;
        }
        return false;
    }
    err = SwarmLoginHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
