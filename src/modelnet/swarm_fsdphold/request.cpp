// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/request.h>

#include <modelnet/swarm_fsdphold/codes.h>
#include <modelnet/swarm_fsdphold/gate.h>
#include <modelnet/swarm_fsdphold/stay.h>

namespace modelnet {

bool SwarmFsdpHoldRequest::Apply(SwarmFsdpHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmFsdpHoldDecision decision = SwarmFsdpHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmFsdpHoldReplay;
        } else {
            err = kSwarmFsdpHoldFsdp;
        }
        return false;
    }
    err = SwarmFsdpHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
