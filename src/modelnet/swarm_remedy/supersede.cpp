// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/supersede.h>

#include <modelnet/swarm_remedy/codes.h>

namespace modelnet {

bool SwarmRemedySupersede::Apply(const SwarmRevocation& current, int sequence, unsigned char fill,
                                 SwarmRevocation& prior_out, SwarmRevocation& next_out, std::string& err) const
{
    const SwarmRevocation next = SwarmNewRevocation(sequence, fill);
    SwarmRevocation prior = current;
    std::string superseded;
    if (!SwarmSupersede(prior, next, superseded)) {
        err = kSwarmRemedyStale;
        return false;
    }
    prior_out = prior;
    next_out = next;
    err.clear();
    return true;
}

} // namespace modelnet
