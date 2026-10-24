// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/request.h>

#include <modelnet/swarm_ckpttrust/codes.h>
#include <modelnet/swarm_ckpttrust/gate.h>
#include <modelnet/swarm_ckpttrust/stay.h>

namespace modelnet {

bool SwarmCheckpointTrustRequest::Apply(SwarmCheckpointTrustBook& book, const std::string& claim, std::string& err) const
{
    const SwarmCheckpointTrustDecision decision = SwarmCheckpointTrustDecide(book, claim);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(claim) || !book.contains(claim)) {
        if (book.contains(claim)) {
            err = kSwarmCheckpointTrustReplay;
        } else {
            err = kSwarmCheckpointTrustClaim;
        }
        return false;
    }
    err = SwarmCheckpointTrustStay{}.refusal();
    return false;
}

} // namespace modelnet
