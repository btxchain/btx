// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/open.h>

#include <modelnet/swarm_disputestay/codes.h>
#include <modelnet/swarm_disputestay/gate.h>

namespace modelnet {

bool SwarmDisputeStayOpen::Apply(SwarmDisputeStayBook& book, const std::string& dispute, std::string& err) const
{
    const SwarmDisputeStayDecision decision = SwarmDisputeStayDecide(book, dispute);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(dispute) || !book.contains(dispute)) {
        if (book.contains(dispute)) {
            err = kSwarmDisputeStayReplay;
        } else {
            err = kSwarmDisputeStayDispute;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
