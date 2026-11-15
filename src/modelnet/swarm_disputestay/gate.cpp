// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/gate.h>

#include <modelnet/swarm_disputestay/blank.h>
#include <modelnet/swarm_disputestay/codes.h>
#include <modelnet/swarm_disputestay/replay.h>

namespace modelnet {

SwarmDisputeStayDecision SwarmDisputeStayDecide(const SwarmDisputeStayBook& book, const std::string& dispute)
{
    std::string err;
    if (!SwarmDisputeStayBlank{}.accept(dispute, err)) {
        return SwarmDisputeStayDecision{err, false};
    }
    if (SwarmDisputeStayIsReplay(book, dispute)) {
        return SwarmDisputeStayDecision{std::string{kSwarmDisputeStayReplay}, false};
    }
    return SwarmDisputeStayDecision{{}, true};
}

} // namespace modelnet
