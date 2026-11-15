// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/gate.h>

#include <modelnet/swarm_ckpttrust/blank.h>
#include <modelnet/swarm_ckpttrust/codes.h>
#include <modelnet/swarm_ckpttrust/replay.h>

#include <string>

namespace modelnet {

SwarmCheckpointTrustDecision SwarmCheckpointTrustDecide(const SwarmCheckpointTrustBook& book, const std::string& claim)
{
    std::string err;
    if (!SwarmCheckpointTrustBlank{}.accept(claim, err)) {
        return SwarmCheckpointTrustDecision{err, false};
    }
    if (SwarmCheckpointTrustIsReplay(book, claim)) {
        return SwarmCheckpointTrustDecision{std::string{kSwarmCheckpointTrustReplay}, false};
    }
    return SwarmCheckpointTrustDecision{{}, true};
}

} // namespace modelnet
