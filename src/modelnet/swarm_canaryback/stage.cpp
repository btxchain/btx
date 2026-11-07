// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/stage.h>

#include <modelnet/swarm_canaryback/id.h>

namespace modelnet {

bool SwarmCanaryBackStage::Apply(SwarmCanaryBackCandidate& candidate, const std::string& id, std::string& err) const
{
    if (!SwarmCanaryBackIdGate{}.accept(id, err)) {
        return false;
    }
    candidate.store(id);
    err.clear();
    return true;
}

} // namespace modelnet
