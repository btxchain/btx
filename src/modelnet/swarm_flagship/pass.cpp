// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/pass.h>

#include <modelnet/swarm_flagship/catalog.h>
#include <modelnet/swarm_flagship/codes.h>

#include <string>

namespace modelnet {

bool SwarmFlagshipPass::apply(const std::string& stage, std::string& err) const
{
    if (!SwarmFlagshipCatalog::known(stage)) {
        return SwarmFlagshipRefuse(err, kSwarmFlagshipStage);
    }
    return SwarmFlagshipRefuse(err, kSwarmFlagshipNotPassed);
}

} // namespace modelnet
