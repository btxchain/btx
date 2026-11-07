// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/engine.h>

#include <modelnet/swarm_kvmove/codes.h>

#include <string>

namespace modelnet {

SwarmKvMoveEngineKind SwarmKvMoveClassifyEngine(const std::string& engine)
{
    if (engine == kSwarmKvMoveEngineMemory) {
        return SwarmKvMoveEngineKind::Memory;
    }
    if (engine == kSwarmKvMoveEngineNixl || engine == kSwarmKvMoveEngineMooncake || engine == kSwarmKvMoveEngineRdma) {
        return SwarmKvMoveEngineKind::Absent;
    }
    return SwarmKvMoveEngineKind::Other;
}

} // namespace modelnet
