// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/grantkind.h>

#include <modelnet/swarm_capact/blank.h>
#include <modelnet/swarm_capact/codes.h>
#include <modelnet/swarm_capact/replay.h>

namespace modelnet {

SwarmCapActGrantKind SwarmCapActClassifyGrant(const SwarmCapActGrants& grants, const std::string& name)
{
    if (SwarmCapActBlank(name)) return SwarmCapActGrantKind::Capability;
    if (SwarmCapActGrantIsReplay(grants, name)) return SwarmCapActGrantKind::Replay;
    return SwarmCapActGrantKind::Ready;
}

const char* SwarmCapActGrantKindCode(SwarmCapActGrantKind kind)
{
    switch (kind) {
    case SwarmCapActGrantKind::Capability:
        return kSwarmCapActCapability;
    case SwarmCapActGrantKind::Replay:
        return kSwarmCapActReplay;
    case SwarmCapActGrantKind::Ready:
        return nullptr;
    }
    return kSwarmCapActCapability;
}

} // namespace modelnet
