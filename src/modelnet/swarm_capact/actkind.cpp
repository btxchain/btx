// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/actkind.h>

#include <modelnet/swarm_capact/blank.h>
#include <modelnet/swarm_capact/codes.h>
#include <modelnet/swarm_capact/replay.h>

namespace modelnet {

SwarmCapActActKind SwarmCapActClassifyAct(const SwarmCapActGrants& grants,
                                           const SwarmCapActActions& actions,
                                           const std::string& name)
{
    if (SwarmCapActBlank(name)) return SwarmCapActActKind::Capability;
    if (!grants.contains(name)) return SwarmCapActActKind::NotActed;
    if (SwarmCapActActionIsReplay(actions, name)) return SwarmCapActActKind::Replay;
    return SwarmCapActActKind::Ready;
}

const char* SwarmCapActActKindCode(SwarmCapActActKind kind)
{
    switch (kind) {
    case SwarmCapActActKind::Capability:
        return kSwarmCapActCapability;
    case SwarmCapActActKind::NotActed:
        return kSwarmCapActNotActed;
    case SwarmCapActActKind::Replay:
        return kSwarmCapActReplay;
    case SwarmCapActActKind::Ready:
        return nullptr;
    }
    return kSwarmCapActCapability;
}

} // namespace modelnet
