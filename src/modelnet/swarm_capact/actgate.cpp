// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/actgate.h>

#include <modelnet/swarm_capact/actkind.h>
#include <modelnet/swarm_capact/codes.h>

namespace modelnet {

std::string SwarmCapActActRefusal(const SwarmCapActGrants& grants,
                                   const SwarmCapActActions& actions,
                                   const std::string& name)
{
    const SwarmCapActActKind kind = SwarmCapActClassifyAct(grants, actions, name);
    if (kind == SwarmCapActActKind::Ready) return {};
    const char* code = SwarmCapActActKindCode(kind);
    if (code == nullptr) return std::string{kSwarmCapActCapability};
    return std::string{code};
}

} // namespace modelnet
