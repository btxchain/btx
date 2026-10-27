// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/gate.h>

#include <modelnet/swarm_capact/codes.h>
#include <modelnet/swarm_capact/grantkind.h>

namespace modelnet {

std::string SwarmCapActGrantRefusal(const SwarmCapActGrants& grants, const std::string& name)
{
    const SwarmCapActGrantKind kind = SwarmCapActClassifyGrant(grants, name);
    if (kind == SwarmCapActGrantKind::Ready) return {};
    const char* code = SwarmCapActGrantKindCode(kind);
    if (code == nullptr) return std::string{kSwarmCapActCapability};
    return std::string{code};
}

} // namespace modelnet
