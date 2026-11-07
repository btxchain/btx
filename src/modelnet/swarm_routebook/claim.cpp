// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/claim.h>

#include <modelnet/swarm_routebook/codes.h>

#include <string>

namespace modelnet {

bool SwarmRouteBookRefuseClaim(const std::string& route, std::string& err)
{
    // A known route and an unknown route are both unqualified.
    static_cast<void>(route.size());
    err = SWARM_ROUTEBOOK_UNQUALIFIED;
    return false;
}

} // namespace modelnet
