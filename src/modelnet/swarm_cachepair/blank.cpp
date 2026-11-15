// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/blank.h>

namespace modelnet {

bool SwarmCachePairPageBlank(const std::string& page)
{
    return page.empty();
}

bool SwarmCachePairMemberBlank(const std::string& member)
{
    return member.empty();
}

} // namespace modelnet
