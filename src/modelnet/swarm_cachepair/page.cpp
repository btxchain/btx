// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/page.h>

#include <modelnet/swarm_cachepair/blank.h>
#include <modelnet/swarm_cachepair/codes.h>

namespace modelnet {

SwarmCachePairPageKind SwarmCachePairClassifyPage(const std::string& page)
{
    if (SwarmCachePairPageBlank(page)) return SwarmCachePairPageKind::Empty;
    return SwarmCachePairPageKind::Named;
}

const char* SwarmCachePairPageCode(SwarmCachePairPageKind kind)
{
    switch (kind) {
    case SwarmCachePairPageKind::Empty:
        return kSwarmCachePairPage;
    case SwarmCachePairPageKind::Named:
        return nullptr;
    }
    return kSwarmCachePairPage;
}

} // namespace modelnet
