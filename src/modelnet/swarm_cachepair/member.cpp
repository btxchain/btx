// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/member.h>

#include <modelnet/swarm_cachepair/blank.h>
#include <modelnet/swarm_cachepair/codes.h>

namespace modelnet {

SwarmCachePairMemberKind SwarmCachePairClassifyMember(const std::string& member)
{
    if (SwarmCachePairMemberBlank(member)) return SwarmCachePairMemberKind::Empty;
    return SwarmCachePairMemberKind::Named;
}

const char* SwarmCachePairMemberCode(SwarmCachePairMemberKind kind)
{
    switch (kind) {
    case SwarmCachePairMemberKind::Empty:
        return kSwarmCachePairMember;
    case SwarmCachePairMemberKind::Named:
        return nullptr;
    }
    return kSwarmCachePairMember;
}

} // namespace modelnet
