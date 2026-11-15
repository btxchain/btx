// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/record.h>

#include <modelnet/swarm_cachepair/limits.h>

#include <set>

namespace modelnet {

SwarmCachePairRecord SwarmCachePairMakeRecord(const std::string& page, const std::vector<std::string>& members)
{
    SwarmCachePairRecord record;
    record.page = page;
    record.members = members;
    return record;
}

bool SwarmCachePairRecordUsable(const SwarmCachePairRecord& record)
{
    if (record.page.empty()) return false;
    if (record.members.size() < kSwarmCachePairShareMin) return false;
    std::set<std::string> seen;
    for (const std::string& member : record.members) {
        if (member.empty()) return false;
        if (!seen.insert(member).second) return false;
    }
    return true;
}

} // namespace modelnet
