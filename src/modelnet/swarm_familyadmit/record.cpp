// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/record.h>

namespace modelnet {

SwarmFamilyAdmitRecord SwarmFamilyAdmitMakeRecord(const std::string& peer, const std::string& family)
{
    SwarmFamilyAdmitRecord record;
    record.peer = peer;
    record.family = family;
    return record;
}

bool SwarmFamilyAdmitRecordUsable(const SwarmFamilyAdmitRecord& record)
{
    return !record.peer.empty() && !record.family.empty();
}

} // namespace modelnet
