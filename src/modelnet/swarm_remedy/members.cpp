// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/members.h>

#include <modelnet/swarm_remedy/codes.h>

namespace modelnet {

bool SwarmRemedyMembers::Revoke(const std::string& member, std::string& err)
{
    if (member.empty()) {
        err = kSwarmRemedyMember;
        return false;
    }
    if (m_revoked.count(member) != 0) {
        err = kSwarmRemedyReplay;
        return false;
    }
    m_revoked.insert(member);
    err.clear();
    return true;
}

bool SwarmRemedyMembers::Read(const std::string& member, std::string& err)
{
    if (member.empty()) {
        err = kSwarmRemedyMember;
        return false;
    }
    if (m_revoked.count(member) != 0) {
        err = kSwarmRemedyNotRead;
        return false;
    }
    m_reads.insert(member);
    err.clear();
    return true;
}

bool SwarmRemedyMembers::revoked(const std::string& member) const
{
    return m_revoked.count(member) != 0;
}

bool SwarmRemedyMembers::recorded(const std::string& member) const
{
    return m_reads.count(member) != 0;
}

} // namespace modelnet
