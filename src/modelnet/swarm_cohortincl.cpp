// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cohortincl.h>

namespace modelnet {

bool SwarmCohortIncl::Admit(const std::string& member, int64_t now_ms, int64_t lease_until_ms, std::string& err)
{
    if (member.empty()) {
        err = "MEMBER";
        return false;
    }
    if (now_ms < 0 || lease_until_ms < 0) {
        err = "RANGE";
        return false;
    }
    if (m_members.find(member) != m_members.end()) {
        err = "REPLAY";
        return false;
    }
    if (lease_until_ms < now_ms) {
        err = "EXPIRED";
        return false;
    }
    m_members.insert(member);
    err.clear();
    return true;
}

bool SwarmCohortIncl::admitted(const std::string& member) const
{
    return m_members.find(member) != m_members.end();
}

bool SwarmCohortIncl::mined() const
{
    return false;
}

} // namespace modelnet
