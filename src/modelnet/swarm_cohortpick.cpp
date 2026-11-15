// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cohortpick.h>

#include <modelnet/swarm_cycle.h>

#include <algorithm>

namespace modelnet {

bool SwarmCohortPick::Admit(const std::string& member, int64_t now_ms, int64_t lease_until_ms, bool checkpoint_match,
                            bool recipe_match, std::string& err)
{
    if (member.empty()) {
        err = "MEMBER";
        return false;
    }
    if (Contains(member)) {
        err = "REPLAY";
        return false;
    }
    if (!SwarmAdmitCohortMember(now_ms, lease_until_ms, checkpoint_match, recipe_match, err)) return false;
    m_members.push_back(member);
    err.clear();
    return true;
}

bool SwarmCohortPick::Contains(const std::string& member) const
{
    return std::find(m_members.begin(), m_members.end(), member) != m_members.end();
}

std::size_t SwarmCohortPick::size() const
{
    return m_members.size();
}

} // namespace modelnet
