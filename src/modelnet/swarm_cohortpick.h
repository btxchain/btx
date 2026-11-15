// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_COHORTPICK_H
#define BTX_MODELNET_SWARM_COHORTPICK_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Stored cohort members. An empty member is MEMBER. A member already stored
 * is REPLAY. SwarmAdmitCohortMember rejects an expired lease and a checkpoint
 * or recipe mismatch; those failures store nothing. A successful admit stores
 * the member.
 */
class SwarmCohortPick {
public:
    bool Admit(const std::string& member, int64_t now_ms, int64_t lease_until_ms, bool checkpoint_match,
               bool recipe_match, std::string& err);
    bool Contains(const std::string& member) const;
    std::size_t size() const;

private:
    std::vector<std::string> m_members;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_COHORTPICK_H
