// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_COHORTINCL_H
#define BTX_MODELNET_SWARM_COHORTINCL_H

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

/**
 * Cohort lease admission with an inclusive expiry.
 * lease_until_ms == now_ms is still admitted. lease_until_ms < now_ms is
 * expired and stores nothing. mined stays false. This class does not mine,
 * broadcast, spend, or connect, and it does not call SwarmAdmitCohortMember.
 *
 * Admit order, first match wins: an empty member is MEMBER and stores
 * nothing. now_ms or lease_until_ms below 0 is RANGE and stores nothing.
 * A member already stored is REPLAY and leaves the first admission.
 * lease_until_ms below now_ms is EXPIRED and stores nothing. Otherwise the
 * member is stored and err is cleared.
 */
class SwarmCohortIncl {
public:
    bool Admit(const std::string& member, int64_t now_ms, int64_t lease_until_ms, std::string& err);
    bool admitted(const std::string& member) const;
    bool mined() const;

private:
    std::set<std::string> m_members;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_COHORTINCL_H
