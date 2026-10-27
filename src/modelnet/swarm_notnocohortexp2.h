// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOHORTEXP2_H
#define BTX_MODELNET_SWARM_NOTNOCOHORTEXP2_H

#include <string>

namespace modelnet {

/**
 * A local note about one cohort window. cohort_id names the cohort.
 * want_exclude asks this note to exclude a member.
 *
 * This note excludes no member. excluded stays false on every path.
 * Cohort expiry stays inclusive.
 */
struct SwarmNotNoCohortExp2 {
    std::string cohort_id;
    bool want_exclude{false};
};

/**
 * Outcome of noting a cohort. excluded stays false on every path.
 * Cohort expiry stays inclusive. This note excludes no member.
 */
struct SwarmNotNoCohortExp2Result {
    std::string code;
    bool excluded{false};
};

/**
 * Note a cohort without excluding a member.
 * Order, first match wins: an empty cohort_id is COHORT. want_exclude
 * is HELD. Otherwise the note is NOTED and err is cleared. excluded stays
 * false on every path. Cohort expiry stays inclusive. This note excludes
 * no member.
 */
SwarmNotNoCohortExp2Result SwarmNoteNotNoCohortExp2(const SwarmNotNoCohortExp2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOHORTEXP2_H
