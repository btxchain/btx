// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOHORTINC2_H
#define BTX_MODELNET_SWARM_NOTNOCOHORTINC2_H

#include <string>

namespace modelnet {

/**
 * A local note about one cohort window. cohort_id names the cohort.
 * inclusive marks the cohort expiry as inclusive. want_exclude asks this
 * note to exclude a member.
 *
 * This note excludes no member. excluded stays false on every path.
 * Cohort expiry stays inclusive.
 */
struct SwarmNotNoCohortInc2 {
    std::string cohort_id;
    bool inclusive{false};
    bool want_exclude{false};
};

/**
 * Outcome of noting a cohort. excluded stays false on every path.
 * Cohort expiry stays inclusive. This note excludes no member.
 */
struct SwarmNotNoCohortInc2Result {
    std::string code;
    bool excluded{false};
};

/**
 * Note a cohort without excluding a member.
 * Order, first match wins: an empty cohort_id is COHORT. If inclusive
 * is true, the note is STAYS even when want_exclude is false. want_exclude
 * is HELD. Otherwise the note is NOTED and err is cleared. excluded stays
 * false on every path. Cohort expiry stays inclusive. This note excludes
 * no member.
 */
SwarmNotNoCohortInc2Result SwarmNoteNotNoCohortInc2(const SwarmNotNoCohortInc2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOHORTINC2_H
