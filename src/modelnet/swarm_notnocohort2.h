// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOHORT2_H
#define BTX_MODELNET_SWARM_NOTNOCOHORT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one cohort window. cohort_id names the cohort.
 * inclusive marks the cohort expiry as inclusive. want_drop asks this
 * note to drop a member.
 *
 * This note drops no member. dropped stays false on every path.
 * Cohort expiry is inclusive.
 */
struct SwarmNotNoCohort2 {
    std::string cohort_id;
    bool inclusive{false};
    bool want_drop{false};
};

/**
 * Outcome of noting a cohort. dropped stays false on every path.
 * Cohort expiry is inclusive. This note drops no member.
 */
struct SwarmNotNoCohort2Result {
    std::string code;
    bool dropped{false};
};

/**
 * Note a cohort without dropping a member.
 * Order, first match wins: an empty cohort_id is COHORT. If inclusive
 * is true, the note is STAYS even when want_drop is false. want_drop is
 * HELD. Otherwise the note is NOTED and err is cleared. dropped stays
 * false on every path. Cohort expiry is inclusive. This note drops no
 * member.
 */
SwarmNotNoCohort2Result SwarmNoteNotNoCohort2(const SwarmNotNoCohort2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOHORT2_H
