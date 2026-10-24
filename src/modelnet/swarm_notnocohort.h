// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOHORT_H
#define BTX_MODELNET_SWARM_NOTNOCOHORT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one cohort window. cohort_id names the cohort.
 * now_ms is the observation time. until_ms is the end of the window.
 * want_spend asks this note to spend.
 *
 * This note does not spend. spent stays false and atoms stays 0 on
 * every path. An inclusive cohort expiry spends nothing.
 */
struct SwarmNotNoCohort {
    std::string cohort_id;
    int64_t now_ms{0};
    int64_t until_ms{0};
    bool want_spend{false};
};

/**
 * Outcome of noting a cohort. spent stays false and atoms stays 0 on
 * every path. An inclusive cohort expiry spends nothing.
 */
struct SwarmNotNoCohortResult {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a cohort without spending. Order, first match wins: an empty
 * cohort_id is COHORT. If now_ms is at or after until_ms, the note is
 * EXPIRED even when want_spend is false. want_spend is HELD. Otherwise
 * the note is NOTED and err is clear.
 * spent stays false and atoms stays 0 on every path. An inclusive
 * cohort expiry spends nothing.
 */
SwarmNotNoCohortResult SwarmNoteNotNoCohort(const SwarmNotNoCohort& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOHORT_H
