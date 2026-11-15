// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCOHORT_H
#define BTX_MODELNET_SWARM_NOTCOHORT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one cohort window. cohort_id names the cohort.
 * now_ms is the observation time. until_ms is the end of the window.
 * want_extend asks this note to extend the cohort.
 *
 * This note does not extend a cohort. extended stays false on every path.
 */
struct SwarmNotCohort {
    std::string cohort_id;
    int64_t now_ms{0};
    int64_t until_ms{0};
    bool want_extend{false};
};

/**
 * Outcome of noting a cohort. extended stays false on every path.
 * expired is true only on the EXPIRED path. Cohort expiry is inclusive.
 */
struct SwarmNotCohortResult {
    std::string code;
    bool extended{false};
    bool expired{false};
};

/**
 * Note a cohort without extending it.
 * Order, first match wins: an empty cohort_id is COHORT. want_extend is
 * HELD. If now_ms is at or after until_ms, the note is EXPIRED. Otherwise
 * the note is NOTED and err is clear.
 * extended stays false on every path. expired is true only on the EXPIRED
 * path. Cohort expiry is inclusive. This note does not extend a cohort.
 */
SwarmNotCohortResult SwarmNoteNotCohort(const SwarmNotCohort& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCOHORT_H
