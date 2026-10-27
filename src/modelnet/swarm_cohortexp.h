// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_COHORTEXP_H
#define BTX_MODELNET_SWARM_COHORTEXP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one cohort window. cohort_id names the cohort.
 * now_ms is the observation time. until_ms is the end of the window.
 * want_admit asks this note to admit a member.
 *
 * This note does not admit a member and does not start training. No
 * hostnames or IPs are used.
 */
struct SwarmCohortExpiry {
    std::string cohort_id;
    int64_t now_ms{0};
    int64_t until_ms{0};
    bool want_admit{false};
};

/**
 * Outcome of noting a cohort window. admitted stays false on every path:
 * this note does not admit a member and does not start training.
 * expired is true only when the window has reached until_ms.
 */
struct SwarmCohortExpiryResult {
    bool admitted{false};
    bool expired{false};
    std::string code;
};

/**
 * Note a cohort window without admitting a member.
 * Order, first match wins: an empty cohort_id, a now_ms below 0, or an
 * until_ms below 1 is COHORT. now_ms at or after until_ms is EXPIRED,
 * including equality, and that wins even when want_admit is true.
 * want_admit is HELD and err is clear. Otherwise the note is NOTED and
 * err is clear.
 * admitted stays false on every path. This note does not admit a member
 * and does not start training. No hostnames or IPs are used.
 */
SwarmCohortExpiryResult SwarmNoteCohortExpiry(const SwarmCohortExpiry& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_COHORTEXP_H
