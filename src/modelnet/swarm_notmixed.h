// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMIXED_H
#define BTX_MODELNET_SWARM_NOTMIXED_H

#include <string>

namespace modelnet {

/**
 * A local note about one job. want_mixed asks this note to treat the job as
 * mixed precision.
 *
 * Mixed precision has not run. mixed stays false on every path.
 */
struct SwarmNotMixed {
    std::string job_id;
    bool want_mixed{false};
};

/**
 * Outcome of noting a mixed-precision request. mixed stays false on every
 * path: mixed precision has not run.
 */
struct SwarmNotMixedResult {
    std::string code;
    bool mixed{false};
};

/**
 * Note a mixed-precision request without running mixed precision.
 * Order, first match wins: an empty job_id is JOB.
 * want_mixed is NOT_MIXED.
 * Otherwise the note is NOTED and err is clear.
 * mixed stays false on every path.
 */
SwarmNotMixedResult SwarmNoteNotMixed(const SwarmNotMixed& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMIXED_H
