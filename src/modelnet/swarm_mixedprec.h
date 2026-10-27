// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MIXEDPREC_H
#define BTX_MODELNET_SWARM_MIXEDPREC_H

#include <string>

namespace modelnet {

/**
 * A mixed-precision run request is held. job_id names the job. want_run
 * asks this note to run.
 *
 * A mixed-precision run request is held and does not run.
 * running stays false on every path.
 */
struct SwarmMixedPrec {
    std::string job_id;
    bool want_run{false};
};

/**
 * Outcome of noting a held mixed-precision run request. running stays
 * false on every path.
 */
struct SwarmMixedPrecResult {
    std::string code;
    bool running{false};
};

/**
 * Note a held mixed-precision run request. It does not run.
 * Order, first match wins: an empty job_id is JOB.
 * want_run true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 * running stays false on every path.
 * A mixed-precision run request is held and does not run.
 */
SwarmMixedPrecResult SwarmNoteMixedPrec(const SwarmMixedPrec& job, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MIXEDPREC_H
