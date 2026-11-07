// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMIXED_H
#define BTX_MODELNET_SWARM_NOTNOMIXED_H

#include <string>

namespace modelnet {

/**
 * A local note about one step. want_mixed asks this note to treat the step as
 * mixed precision.
 *
 * Mixed precision has not run. This note trains nothing. mixed and trained
 * stay false on every path.
 */
struct SwarmNotNoMixed {
    std::string step_id;
    bool want_mixed{false};
};

/**
 * Outcome of noting a mixed-precision request. mixed and trained stay false
 * on every path: mixed precision has not run, and this note trains nothing.
 */
struct SwarmNotNoMixedResult {
    std::string code;
    bool mixed{false};
    bool trained{false};
};

/**
 * Note a mixed-precision request without running mixed precision or training.
 * Order, first match wins: an empty step_id is STEP.
 * want_mixed is NOT_RUN.
 * Otherwise the note is NOTED and err is clear.
 * mixed and trained stay false on every path.
 */
SwarmNotNoMixedResult SwarmNoteNotNoMixed(const SwarmNotNoMixed& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMIXED_H
