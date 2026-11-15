// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMIXED2_H
#define BTX_MODELNET_SWARM_NOTNOMIXED2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_run asks this note to run mixed precision.
 *
 * Mixed precision does not run.
 * ran and gpu stay false on every path.
 */
struct SwarmNotNoMixed2 {
    std::string run_id;
    bool want_run{false};
};

/**
 * Outcome of noting a mixed-precision request. ran and gpu stay false
 * on every path: mixed precision does not run.
 */
struct SwarmNotNoMixed2Result {
    std::string code;
    bool ran{false};
    bool gpu{false};
};

/**
 * Note a mixed-precision request without running mixed precision.
 * Order, first match wins: an empty run_id is RUN.
 * want_run is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * ran and gpu stay false on every path.
 * Mixed precision does not run.
 */
SwarmNotNoMixed2Result SwarmNoteNotNoMixed2(const SwarmNotNoMixed2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMIXED2_H
