// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMIXEDPREC2_H
#define BTX_MODELNET_SWARM_NOTNOMIXEDPREC2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_run asks this note to run mixed precision.
 *
 * Mixed precision has not run and this note runs nothing.
 * running stays false on every path.
 */
struct SwarmNotNoMixedPrec2 {
    std::string run_id;
    bool want_run{false};
};

/**
 * Outcome of noting a mixed-precision request. running stays false
 * on every path. Mixed precision has not run and this note runs nothing.
 */
struct SwarmNotNoMixedPrec2Result {
    std::string code;
    bool running{false};
};

/**
 * Note a mixed-precision request without running mixed precision.
 * Order, first match wins: an empty run_id is RUN.
 * want_run is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * running stays false on every path.
 * Mixed precision has not run and this note runs nothing.
 */
SwarmNotNoMixedPrec2Result SwarmNoteNotNoMixedPrec2(const SwarmNotNoMixedPrec2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMIXEDPREC2_H
