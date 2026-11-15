// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFSDPRUN2_H
#define BTX_MODELNET_SWARM_NOTNOFSDPRUN2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_run asks this note to run Fully Sharded
 * Data Parallel (FSDP) training.
 *
 * FSDP has not run and this note runs nothing.
 * running stays false on every path.
 */
struct SwarmNotNoFsdpRun2 {
    std::string run_id;
    bool want_run{false};
};

/**
 * Outcome of noting an FSDP run request. running stays false on every
 * path. FSDP has not run and this note runs nothing.
 */
struct SwarmNotNoFsdpRun2Result {
    std::string code;
    bool running{false};
};

/**
 * Note an FSDP run request without running it.
 * Order, first match wins: an empty run_id is RUN.
 * want_run is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * running stays false on every path.
 * FSDP has not run and this note runs nothing.
 */
SwarmNotNoFsdpRun2Result SwarmNoteNotNoFsdpRun2(const SwarmNotNoFsdpRun2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFSDPRUN2_H
