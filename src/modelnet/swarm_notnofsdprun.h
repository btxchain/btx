// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFSDPRUN_H
#define BTX_MODELNET_SWARM_NOTNOFSDPRUN_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_run asks this note to run Fully Sharded
 * Data Parallel (FSDP) training.
 *
 * An FSDP request does not run and does not mark a GPU pass.
 * ran and gpu stay false on every path.
 */
struct SwarmNotNoFsdpRun {
    std::string run_id;
    bool want_run{false};
};

/**
 * Outcome of noting an FSDP run request. ran and gpu stay false on every
 * path: an FSDP request does not run and does not mark a GPU pass.
 */
struct SwarmNotNoFsdpRunResult {
    std::string code;
    bool ran{false};
    bool gpu{false};
};

/**
 * Note an FSDP run request without running it and without marking a GPU pass.
 * Order, first match wins: an empty run_id is RUN.
 * want_run is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * ran and gpu stay false on every path.
 * An FSDP request does not run and does not mark a GPU pass.
 */
SwarmNotNoFsdpRunResult SwarmNoteNotNoFsdpRun(const SwarmNotNoFsdpRun& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFSDPRUN_H
