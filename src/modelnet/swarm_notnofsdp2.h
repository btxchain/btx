// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFSDP2_H
#define BTX_MODELNET_SWARM_NOTNOFSDP2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_fsdp asks this note to run Fully Sharded
 * Data Parallel (FSDP) training.
 *
 * An FSDP request does not run.
 * ran and gpu stay false on every path.
 */
struct SwarmNotNoFsdp2 {
    std::string run_id;
    bool want_fsdp{false};
};

/**
 * Outcome of noting an FSDP request. ran and gpu stay false on every path:
 * an FSDP request does not run.
 */
struct SwarmNotNoFsdp2Result {
    std::string code;
    bool ran{false};
    bool gpu{false};
};

/**
 * Note an FSDP request without running it.
 * Order, first match wins: an empty run_id is RUN.
 * want_fsdp is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * ran and gpu stay false on every path.
 * An FSDP request does not run.
 */
SwarmNotNoFsdp2Result SwarmNoteNotNoFsdp2(const SwarmNotNoFsdp2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFSDP2_H
