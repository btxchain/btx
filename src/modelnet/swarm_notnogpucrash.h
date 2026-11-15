// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGPUCRASH_H
#define BTX_MODELNET_SWARM_NOTNOGPUCRASH_H

#include <string>

namespace modelnet {

/**
 * A local note about one GPU crash. gpu_crash records that a GPU crash
 * was reported. want_publish asks this note to publish.
 *
 * A GPU-crash publication code does not mean a GPU ran and publishes
 * nothing. published and gpu stay false on every path.
 */
struct SwarmNotNoGpuCrash {
    std::string run_id;
    bool gpu_crash{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a GPU crash. published and gpu stay false on every
 * path. A GPU-crash publication code does not mean a GPU ran and
 * publishes nothing.
 */
struct SwarmNotNoGpuCrashResult {
    std::string code;
    bool published{false};
    bool gpu{false};
};

/**
 * Note a GPU crash without publishing. Order, first match wins: an empty
 * run_id is RUN. gpu_crash is NOT_RUN even when want_publish is false.
 * want_publish is NOT_RUN. Otherwise the note is NOTED and err is cleared.
 * published and gpu stay false on every path. A GPU-crash publication
 * code does not mean a GPU ran and publishes nothing.
 */
SwarmNotNoGpuCrashResult SwarmNoteNotNoGpuCrash(const SwarmNotNoGpuCrash& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGPUCRASH_H
