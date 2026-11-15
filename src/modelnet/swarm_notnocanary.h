// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCANARY_H
#define BTX_MODELNET_SWARM_NOTNOCANARY_H

#include <string>

namespace modelnet {

/**
 * A local note about one canary. want_run asks this note to run it.
 *
 * A local note does not run a canary. ran and regressed stay false on
 * every path.
 */
struct SwarmNotNoCanary {
    std::string canary_id;
    bool want_run{false};
};

/**
 * Outcome of noting a canary. ran and regressed stay false on every path:
 * a local note does not run a canary.
 */
struct SwarmNotNoCanaryResult {
    std::string code;
    bool ran{false};
    bool regressed{false};
};

/**
 * Note a canary without running it.
 * Order, first match wins: an empty canary_id is CANARY.
 * want_run is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * ran and regressed stay false on every path. A local note does not run
 * a canary.
 */
SwarmNotNoCanaryResult SwarmNoteNotNoCanary(const SwarmNotNoCanary& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCANARY_H
