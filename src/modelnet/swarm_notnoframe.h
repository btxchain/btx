// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFRAME_H
#define BTX_MODELNET_SWARM_NOTNOFRAME_H

#include <string>

namespace modelnet {

/**
 * A local note about one framework. want_run asks this note to run it.
 *
 * Naming a framework does not run it. ran and trained stay false on every path.
 */
struct SwarmNotNoFrame {
    std::string framework_id;
    bool want_run{false};
};

/**
 * Outcome of noting a framework. ran and trained stay false on every path.
 * Naming a framework does not run it.
 */
struct SwarmNotNoFrameResult {
    std::string code;
    bool ran{false};
    bool trained{false};
};

/**
 * Note a framework without running it.
 * Order, first match wins: an empty framework_id is FRAMEWORK.
 * want_run is NOT_RUN. Otherwise the note is NOTED and err
 * is cleared. ran and trained stay false on every path.
 * Naming a framework does not run it.
 */
SwarmNotNoFrameResult SwarmNoteNotNoFrame(const SwarmNotNoFrame& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFRAME_H
