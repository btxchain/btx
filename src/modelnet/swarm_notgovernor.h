// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTGOVERNOR_H
#define BTX_MODELNET_SWARM_NOTGOVERNOR_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. idle_off, battery, thermal, and metered
 * record drain conditions. want_keep asks this note to keep the node.
 *
 * This note records the drain rule and does not stop a process.
 * drained stays false and workers stays 0 on every path.
 */
struct SwarmNotGovernor {
    std::string node_id;
    bool idle_off{false};
    bool battery{false};
    bool thermal{false};
    bool metered{false};
    bool want_keep{false};
};

/**
 * Outcome of noting a governor drain rule. drained stays false and
 * workers stays 0 on every path: this note does not stop a process.
 */
struct SwarmNotGovernorResult {
    std::string code;
    bool drained{false};
    int workers{0};
};

/**
 * Note a governor drain rule without stopping a process.
 * Order, first match wins:
 * 1. An empty node_id is NODE. drained stays false, workers stays 0,
 *    and err is NODE.
 * 2. idle_off, battery, thermal, or metered is DRAIN, even when
 *    want_keep is false. drained stays false, workers stays 0, and
 *    err is DRAIN.
 * 3. want_keep is DRAIN. drained stays false, workers stays 0, and
 *    err is DRAIN.
 * 4. Otherwise the note is NOTED. drained stays false, workers stays
 *    0, and err is cleared.
 * This note records the drain rule and does not stop a process.
 */
SwarmNotGovernorResult SwarmNoteNotGovernor(const SwarmNotGovernor& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTGOVERNOR_H
