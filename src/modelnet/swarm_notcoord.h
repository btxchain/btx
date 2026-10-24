// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCOORD_H
#define BTX_MODELNET_SWARM_NOTCOORD_H

#include <string>

namespace modelnet {

/**
 * A local note about one task. want_run asks this note to execute distinct
 * agent tasks across a GPU node and a CPU node.
 *
 * Distinct agent tasks have not executed across a GPU node and a CPU node.
 * ran stays false on every path.
 */
struct SwarmNotCoord {
    std::string task_id;
    bool want_run{false};
};

/**
 * Outcome of noting a coordination request. ran stays false on every path:
 * distinct agent tasks have not executed across a GPU node and a CPU node.
 */
struct SwarmNotCoordResult {
    std::string code;
    bool ran{false};
};

/**
 * Note a coordination request without executing distinct agent tasks across
 * a GPU node and a CPU node. Order, first match wins: an empty task_id is
 * TASK. want_run is NOT_RUN. Otherwise the note is NOTED and err is clear.
 * ran stays false on every path.
 */
SwarmNotCoordResult SwarmNoteNotCoord(const SwarmNotCoord& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCOORD_H
