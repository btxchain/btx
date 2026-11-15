// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG03_H
#define BTX_MODELNET_SWARM_FLAG03_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 3 coordinate: distinct tasks persist independently of
 * the leader. task_a and task_b name the two tasks. leader_id names the
 * leader. durable asks this note to retain evidence locally. want_run
 * asks this note to execute a task. want_pass asks this note to treat a
 * task as passed.
 *
 * ran, passed, bytes_moved, and broadcast stay false on every path.
 * persisted is true only when the note is durable and the two task ids
 * differ. No task is executed.
 */
struct SwarmFlag03 {
    std::string task_a;
    std::string task_b;
    std::string leader_id;
    bool durable{false};
    bool want_run{false};
    bool want_pass{false};
};

/**
 * Outcome of flagship stage 3 coordinate. ran, passed, bytes_moved, and
 * broadcast stay false on every path. persisted is true only when the
 * note is durable and the two task ids differ.
 */
struct SwarmFlag03Result {
    std::string code;
    bool persisted{false};
    bool ran{false};
    bool passed{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

/**
 * Note flagship stage 3 coordinate. Distinct tasks persist independently
 * of the leader. Order, first match wins: an empty task_a, task_b, or
 * leader_id is TASK. Equal task_a and task_b is SAME_TASK. want_run is
 * NOT_RUN. want_pass is UNQUALIFIED. durable false is LOST. Otherwise
 * the note is PERSISTED, persisted is true, and err is cleared.
 * ran, passed, bytes_moved, and broadcast stay false on every path.
 * Evidence is retained locally. No task is executed.
 */
SwarmFlag03Result SwarmStageCoordinate(const SwarmFlag03& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG03_H
