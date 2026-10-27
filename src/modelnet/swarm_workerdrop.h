// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WORKERDROP_H
#define BTX_MODELNET_SWARM_WORKERDROP_H

#include <string>

namespace modelnet {

/**
 * A local note about one worker and a stored task result. Execution
 * and broadcast are not provided.
 */
struct SwarmWorkerDropRequest {
    std::string task_id;
    std::string worker_id;
    bool result_stored{false};
    bool worker_connected{false};
};

/**
 * A local worker-drop note. executed stays false: a note does not
 * run the task and does not broadcast it. result_kept is true only
 * when a stored result remains after the note.
 */
struct SwarmWorkerDropResult {
    bool executed{false};
    bool result_kept{false};
    std::string code;
};

/**
 * Order, first match wins: an empty task_id or worker_id is WORKER.
 * A result that is not stored is RESULT_ABSENT, including when
 * worker_connected is false. A stored result whose worker is not
 * connected is DROPPED and err is clear; the stored result is kept.
 * Otherwise the note is NOTED and err is clear; the stored result is
 * kept. executed stays false on every path. This records a local
 * note. It does not execute a task and does not broadcast. A stored
 * result is kept when the worker disconnects. No hostnames or IPs
 * are used.
 */
SwarmWorkerDropResult SwarmNoteWorkerDrop(const SwarmWorkerDropRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WORKERDROP_H
