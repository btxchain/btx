// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTUSEFUL_H
#define BTX_MODELNET_SWARM_NOTUSEFUL_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Note that a task was not useful.
 *  published stays false, gpu_hours stays 0, and useful stays false.
 *  This record does not claim a GPU ran.
 */
struct SwarmNotUseful {
    std::string task_id;
    bool want_publish{false};
};

struct SwarmNotUsefulResult {
    std::string code;
    bool published{false};
    int64_t gpu_hours{0};
    bool useful{false};
};

/** Note a task that is not useful. Publication does not happen.
 *  Order, first match wins:
 *  1. An empty task_id is TASK. published stays false, gpu_hours stays 0,
 *     useful stays false, and err is TASK.
 *  2. want_publish is UNMEASURED. published stays false, gpu_hours stays 0,
 *     useful stays false, and err is UNMEASURED.
 *  3. Otherwise the note is NOTED. published stays false, gpu_hours stays 0,
 *     useful stays false, and err is cleared.
 *  Nothing here claims a GPU ran.
 */
SwarmNotUsefulResult SwarmNoteNotUseful(const SwarmNotUseful& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTUSEFUL_H
