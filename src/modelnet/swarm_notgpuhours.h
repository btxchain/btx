// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTGPUHOURS_H
#define BTX_MODELNET_SWARM_NOTGPUHOURS_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Note that GPU hours were not measured.
 *  published stays false and gpu_hours stays 0. This record does not claim a GPU ran.
 */
struct SwarmNotGpuHours {
    std::string job_id;
    bool want_publish{false};
};

struct SwarmNotGpuHoursResult {
    std::string code;
    bool published{false};
    int64_t gpu_hours{0};
};

/** Note an unmeasured GPU-hours record. Publication does not happen.
 *  Order, first match wins:
 *  1. An empty job_id is JOB. published stays false, gpu_hours stays 0, and err is JOB.
 *  2. want_publish is UNMEASURED. published stays false, gpu_hours stays 0, and err is UNMEASURED.
 *  3. Otherwise the note is NOTED. published stays false, gpu_hours stays 0, and err is cleared.
 *  Nothing here claims a GPU ran.
 */
SwarmNotGpuHoursResult SwarmNoteNotGpuHours(const SwarmNotGpuHours& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTGPUHOURS_H
